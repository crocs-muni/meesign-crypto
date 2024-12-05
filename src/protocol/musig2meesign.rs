use core::panic;

use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType, ServerMessage};
use crate::protocol::*;

use musig2::verify_single;
use musig2::{CompactSignature, FirstRound, KeyAggContext, PartialSignature, PubNonce, SecondRound};
use musig2::secp::Scalar;
use rand::RngCore;
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use prost::Message;
use serde::{Deserialize, Serialize};

use rand::rngs::OsRng;

#[derive(Serialize, Deserialize, Clone, Copy)]
struct Setup {
    threshold: u16,
    parties: u16,
    index: u16,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeygenContext {
    round: KeygenRound,
    with_card: bool,
}

#[derive(Serialize, Deserialize)]
enum KeygenRound {
    R0,
    R1(Setup, Signer), // Setup and skey share of the user
    Done(Setup, Signer),
}

impl KeygenContext {
    //pub fn with_card() -> Self {
    //    Self {
    //        round: KeygenRound::R0,
    //        with_card: false, //TODO: Change when card is implemented
    //    }
    //}

    fn init(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let msg = ProtocolGroupInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Musig2 as i32 {
            return Err("wrong protocol type".into());
        }

        // Musig2 is n-out-of-n scheme. Therefore n = k.
        if msg.parties as u16 != msg.threshold as u16 {
            return Err("number of parties must be equal to the treshold".into());
        }

        let setup = Setup {
            threshold: msg.threshold as u16,
            parties: msg.parties as u16,
            index: msg.index as u16,
        };

        // Key share pair generated
        let signer: Signer = Signer::new();

        let public_key_share = signer.pubkey_serialized();

        let msg = serialize_bcast(&public_key_share, ProtocolType::Musig2)?;
        self.round = KeygenRound::R1(setup, signer);
        Ok((msg, Recipient::Server))
    }

    fn update(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let (c, data, rec) = match &mut self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),
            KeygenRound::R1(setup, signer) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let pub_keys_hashmap = deserialize_map(&data)?;

                // Get public key shares of all signers
                let pub_key_shares: Vec<Vec<u8>> = pub_keys_hashmap.values().cloned().collect();

                // Generate key_agg_ctx (together with agg_pubkey). Currently there's no support for tweaks.
                signer.generate_key_agg_ctx_serialized(pub_key_shares, None, false);

                let agg_pubkey = signer.get_agg_pubkey().clone();
                let msg = serialize_bcast(&agg_pubkey, ProtocolType::Musig2)?;

                (
                    KeygenRound::Done(*setup, signer.clone()),
                    msg,
                    Recipient::Server,
                )
            }
            KeygenRound::Done(_, _) => return Err("protocol already finished".into()),
        };
        self.round = c;

        Ok((data, rec))
    }
}

#[typetag::serde(name = "musig2_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            KeygenRound::Done(setup, signer) => {
                Ok(serde_json::to_vec(&(setup, signer))?)
            }
            _ => Err("protocol not finished".into()),
        }
    }
}

impl KeygenProtocol for KeygenContext {
    fn new() -> Self {
        Self {
            round: KeygenRound::R0,
            with_card: false,
        }
    }
}

// By GitHub Copilot
// Deserialize a vector of bytes with pubnonces/partial signatures and internal identifiers of the signers to a hashmap
fn deserialize_musig(data: Vec<Vec<u8>>, chunk_len: usize) -> Result<HashMap<u8, Vec<u8>>> {
    let data = data.concat();
    if data.len() % chunk_len != 0 {
        return Err("Input data length must be a multiple of the input size".into());
    }

    let mut hashmap = HashMap::new();
    for chunk in data.chunks_exact(chunk_len) {
        let key = chunk[chunk_len - 1];
        let mut value = Vec::new();
        value.extend_from_slice(&chunk[..chunk_len - 1]);

        if hashmap.contains_key(&key) {
            return Err("Duplicate key found".into());
        }

        hashmap.insert(key, value);
    }

    Ok(hashmap)
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SignContext {
    setup: Setup,
    initial_signer: Signer,
    message: Option<Vec<u8>>,
    indices: Option<Vec<u16>>,
    round: SignRound,
}

const PUBNONCE_CHUNK_LEN: usize = 67; //(33*2+1)
const SCALAR_CHUNK_LEN: usize = 33; //(32+1)

#[derive(Serialize, Deserialize)]
enum SignRound {
    R0,
    R1(Signer),
    R2(Signer),
    Done(CompactSignature),
}

impl SignContext {
    //fn participants(&self) -> usize {
    //    self.indices.as_ref().unwrap().len()
    //}

    // Format sent is &[u8] + u8 (pubnonce and index of the signer)
    fn init(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let msg = ProtocolInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Musig2 as i32 {
            return Err("wrong protocol type".into());
        }

        self.indices = Some(msg.indices.iter().map(|i| *i as u16).collect());
        self.message = Some(msg.data);

        // TODO: Can I shuffle the ids of the signers?
        // Generate secnonce and pubnonce
        self.initial_signer.first_round();

        let mut out_buffer = self.initial_signer.get_pubnonce_serialized().clone();
        let internal_index: u8 = self.initial_signer.get_index() as u8;

        out_buffer.push(internal_index);

        // Serialize the public nonce and the internal index of the signer. Format: &[u8] + u8
        let msg = serialize_bcast(&out_buffer, ProtocolType::Musig2)?; // TODO: Check if this is correct usage of serialize_bcast

        // TODO: Can I somehow just pass a reference instead of cloning? (Due to Signer having a secret share inside)
        self.round = SignRound::R1(self.initial_signer.clone());

        Ok((msg, Recipient::Server))
    }

    fn update(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        match &self.round {
            SignRound::R0 => Err("protocol not initialized".into()),
            SignRound::R1(signer) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let pubnonce_hashmap: HashMap<u32, Vec<u8>> = deserialize_map(&data)?;

                // TODO: Is the pubnonce instance of this Signer object returned by the server?
                // Generate hashmap <internal index of Signer, pubnonce>
                let pubnonces = deserialize_musig(pubnonce_hashmap.values().cloned().collect(), PUBNONCE_CHUNK_LEN)?;

                // Create a vector of tuples (internal index of Signer, pubnonce)
                let pubnonces: Vec<(usize, Vec<u8>)> = pubnonces
                    .into_iter()
                    .map(|(index, pubnonce)| (index as usize, pubnonce.to_vec()))
                    .collect();

                // Get copy of Signer object
                // TODO: Another example of the unnecessary cloning?
                let mut signer: Signer = signer.clone();

                // Establish second round
                if let Some(message) = &mut self.message {
                    signer.second_round(&message, pubnonces);

                    let mut out_buffer = signer.get_partial_signature_serialized().clone();
                    let internal_index = signer.get_index() as u8;

                    out_buffer.push(internal_index);

                    // Serialize the partial signature and the internal index of the signer. Format: &[u8] + u8
                    let msg = serialize_bcast(&out_buffer, ProtocolType::Musig2)?;

                    self.round = SignRound::R2(signer);
                    
                    Ok((msg, Recipient::Server))
                } else {
                    Err("message to sign not initialized".into())
                }
            }
            SignRound::R2(signer) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let shares_hashmap: HashMap<u32, Vec<u8>> = deserialize_map(&data)?;
                let shares = deserialize_musig(shares_hashmap.values().cloned().collect(), SCALAR_CHUNK_LEN)?;

                // Create a vector of tuples (internal index of Signer, partial signature)
                let partial_signatures: Vec<(usize, Vec<u8>)> = shares
                    .into_iter()
                    .map(|(index, partial_signature)| (index as usize, partial_signature.to_vec()))
                    .collect();

                // Get copy of Signer object
                let mut signer: Signer = signer.clone();

                // Set partial signatures of other signers
                signer.receive_partial_signatures(partial_signatures);
                
                // Get aggregated signature and if successful, return it to the server
                match signer.get_agg_signature() {
                    Ok(signature) => {
                        let msg = serialize_bcast(&signature.serialize().to_vec(), ProtocolType::Musig2)?;
                        self.round = SignRound::Done(signature);
                        Ok((msg, Recipient::Server))
                    }
                    Err(e) => Err(e),
                }
            }
            SignRound::Done(_) => Err("protocol already finished".into()),
        }
    }
}

#[typetag::serde(name = "musig2_sign")]
impl Protocol for SignContext {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        match self.round {
            SignRound::R0 => self.init(data),
            _ => self.update(data),
        }
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            SignRound::Done(sig) => Ok(serde_json::to_vec(&sig)?),
            _ => Err("protocol not finished".into()),
        }
    }
}

impl ThresholdProtocol for SignContext {
    fn new(group: &[u8]) -> Self {
        let (setup, initial_signer): (Setup, Signer) =
            serde_json::from_slice(group).expect("could not deserialize group context");
        Self {
            setup,
            initial_signer,
            message: None,
            indices: None,
            round: SignRound::R0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tests::{KeygenProtocolTest, ThresholdProtocolTest};
    use musig2::CompactSignature;
    use rand::seq::IteratorRandom;

    impl KeygenProtocolTest for KeygenContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Musig2;
        const ROUNDS: usize = 2;
        const INDEX_OFFSET: u32 = 1;
    }

    impl ThresholdProtocolTest for SignContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Musig2;
        const ROUNDS: usize = 3;
        const INDEX_OFFSET: u32 = 1;
    }

    #[test]
    fn keygen() {
        for parties in 2..6 {
            let (pks, _) =
                <KeygenContext as KeygenProtocolTest>::run(parties as u32, parties as u32);

            let pks: Vec<PublicKey> = pks
                .iter()
                .map(|(_, x)| serde_json::from_slice(&x).unwrap())
                .collect();

            for i in 1..parties {
                assert_eq!(pks[0], pks[i])
            }
        }
    }

    #[test]
    fn sign() {
        for parties in 2..6 {
            let (pks, ctxs) =
                <KeygenContext as KeygenProtocolTest>::run(parties as u32, parties as u32);
            let msg = b"hello";
            let (_, pk) = pks.iter().take(1).collect::<Vec<_>>()[0];
            let pk: PublicKey = serde_json::from_slice(&pk).unwrap();

            let ctxs = ctxs
                .into_iter()
            //    .choose_multiple(&mut OsRng, parties)
            //    .into_iter()
                .collect();
            let results =
                <SignContext as ThresholdProtocolTest>::run(ctxs, msg.to_vec());

            let signature: CompactSignature = serde_json::from_slice(&results[0]).unwrap();

            for result in results {
                assert_eq!(signature, serde_json::from_slice(&result).unwrap());
            }

            assert!(musig2::verify_single(pk, signature, msg).is_ok());
        }
    }
}

// Musig2 Signer Util

#[derive(Serialize, Deserialize, Clone)]
pub struct Signer {
    keypair: Keypair, // Pair of shares
    key_agg_ctx: Option<KeyAggContext>,
    index: Option<usize>, // Index of the signer
    agg_signature: Option<CompactSignature>, // Aggregated signature
    first_round: Option<FirstRound>,
    second_round: Option<SecondRound<Vec<u8>>>,
}

impl Signer {
    pub fn new() -> Self {

        let secp = Secp256k1::new();
        let mut rng = OsRng::default();
        let pair = secp.generate_keypair(&mut rng); 

        Self {
            keypair: Keypair::from_secret_key(&secp, &pair.0),
            key_agg_ctx: None,
            index: None,
            first_round: None,
            agg_signature: None,
            second_round: None,
        }
    }

    pub fn pubkey_serialized(&self) -> Vec<u8> {
        return self.pubkey().serialize().to_vec();
    }

    pub fn get_index(&self) -> usize {

        match self.index {
            None => panic!("Index not set"),
            Some(_) => {}
        }

        return self.index.unwrap();
    }

    pub fn get_partial_signature_serialized(&self) -> Vec<u8> {
        return self.get_partial_signature().serialize().to_vec();
    }

    pub fn get_pubnonce_serialized(&self) -> Vec<u8> {
        return self.get_pubnonce().serialize().to_vec();
    }

    pub fn generate_key_agg_ctx_serialized(&mut self, pubkeys_ser: Vec<Vec<u8>>, tweak: Option<[u8;32]>, xonly: bool) {

        let mut pubkeys: Vec<PublicKey> = Vec::new();
        for pubkey in pubkeys_ser {
            pubkeys.push(PublicKey::from_slice(&pubkey).unwrap());
        }

        self.generate_key_agg_ctx(pubkeys, tweak, xonly);
    }

    pub fn receive_partial_signatures(&mut self, partial_signatures: Vec<(usize, Vec<u8>)>) {
        for (index, partial_signature) in partial_signatures {
            self.receive_partial_signature_serialized(index, partial_signature);
        }
    }

    pub fn verify_serialized(&self, aggregated_pubkey: Vec<u8>, aggregated_signature: Vec<u8>, mssg: &str) -> bool {
        let signature = CompactSignature::from_bytes(&aggregated_signature).unwrap();
        let pubkey = PublicKey::from_slice(&aggregated_pubkey).unwrap();
        
        match verify_single(pubkey, signature, mssg) {
            Ok(_) => return true,
            Err(e) => if e.to_string() == "InvalidSignature" {
                return false;
            } else {
                panic!("Error verifying signature: {:?}", e);
            },
        }
    }

    // Share public key
    fn pubkey(&self) -> PublicKey {
        return self.keypair.public_key();
    }

    // Share secret key
    fn seckey(&self) -> SecretKey {
        return self.keypair.secret_key();
    }

    fn generate_key_agg_ctx(&mut self, all_pubkeys: Vec<PublicKey>, tweak: Option<[u8;32]>, xonly: bool) {

        // Get public key shares sorted in lexigraphical order (BIP0327)
        let mut pubkeys: Vec<PublicKey> = all_pubkeys.clone();
        pubkeys.push(self.pubkey());
        let sorted_pubkeys: Vec<PublicKey>  = self.sort_pubkeys(pubkeys);

        // Set index of this signer in the sorted public keys
        self.set_index(sorted_pubkeys.clone());

        // Create key aggregation context
        let mut ctx = KeyAggContext::new(sorted_pubkeys).unwrap();

        // Apply tweak if provided
        match tweak {
            Some(tweak) => {
                let tweak_scalar = Scalar::from_slice(&tweak).unwrap();
                ctx = ctx.with_tweak(tweak_scalar, xonly).unwrap();

            }
            None => {}
        }

        self.key_agg_ctx = Some(ctx);

        }

    fn get_agg_pubkey(&self) -> PublicKey {
        if let Some(ctx) = self.key_agg_ctx.as_ref() {
            return ctx.aggregated_pubkey();
        } else {
            panic!("Aggregated public key not initialized.");
        }
    }

    pub fn first_round(&mut self) {

        // Secret key share
        let seckey = self.seckey();

        // Create an instance of OsRng
        let mut rng = OsRng;

        // Generate a random 32-byte array
        let mut nonce_seed = [0u8; 32];
        rng.fill_bytes(&mut nonce_seed);

        // Create first round for this signer
        let first_round = musig2::FirstRound::new(
            self.key_agg_ctx.clone().unwrap(),
            // TODO: I can't see any problem here
            nonce_seed,
            self.get_index(),
            musig2::SecNonceSpices::new()
                .with_seckey(seckey)
        )
        .unwrap();

        // Store the first round
        self.first_round = Some(first_round);
    }

    fn get_pubnonce(&self) -> PubNonce {
        if let Some(fr) = self.first_round.as_ref() {
            return fr.our_public_nonce();
        } else {
            panic!("First round not initialized");
        }
    }

    // Add a public nonce of another signer to this signer's first round context
    fn add_pubnonce(&mut self, nonce_index: usize, pubnonce: PubNonce) {

        if let Some(fr) = self.first_round.as_mut() {

            if fr.is_complete() {
                panic!("First round already complete");
            }

            let res = fr.receive_nonce(nonce_index, pubnonce);

            match res {
                Ok(_) => {}
                Err(e) => {
                    panic!("Error adding pubnonce: {:?}", e);
                }
            }
        } else {
            panic!("First round not initialized");
        }
    }

    fn add_pubnonce_serialized(&mut self, nonce_index: usize, pubnonce: Vec<u8>) {
        let pubnonce = PubNonce::from_bytes(&pubnonce).unwrap();
        self.add_pubnonce(nonce_index, pubnonce);
    }

    pub fn second_round(&mut self, message: &Vec<u8>, pubnonces: Vec<(usize, Vec<u8>)>) {

        for (index, pubnonce) in pubnonces {
            self.add_pubnonce_serialized(index, pubnonce);
        }

        if let Some(fr) = self.first_round.take() {
            if !fr.is_complete() {
                panic!("First round not complete");
            }

            if let Some(sr) = self.second_round.as_ref() {
                if sr.is_complete() {
                    panic!("Second round already complete");
                } else {
                    panic!("Second is already initialized");
                }
            }

            let second_round: SecondRound<Vec<u8>> = fr.finalize::<Vec<u8>>(self.seckey(),message.clone()).unwrap();
            self.second_round = Some(second_round);

        } else {
            panic!("First round not initialized");
        } 
    }

    fn get_partial_signature(&self) -> PartialSignature {
        if let Some(sr) = self.second_round.as_ref() {
            return sr.our_signature();
        } else {
            panic!("Second round not initialized");
        }
    }

    fn receive_partial_signature(&mut self, signer_index: usize, partial_signature: PartialSignature) {
            
            if let Some(sr) = self.second_round.as_mut() {
                
                let res = sr.receive_signature(signer_index, partial_signature);

                match res {
                    Ok(_) => {}
                    Err(e) => {
                        panic!("Error adding partial signature: {:?}", e);
                    }
                }
            } else {
                panic!("Second round not initialized");
            }
    } 

    fn receive_partial_signature_serialized(&mut self, signer_index: usize, partial_signature: Vec<u8>) {
        let partial_signature = PartialSignature::from_slice(&partial_signature).unwrap();
        self.receive_partial_signature(signer_index, partial_signature);
    }

    fn get_agg_signature(&mut self) -> Result<CompactSignature> {
        if let Some(sr) = self.second_round.take() {
            return Ok(sr.finalize().unwrap());
        } else {
            return Err("Second round not initialized".into());
        }
    }

    fn sort_pubkeys(&mut self, pubkeys: Vec<PublicKey>) -> Vec<PublicKey> {
        let mut pubkeys = pubkeys;
        pubkeys.sort_by(|a, b| a.serialize().cmp(&b.serialize()));

        return pubkeys;
    }

    fn set_index(&mut self, pubkeys: Vec<PublicKey>) {
        let index = pubkeys.iter().position(|&x| x == self.pubkey());

        if index == None {
            panic!("Public key not found in the list of public keys");
        }

        self.index = index;
    }
}