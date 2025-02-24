pub mod signer;

use std::convert::TryInto;

use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType, ServerMessage};
use crate::protocol::*;

use secp256k1::PublicKey;
use signer::Signer;
use ::musig2::{CompactSignature, PartialSignature, PubNonce};
use prost::Message;
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Clone, Copy)]
struct Setup {
    threshold: u16,
    parties: u16,
    index: u16,
    with_card: bool
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeygenContext {
    round: KeygenRound,
    with_card: bool,
}

#[derive(Serialize, Deserialize)]
enum KeygenRound {
    R0,
    R0GetPubkey(Setup), // Get pubkey from card
    R0AwaitGetPubkey(Setup), // Get pubkey from card
    R1(Setup, Signer), // Setup and skey share of the user
    R1AwaitAggkeyLoad(Setup, Signer), // Load aggregate key onto the card
    Done(Setup, Signer),
}

impl KeygenContext {
    pub fn with_card() -> Self {
        Self {
            round: KeygenRound::R0,
            with_card: true, 
        }
    }

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
            with_card: self.with_card
        };

        // Key share pair generated
        if self.with_card {
            let command = jc::command::keygen();
            self.round = KeygenRound::R0GetPubkey(setup);
            Ok((command, Recipient::Card))
        } else {
            let signer: Signer = Signer::new();

            let public_key_share = signer.pubkey().serialize().to_vec();

            let msg = serialize_bcast(&public_key_share, ProtocolType::Musig2)?;
            self.round = KeygenRound::R1(setup, signer);
            Ok((msg, Recipient::Server))
        }

    }

    fn update(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let (c, data, rec) = match &mut self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),
            KeygenRound::R0GetPubkey(setup) => {
                jc::response::keygen(data)?;
                let command = jc::command::get_plain_pubkey();
                (
                    KeygenRound::R0AwaitGetPubkey(*setup),
                    command,
                    Recipient::Card,
                )
            }
            KeygenRound::R0AwaitGetPubkey(setup) => {
                let pubkey = jc::response::get_plain_pubkey(data)?;
                let signer = Signer::new_from_card(pubkey);

                let public_key_share = pubkey.serialize().to_vec();

                let msg = serialize_bcast(&public_key_share, ProtocolType::Musig2)?;
                (
                    KeygenRound::R1(*setup, signer),
                    msg,
                    Recipient::Server
                )

            }
            KeygenRound::R1(setup, signer) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let pub_keys_hashmap = deserialize_map(&data)?;

                // Get public key shares of all signers
                let pub_key_shares: Vec<PublicKey> = pub_keys_hashmap
                    .values()
                    .cloned()
                    .map(|x: Vec<u8>| {
                        let array: [u8; 33] = x.try_into().expect("slice with incorrect length");
                        PublicKey::from_slice(&array).unwrap()
                    })
                    .collect();

                // Generate key_agg_ctx (together with agg_pubkey). Currently there's no support for tweaks.
                signer.generate_key_agg_ctx(pub_key_shares, None, false);
                let agg_pubkey = signer.get_agg_pubkey().clone();

                if self.with_card {
                    
                    let coef_a = signer.get_coef_a().serialize();

                    let command = jc::command::set_aggpubkey(
               agg_pubkey,
                        coef_a
                    );

                    (
                        KeygenRound::R1AwaitAggkeyLoad(*setup, signer.clone()),
                        command,
                        Recipient::Card,
                    )

                } else {
                    (
                        KeygenRound::Done(*setup, signer.clone()),
                        serialize_bcast(&agg_pubkey, ProtocolType::Musig2)?,
                        Recipient::Server,
                    )
                }

            }
            KeygenRound::R1AwaitAggkeyLoad(setup, signer) => {

                jc::response::set_aggpubkey(data)?;
                let agg_pubkey = signer.get_agg_pubkey();

                (
                        KeygenRound::Done(*setup, signer.clone()),
                        serialize_bcast(&agg_pubkey, ProtocolType::Musig2)?,
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
    R0GenerateNonce(Signer),
    R0AwaitNonce(Signer),
    R1(Signer), // Also loads aggnonce onto the card
    R1PartiallySign(Signer),
    R1AwaitPartialSignature(Signer),
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

        if self.setup.with_card {
            let command = jc::command::noncegen();
            self.round = SignRound::R0GenerateNonce(self.initial_signer.clone());

            return Ok((command, Recipient::Card));
        }

        self.initial_signer.first_round();

        let mut out_buffer = self.initial_signer.get_pubnonce()?.serialize().to_vec();
        let internal_index: u8 = self.initial_signer.get_index() as u8;

        out_buffer.push(internal_index);

        // Serialize the public nonce and the internal index of the signer. Format: &[u8] + u8
        let msg = serialize_bcast(&out_buffer, ProtocolType::Musig2)?; // TODO: Check if this is correct usage of serialize_bcast

        self.round = SignRound::R1(self.initial_signer.clone());

        Ok((msg, Recipient::Server))
    }

    fn update(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        match &self.round {
            SignRound::R0 => Err("protocol not initialized".into()),
            SignRound::R0GenerateNonce(signer) => {
                jc::response::noncegen(data)?;
                let command: Vec<u8> = jc::command::get_pubnonce();
                self.round = SignRound::R0AwaitNonce(signer.clone());
                Ok((command, Recipient::Card))
            }
            SignRound::R0AwaitNonce(signer) => {
                let pubnonce = jc::response::get_pubnonce(data)?;

                let mut signer = signer.clone();
                signer.set_pubnonce(pubnonce)?;

                //signer.set_pubnonce(pubnonce);
                let mut out_buffer = signer.get_pubnonce()?.serialize().to_vec();
                let internal_index: u8 = signer.get_index() as u8;

                out_buffer.push(internal_index);
                let msg = serialize_bcast(&out_buffer, ProtocolType::Musig2)?;

                self.round = SignRound::R1(signer);
                Ok((msg, Recipient::Server))
            }
            SignRound::R1(signer) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let pubnonce_hashmap: HashMap<u32, Vec<u8>> = deserialize_map(&data)?;

                // TODO: Is the pubnonce instance of this Signer object returned by the server?
                // Generate hashmap <internal index of Signer, pubnonce>
                let pubnonces = deserialize_musig(pubnonce_hashmap.values().cloned().collect(), PUBNONCE_CHUNK_LEN)?;

                // Create a vector of tuples (internal index of Signer, pubnonce)
                let pubnonces: Vec<(usize, PubNonce)> = pubnonces
                    .into_iter()
                    .map(|(index, pubnonce)| (index as usize, PubNonce::from_bytes(&pubnonce).unwrap()))
                    .collect();

                // Get copy of Signer object
                let mut signer: Signer = signer.clone();

                // Establish second round
                if let Some(message) = &mut self.message {
                    signer.second_round(&message, pubnonces);

                    if self.setup.with_card {
                        let aggnonce = signer.get_aggnonce()?;
                        let command = jc::command::set_agg_nonces(&aggnonce);
                        self.round = SignRound::R1PartiallySign(signer);

                        return Ok((command, Recipient::Card));
                    }

                    let mut out_buffer = signer
                        .get_partial_signature()
                        .serialize()
                        .to_vec();

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
            SignRound::R1PartiallySign(signer) => {
                jc::response::set_agg_nonces(data)?;
                let command: Vec<u8> = jc::command::sign(self.message.as_ref().unwrap().as_slice());
                self.round = SignRound::R1AwaitPartialSignature(signer.clone());
                Ok((command, Recipient::Card))
            }
            SignRound::R1AwaitPartialSignature(signer) => {
                let partial_signature = jc::response::sign(data)?;
                let mut signer = signer.clone();
                signer.set_partial_signature(partial_signature)?;

                let mut out_buffer = partial_signature
                        .serialize()
                        .to_vec();

                let internal_index = signer.get_index() as u8;

                out_buffer.push(internal_index);

                // Serialize the partial signature and the internal index of the signer. Format: &[u8] + u8
                let msg = serialize_bcast(&out_buffer, ProtocolType::Musig2)?;

                self.round = SignRound::R2(signer.clone());
                
                Ok((msg, Recipient::Server))
            }
            SignRound::R2(signer) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let shares_hashmap: HashMap<u32, Vec<u8>> = deserialize_map(&data)?;
                let shares = deserialize_musig(shares_hashmap.values().cloned().collect(), SCALAR_CHUNK_LEN)?;

                // Create a vector of tuples (internal index of Signer, partial signature)
                let partial_signatures: Vec<(usize, PartialSignature)> = shares
                    .into_iter()
                    .map(|(index, partial_signature)| (index as usize, PartialSignature::from_slice(&partial_signature).unwrap()))
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
                    Err(e) => Err(e.into()),
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
    use ::musig2::CompactSignature;
    use secp256k1::PublicKey;

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
                .collect();
            let results =
                <SignContext as ThresholdProtocolTest>::run(ctxs, msg.to_vec());

            let signature: CompactSignature = serde_json::from_slice(&results[0]).unwrap();

            for result in results {
                assert_eq!(signature, serde_json::from_slice(&result).unwrap());
            }

            assert!(::musig2::verify_single(pk, signature, msg).is_ok());
        }
    }
}

mod jc {
    mod util {
        use crate::protocol::Result;
        use k256::{
            elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
            AffinePoint, EncodedPoint,
        };

        pub fn reencode_point(ser: &[u8], compress: bool) -> Result<Box<[u8]>> {
            let encoded = EncodedPoint::from_bytes(ser)?;
            match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded)) {
                Some(affine) => Ok(affine.to_encoded_point(compress).to_bytes()),
                None => Err("Invalid point".into()),
            }
        }

        // By GitHub Copilot
        pub fn vec_removed<T: Clone>(vec: &Vec<T>, index: usize) -> Vec<T> {
            vec.iter()
                .enumerate()
                .filter(|&(i, _)| i != index)
                .map(|(_, item)| item.clone())
                .collect()
        }

    }

    pub mod command {
        use musig2::AggNonce;
        use secp256k1::{PublicKey, SecretKey};

        use super::util::reencode_point;
        use crate::protocol::apdu::CommandBuilder;

        const SCALAR_LEN: usize = 32;
        const POINT_LEN : usize = 33;

        const STATE_TRUE: u8 = 0xF4;
        const STATE_FALSE: u8 = 0x2C;

        const CLA: u8 = 0xA6;

        const INS_RESET: u8 = 0x65;

        const INS_GENERATE_KEYS: u8 = 0xBB;
        const INS_GENERATE_NONCES: u8 = 0x5E;
        const INS_SIGN: u8 = 0x49;

        const INS_GET_XONLY_PUBKEY: u8 = 0x8B;
        const INS_GET_PLAIN_PUBKEY: u8 = 0x5A;
        const INS_GET_PNONCE_SHARE: u8 = 0x35;

        const INS_SET_AGG_PUBKEY: u8 = 0x76;
        const INS_SET_AGG_NONCES: u8 = 0x9A;

        pub fn keygen_with_sk(sk: &SecretKey) -> Vec<u8> {
            let testing_value_switch: [u8; 5] = [STATE_TRUE, STATE_FALSE, STATE_FALSE, STATE_FALSE, STATE_FALSE];

            CommandBuilder::new(CLA, INS_GENERATE_KEYS)
                .extend(&testing_value_switch)
                .extend(&sk.secret_bytes())
                .build()
        }

        pub fn reset() -> Vec<u8> {
            CommandBuilder::new(CLA, INS_RESET)
            .build()
        }

        pub fn keygen() -> Vec<u8> {
            CommandBuilder::new(CLA, INS_GENERATE_KEYS)
                .build()
        }

        pub fn get_plain_pubkey() -> Vec<u8> {
            CommandBuilder::new(CLA, INS_GET_PLAIN_PUBKEY)
                .build()
        }

        pub fn set_aggpubkey(aggkey_q: PublicKey, coef_a: [u8; SCALAR_LEN]) -> Vec<u8> {

            CommandBuilder::new(CLA, INS_SET_AGG_PUBKEY)
                .extend(&reencode_point(&aggkey_q.serialize(), true).unwrap())
                .extend(&coef_a)
                .build()
        }

        pub fn noncegen() -> Vec<u8> {
            CommandBuilder::new(CLA, INS_GENERATE_NONCES)
                .build()
        }

        pub fn get_pubnonce() -> Vec<u8> {
            CommandBuilder::new(CLA, INS_GET_PNONCE_SHARE)
                .build()
        }

        pub fn set_agg_nonces(aggnonce: &AggNonce) -> Vec<u8> {

            let mut aggnonce_array = aggnonce.serialize();
            let aggnonce_pair = &aggnonce_array.split_at_mut(POINT_LEN);
            
            CommandBuilder::new(CLA, INS_SET_AGG_NONCES)
                .extend(&reencode_point(aggnonce_pair.0, true).unwrap())
                .extend(&reencode_point(aggnonce_pair.1, true).unwrap())
                .build()
        }

        pub fn sign(message: &[u8]) -> Vec<u8> {
            CommandBuilder::new(CLA, INS_SIGN)
                .extend(message)
                .build()
        }
    }

    pub mod response {
        use musig2::{PartialSignature, PubNonce};
        use secp256k1::PublicKey;

        use super::util::reencode_point;
        use crate::protocol::apdu::parse_response;
        use crate::protocol::Result;

        pub fn reset(raw: &[u8]) -> Result<()> {
            parse_response(raw)?;
            Ok(())
        }

        pub fn keygen(raw: &[u8]) -> Result<()> {
            parse_response(raw)?;
            Ok(())
        }

        pub fn get_plain_pubkey(raw: &[u8]) -> Result<PublicKey> {
            let data = parse_response(raw)?;
            let pubkey = PublicKey::from_slice(&reencode_point(data, true)?)?;
            Ok(pubkey)
        }

        pub fn set_aggpubkey(raw: &[u8]) -> Result<()> {
            parse_response(raw)?;
            Ok(())
        }

        pub fn noncegen(raw: &[u8]) -> Result<()> {
            parse_response(raw)?;
            Ok(())
        }

        pub fn get_pubnonce(raw: &[u8]) -> Result<PubNonce> {
            let data = parse_response(raw)?;
            let pubnonce = PubNonce::from_bytes(&data)?;
            Ok(pubnonce)
        }

        pub fn set_agg_nonces(raw: &[u8]) -> Result<()> {
            parse_response(raw)?;
            Ok(())
        }

        pub fn sign(raw: &[u8]) -> Result<PartialSignature> {
            let data = parse_response(raw)?;
            let signature = PartialSignature::from_slice(data)?;
            Ok(signature)
        }
    }



    #[cfg(test)]
    mod tests {
        use std::error::Error;

        use crate::protocol::{apdu::{parse_response, CommandBuilder}, musig2::{jc::command::sign, signer}};

        use super::{super::musig2, command::{self}, response};
        use pcsc::{self, Card};
        use ::musig2::{AggNonce, PartialSignature, PubNonce};
        use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};

        use super::util::vec_removed;

        fn prepare_card() -> Result<(Card, [u8; 264]), Box<dyn Error>> {
            // connect to card
            let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
            let mut readers_buf = [0; 2048];
            let reader = ctx
                .list_readers(&mut readers_buf)?
                .next()
                .ok_or("no reader")?;
            let card = ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;
            let mut resp_buf = [0; pcsc::MAX_BUFFER_SIZE];

            // select MUSIG2
            let aid = b"\x01\xff\xff\x04\x05\x06\x07\x08\x11\x01";
            let select = CommandBuilder::new(0x00, 0xA4).p1(0x04).extend(aid).build();
            let resp = card.transmit(&select, &mut resp_buf)?;
            parse_response(resp)?;

            // Reset card to default state
            let cmd = command::reset();
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            response::reset(resp)?;

            Ok((card, resp_buf))
        }

        // Card must be in DEBUG mode
        #[test]
        fn keygen_test() -> Result<(), Box<dyn Error>> {
            // connect to card
            let card; let mut resp_buf;
            (card, resp_buf) = prepare_card()?;

            let seckey_bytes: &[u8;32] = &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ];

            let our_sk = SecretKey::from_byte_array(seckey_bytes)?;
            let our_pair = Keypair::from_secret_key(&Secp256k1::new(), &our_sk);
            let our_pk = our_pair.public_key();

            // Generate PK on card
            let cmd = command::keygen_with_sk(&our_sk);
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            response::keygen(resp)?;

            let cmd = command::get_plain_pubkey();
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            let card_pubkey = response::get_plain_pubkey(resp)?;

            // Generate PK on device
            let signer = musig2::Signer::new_from_card(our_pk);
            let device_pubkey = signer.pubkey();

            assert_eq!(card_pubkey, device_pubkey);

            Ok(())
        }

        #[test]
        fn full_round_test() -> Result<(), Box<dyn Error>> {

            let card; let mut resp_buf;

            // connect to card
            (card, resp_buf) = prepare_card()?;

            // Must equal
            let n: u8 = 3;
            let message = "Testing mssg123";

            let mut signers: [musig2::Signer; 3] = [musig2::Signer::new(), musig2::Signer::new(), musig2::Signer::new()];

            // keygen
            let cmd = command::keygen();
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            response::keygen(resp)?;

            // get pubkey
            let cmd = command::get_plain_pubkey();
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            let card_pubkey = response::get_plain_pubkey(resp)?;

            // Initialize signers
            signers[0] = musig2::Signer::new_from_card(card_pubkey);

            for i in 1..(n) {
                signers[i as usize] = musig2::Signer::new();
            }

            // Get pubkeys
            let pubkeys: Vec<PublicKey> = signers
                .iter()
                .map(|s| s.pubkey())
                .collect();

            // sort and assign public key
            for i in 0..n {
                let pubkeys_wo_i = vec_removed(&pubkeys, i as usize);
                signers[i as usize].generate_key_agg_ctx(pubkeys_wo_i, None, false);
            }

            assert_eq!(signers[0].get_agg_pubkey(), signers[1].get_agg_pubkey());

            // set agg pubkey
            let agg_pubkey = signers[0].get_agg_pubkey();
            let cmd = command::set_aggpubkey(agg_pubkey, signers[0].get_coef_a().serialize());
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            response::set_aggpubkey(resp)?;

            // Generate and combine (first round) nonces
            let cmd = command::noncegen();
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            response::noncegen(resp)?;

            // Get pubnonce of this card
            let cmd = command::get_pubnonce();
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            let pubnonce_card = response::get_pubnonce(resp)?;
            
            signers[0].set_pubnonce(pubnonce_card)?;

            // Generate and get pubnonces of other signers
            for i in 1..n {
                signers[i as usize].first_round();
            }

            // Combine nonces (second round)
            let mut pubnonces_indexed: Vec<(usize, PubNonce)> = Vec::new();

            for i in 0..n {
                pubnonces_indexed.push((signers[i as usize].get_index(), signers[i as usize].get_pubnonce()?));
            }

            // Do second round
            for i in 0..n {
                let mut pubnonces_filtered = pubnonces_indexed.clone();
                pubnonces_filtered.remove(i as usize);
                signers[i as usize].second_round(&message.as_bytes().to_vec(), pubnonces_filtered);
            }

            // Compute aggnonce (second round). Only for the card.
            //let aggnonce: AggNonce = pubnonces.iter().sum(); // Same as in the Musig2 API
            let aggnonce: AggNonce = signers[0].get_aggnonce()?;

            assert_eq!(aggnonce, signers[1].get_aggnonce()?);

            // Load aggnonce onto the card
            let cmd = command::set_agg_nonces(&aggnonce);
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            response::set_agg_nonces(resp)?;

            // Get partial signature of the card
            let cmd = command::sign(message.as_bytes());
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            let partial_sig_card = response::sign(resp)?;
            signers[0].set_partial_signature(partial_sig_card)?;

            let partial_sigs_with_index: Vec<(usize, PartialSignature)> = signers
                .iter_mut()
                .map(|signer| (signer.get_index(), signer.get_partial_signature()))
                .collect();


            // Combine partial signatures (all signers)
            for i in 0..n {
                signers[i as usize].receive_partial_signatures(
                    vec_removed(&partial_sigs_with_index, i as usize)
                );
            }

            //Check signature by all signers
            for i in 0..n {
                let signature = signers[i as usize].get_agg_signature()?;
                assert!(::musig2::verify_single(signers[i as usize].get_agg_pubkey(), signature, message.as_bytes()).is_ok());
            }

            Ok(())
        }
    }
}
