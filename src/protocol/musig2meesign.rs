use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType, ServerMessage};
use crate::protocol::*;

use signer::Signer;
use musig2::CompactSignature;
use prost::Message;
use serde::{Deserialize, Serialize};

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
    use musig2::CompactSignature;
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

