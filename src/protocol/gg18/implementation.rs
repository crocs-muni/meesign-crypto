use crate::proto::{ProtocolGroupInit, ProtocolInit, ServerMessage};
use crate::protocol::*;
use crate::util::{deserialize_map, Message};
use mpecdsa::{gg18_key_gen::*, gg18_sign::*};
use prost::Message as _;
// TODO: use bincode instead?
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub(crate) struct KeygenContext {
    round: KeygenRound,
}

#[derive(Serialize, Deserialize)]
enum KeygenRound {
    R0,
    R1(GG18KeyGenContext1),
    R2(GG18KeyGenContext2),
    R3(GG18KeyGenContext3),
    R4(GG18KeyGenContext4),
    R5(GG18KeyGenContext5),
    Done(GG18SignContext),
}

/// Collects a hashmap's values sorted by their respective keys
fn map_to_sorted_vec<T>(map: HashMap<u32, T>) -> Vec<T> {
    let mut vec: Vec<_> = map.into_iter().collect();
    vec.sort_by_key(|(i, _)| *i);
    vec.into_iter().map(|(_, x)| x).collect()
}

impl KeygenContext {
    fn init(&mut self, data: &[u8]) -> Result<Message> {
        let msg = ProtocolGroupInit::decode(data)?;

        let (parties, threshold, index) =
            (msg.parties as u16, msg.threshold as u16, msg.index as u16);

        let (out, c1) = gg18_key_gen_1(parties, threshold, index)?;
        let msg = Message::serialize_reliable_broadcast(&out)?;

        self.round = KeygenRound::R1(c1);
        Ok(msg)
    }

    fn update(&mut self, data: &[u8]) -> Result<Message> {
        let data = ServerMessage::decode(data)?;

        let (c, msg) = match &self.round {
            KeygenRound::R0 => unreachable!(),
            KeygenRound::R1(c1) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c2) = gg18_key_gen_2(msgs, c1.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (KeygenRound::R2(c2), msg)
            }
            KeygenRound::R2(c2) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (outs, c3) = gg18_key_gen_3(msgs, c2.clone())?;

                let mut indices: Vec<_> = data.broadcasts.into_keys().collect();
                indices.sort();
                let outs = indices.into_iter().zip(outs.into_iter());
                let msg = Message::serialize_unicast(outs)?;
                (KeygenRound::R3(c3), msg)
            }
            KeygenRound::R3(c3) => {
                let msgs = deserialize_map(&data.unicasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c4) = gg18_key_gen_4(msgs, c3.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (KeygenRound::R4(c4), msg)
            }
            KeygenRound::R4(c4) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c5) = gg18_key_gen_5(msgs, c4.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (KeygenRound::R5(c5), msg)
            }
            KeygenRound::R5(c5) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let c = gg18_key_gen_6(msgs, c5.clone())?;
                let msg = Message::raw_reliable_broadcast(c.pk.to_bytes(false).to_vec());
                (KeygenRound::Done(c), msg)
            }
            KeygenRound::Done(_) => todo!(),
        };
        self.round = c;
        Ok(msg)
    }
}

#[typetag::serde(name = "gg18_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<Message> {
        let data = match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }?;
        Ok(data)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            KeygenRound::Done(ctx) => Ok(serde_json::to_vec(&ctx).unwrap()),
            _ => Err("protocol not finished".into()),
        }
    }
}

impl KeygenProtocol for KeygenContext {
    fn new() -> Self {
        Self {
            round: KeygenRound::R0,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SignContext {
    round: SignRound,
}

#[derive(Serialize, Deserialize)]
enum SignRound {
    R0(GG18SignContext),
    R1(GG18SignContext1),
    R2(GG18SignContext2),
    R3(GG18SignContext3),
    R4(GG18SignContext4),
    R5(GG18SignContext5),
    R6(GG18SignContext6),
    R7(GG18SignContext7),
    R8(GG18SignContext8),
    R9(GG18SignContext9),
    Done(Vec<u8>),
}

impl SignContext {
    fn init(&mut self, data: &[u8]) -> Result<Message> {
        let msg = ProtocolInit::decode(data)?;

        let indices: Vec<u16> = msg.indices.clone().into_iter().map(|i| i as u16).collect();
        let local_index = indices.iter().position(|&i| i == msg.index as u16).unwrap();

        let c0 = match &self.round {
            SignRound::R0(c0) => c0.clone(),
            _ => unreachable!(),
        };

        let (out, c1) = gg18_sign1(c0, indices, local_index, msg.data)?;
        let msg = Message::serialize_reliable_broadcast(&out)?;
        self.round = SignRound::R1(c1);
        Ok(msg)
    }

    fn update(&mut self, data: &[u8]) -> Result<Message> {
        let data = ServerMessage::decode(data)?;

        let (c, msg) = match &self.round {
            SignRound::R0(_) => unreachable!(),
            SignRound::R1(c1) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (outs, c2) = gg18_sign2(msgs, c1.clone())?;

                let mut indices: Vec<_> = data.broadcasts.into_keys().collect();
                indices.sort();
                let outs = indices.into_iter().zip(outs.into_iter());
                let msg = Message::serialize_unicast(outs)?;
                (SignRound::R2(c2), msg)
            }
            SignRound::R2(c2) => {
                let msgs = deserialize_map(&data.unicasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c3) = gg18_sign3(msgs, c2.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (SignRound::R3(c3), msg)
            }
            SignRound::R3(c3) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c4) = gg18_sign4(msgs, c3.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (SignRound::R4(c4), msg)
            }
            SignRound::R4(c4) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c5) = gg18_sign5(msgs, c4.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (SignRound::R5(c5), msg)
            }
            SignRound::R5(c5) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c6) = gg18_sign6(msgs, c5.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (SignRound::R6(c6), msg)
            }
            SignRound::R6(c6) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c7) = gg18_sign7(msgs, c6.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (SignRound::R7(c7), msg)
            }
            SignRound::R7(c7) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c8) = gg18_sign8(msgs, c7.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (SignRound::R8(c8), msg)
            }
            SignRound::R8(c8) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let (out, c9) = gg18_sign9(msgs, c8.clone())?;
                let msg = Message::serialize_reliable_broadcast(&out)?;
                (SignRound::R9(c9), msg)
            }
            SignRound::R9(c9) => {
                let msgs = deserialize_map(&data.broadcasts)?;
                let msgs = map_to_sorted_vec(msgs);
                let sig = gg18_sign10(msgs, c9.clone())?;
                let msg = Message::raw_reliable_broadcast(sig.clone());
                (SignRound::Done(sig), msg)
            }
            SignRound::Done(_) => todo!(),
        };

        self.round = c;
        Ok(msg)
    }
}

#[typetag::serde(name = "gg18_sign")]
impl Protocol for SignContext {
    fn advance(&mut self, data: &[u8]) -> Result<Message> {
        let data = match self.round {
            SignRound::R0(_) => self.init(data),
            _ => self.update(data),
        }?;
        Ok(data)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            SignRound::Done(sig) => Ok(sig),
            _ => Err("protocol not finished".into()),
        }
    }
}

impl ThresholdProtocol for SignContext {
    fn new(group: &[u8]) -> Self {
        Self {
            round: SignRound::R0(serde_json::from_slice(group).unwrap()),
        }
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use rand::{rngs::OsRng, seq::IteratorRandom};
    use sha2::Digest;

    use super::*;
    use crate::proto::ProtocolType;
    use crate::protocol::tests::{KeygenProtocolTest, ThresholdProtocolTest};

    impl KeygenProtocolTest for KeygenContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Gg18;
        const ROUNDS: usize = 6;
    }

    impl ThresholdProtocolTest for SignContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Gg18;
        const ROUNDS: usize = 10;
    }

    #[test]
    fn keygen() {
        for threshold in 2..6 {
            for parties in threshold..6 {
                let (pks, _) =
                    <KeygenContext as KeygenProtocolTest>::run(threshold as u32, parties as u32);

                let pks: Vec<_> = pks.into_values().collect();

                for i in 1..parties {
                    assert_eq!(pks[0], pks[i])
                }
            }
        }
    }

    #[test]
    fn sign() {
        for threshold in 2..6 {
            for parties in threshold..6 {
                let (pks, ctxs) =
                    <KeygenContext as KeygenProtocolTest>::run(threshold as u32, parties as u32);
                let msg = b"hello";
                let dgst = sha2::Sha256::digest(msg);

                let pks: Vec<_> = pks.into_values().collect();
                let pk = VerifyingKey::from_sec1_bytes(&pks[0]).unwrap();

                let ctxs = ctxs
                    .into_iter()
                    .choose_multiple(&mut OsRng, threshold)
                    .into_iter()
                    .collect();
                let results = <SignContext as ThresholdProtocolTest>::run(ctxs, dgst.to_vec());

                let signature = results[0].clone();

                for result in results {
                    assert_eq!(&signature, &result);
                }

                let mut buffer = [0u8; 64];
                buffer.copy_from_slice(&signature);
                let signature = Signature::from_bytes(&buffer.into()).unwrap();

                assert!(pk.verify(msg, &signature).is_ok());
            }
        }
    }
}
