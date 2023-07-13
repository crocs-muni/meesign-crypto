use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType};
use crate::protocol::*;
use crate::protocols::{deserialize_vec, inflate, pack, serialize_bcast, serialize_uni, unpack};

use frost::keys::dkg::{self, round1, round2};
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, Signature, SigningPackage};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::convert::{TryFrom, TryInto};

use frost_secp256k1 as frost;
use rand::rngs::OsRng;

#[derive(Serialize, Deserialize)]
pub struct KeygenContext {
    round: KeygenRound,
}

#[derive(Serialize, Deserialize)]
enum KeygenRound {
    R0,
    R1(round1::SecretPackage),
    R2(round2::SecretPackage, HashMap<Identifier, round1::Package>),
    Done(KeyPackage, PublicKeyPackage),
}

impl KeygenContext {
    pub fn new() -> Self {
        Self {
            round: KeygenRound::R0,
        }
    }

    fn init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = ProtocolGroupInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Frost as i32 {
            return Err("wrong protocol type".into());
        }

        let (parties, threshold, index) = (
            msg.parties as u16,
            msg.threshold as u16,
            (msg.index as u16).try_into()?,
        );

        let (secret_package, public_package) = dkg::part1(index, parties, threshold, OsRng)?;

        let msgs = serialize_bcast(&public_package, (parties - 1) as usize)?;
        self.round = KeygenRound::R1(secret_package);
        Ok(pack(msgs, ProtocolType::Frost))
    }

    fn index_to_identifier(mut index: usize, local_identifier: &Identifier) -> Identifier {
        index += 1;
        if &Identifier::try_from(index as u16).unwrap() >= local_identifier {
            index += 1
        };
        Identifier::try_from(index as u16).unwrap()
    }

    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let (c, msgs) = match &self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),
            KeygenRound::R1(secret) => {
                let data: Vec<round1::Package> = deserialize_vec(&unpack(data)?)?;
                let round1: HashMap<Identifier, round1::Package> = data
                    .into_iter()
                    .enumerate()
                    .map(|(i, msg)| (Self::index_to_identifier(i, secret.identifier()), msg))
                    .collect();
                let (secret, round2) = dkg::part2(secret.clone(), &round1)?;
                let mut round2: Vec<_> = round2.into_iter().collect();
                round2.sort_by_key(|(i, _)| *i);
                let round2: Vec<_> = round2.into_iter().map(|(_, p)| p).collect();

                (KeygenRound::R2(secret, round1), serialize_uni(round2)?)
            }
            KeygenRound::R2(secret, round1) => {
                let data: Vec<round2::Package> = deserialize_vec(&unpack(data)?)?;
                let round2: HashMap<Identifier, round2::Package> = data
                    .into_iter()
                    .enumerate()
                    .map(|(i, msg)| (Self::index_to_identifier(i, secret.identifier()), msg))
                    .collect();
                let (key, pubkey) = frost::keys::dkg::part3(secret, &round1, &round2)?;

                let msgs = inflate(serde_json::to_vec(&pubkey)?, round2.len());
                (KeygenRound::Done(key, pubkey), msgs)
            }
            KeygenRound::Done(_, _) => return Err("protocol already finished".into()),
        };
        self.round = c;

        Ok(pack(msgs, ProtocolType::Frost))
    }
}

#[typetag::serde(name = "frost_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let data = match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }?;
        Ok(data)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            KeygenRound::Done(key_package, pubkey_package) => {
                Ok(serde_json::to_vec(&(key_package, pubkey_package))?)
            }
            _ => Err("protocol not finished".into()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SignContext {
    key: KeyPackage,
    pubkey: PublicKeyPackage,
    message: Option<Vec<u8>>,
    indices: Option<Vec<u16>>,
    round: SignRound,
}

#[derive(Serialize, Deserialize)]
enum SignRound {
    R0,
    R1(SigningNonces, SigningCommitments),
    R2(SigningPackage, SignatureShare),
    Done(Signature),
}

impl SignContext {
    pub fn new(group: &[u8]) -> Self {
        let (key, pubkey): (KeyPackage, PublicKeyPackage) =
            serde_json::from_slice(group).expect("could not deserialize group context");
        Self {
            key,
            pubkey,
            message: None,
            indices: None,
            round: SignRound::R0,
        }
    }

    fn local_index(&self) -> Result<usize> {
        let identifier = self.key.identifier();
        self.indices
            .as_ref()
            .and_then(|indices| {
                indices
                    .iter()
                    .position(|x| &Identifier::try_from(*x).unwrap() == identifier)
            })
            .ok_or("participant index not included".into())
    }

    fn init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = ProtocolInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Frost as i32 {
            return Err("wrong protocol type".into());
        }

        self.indices = Some(msg.indices.iter().map(|i| *i as u16).collect());
        self.message = Some(msg.data);

        let (nonces, commitments) = frost::round1::commit(self.key.secret_share(), &mut OsRng);

        let msgs = serialize_bcast(&commitments, self.indices.as_ref().unwrap().len() - 1)?;
        self.round = SignRound::R1(nonces, commitments);
        Ok(pack(msgs, ProtocolType::Frost))
    }

    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        match &self.round {
            SignRound::R0 => Err("protocol not initialized".into()),
            SignRound::R1(nonces, commitments) => {
                let local_index = self.local_index()?;
                let data: Vec<SigningCommitments> = deserialize_vec(&unpack(data)?)?;

                let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = data
                    .into_iter()
                    .enumerate()
                    .map(|(i, msg)| {
                        (
                            Identifier::try_from(
                                self.indices.as_ref().unwrap()
                                    [if i >= local_index { i + 1 } else { i }],
                            )
                            .unwrap(),
                            msg,
                        )
                    })
                    .collect();
                commitments_map.insert(*self.key.identifier(), *commitments);

                let signing_package =
                    frost::SigningPackage::new(commitments_map, self.message.as_ref().unwrap());
                let share = frost::round2::sign(&signing_package, nonces, &self.key)?;

                let msgs = serialize_bcast(&share, self.indices.as_ref().unwrap().len() - 1)?;
                self.round = SignRound::R2(signing_package, share);
                Ok(pack(msgs, ProtocolType::Frost))
            }
            SignRound::R2(signing_package, share) => {
                let local_index = self.local_index()?;
                let data: Vec<SignatureShare> = deserialize_vec(&unpack(data)?)?;

                let mut shares: HashMap<Identifier, SignatureShare> = data
                    .into_iter()
                    .enumerate()
                    .map(|(i, msg)| {
                        (
                            Identifier::try_from(
                                self.indices.as_ref().unwrap()
                                    [if i >= local_index { i + 1 } else { i }],
                            )
                            .unwrap(),
                            msg,
                        )
                    })
                    .collect();
                shares.insert(*self.key.identifier(), *share);

                let signature = frost::aggregate(signing_package, &shares, &self.pubkey)?;

                let msgs = serialize_bcast(&signature, self.indices.as_ref().unwrap().len() - 1)?;
                self.round = SignRound::Done(signature);
                Ok(pack(msgs, ProtocolType::Frost))
            }
            SignRound::Done(_) => Err("protocol already finished".into()),
        }
    }
}

#[typetag::serde(name = "frost_sign")]
impl Protocol for SignContext {
    fn advance(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let data = match self.round {
            SignRound::R0 => self.init(data),
            _ => self.update(data),
        }?;
        Ok(data)
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            SignRound::Done(sig) => Ok(serde_json::to_vec(&sig)?),
            _ => Err("protocol not finished".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::bytes::Bytes;

    use super::*;
    use crate::proto::ProtocolMessage;

    #[test]
    fn test_keygen() {
        keygen();
    }

    fn keygen() -> (PublicKeyPackage, Vec<u8>, Vec<u8>) {
        let protocol_type = ProtocolType::Frost as i32;
        let threshold = 2;
        let parties = 2;
        let mut p1 = KeygenContext::new();
        let mut p2 = KeygenContext::new();

        let p1_data = p1
            .init(
                &(ProtocolGroupInit {
                    protocol_type,
                    index: 1,
                    parties,
                    threshold,
                })
                .encode_to_vec(),
            )
            .unwrap();
        let p2_data = p2
            .init(
                &(ProtocolGroupInit {
                    protocol_type,
                    index: 2,
                    parties,
                    threshold,
                })
                .encode_to_vec(),
            )
            .unwrap();

        let p1_msg = ProtocolMessage::decode(Bytes::from(p1_data))
            .unwrap()
            .message;
        let p2_msg = ProtocolMessage::decode(Bytes::from(p2_data))
            .unwrap()
            .message;

        let p1_data = p1
            .update(
                &(ProtocolMessage {
                    protocol_type,
                    message: vec![p2_msg[0].clone()],
                })
                .encode_to_vec(),
            )
            .unwrap();
        let p2_data = p2
            .update(
                &(ProtocolMessage {
                    protocol_type,
                    message: vec![p1_msg[0].clone()],
                })
                .encode_to_vec(),
            )
            .unwrap();

        let p1_msg = ProtocolMessage::decode(Bytes::from(p1_data))
            .unwrap()
            .message;
        let p2_msg = ProtocolMessage::decode(Bytes::from(p2_data))
            .unwrap()
            .message;

        let p1_data = p1
            .update(
                &(ProtocolMessage {
                    protocol_type,
                    message: vec![p2_msg[0].clone()],
                })
                .encode_to_vec(),
            )
            .unwrap();
        let p2_data = p2
            .update(
                &(ProtocolMessage {
                    protocol_type,
                    message: vec![p1_msg[0].clone()],
                })
                .encode_to_vec(),
            )
            .unwrap();

        let p1_msg = ProtocolMessage::decode(Bytes::from(p1_data))
            .unwrap()
            .message;
        let p2_msg = ProtocolMessage::decode(Bytes::from(p2_data))
            .unwrap()
            .message;

        let p1_key: PublicKeyPackage = serde_json::from_slice(&p1_msg[0]).unwrap();
        let p2_key: PublicKeyPackage = serde_json::from_slice(&p2_msg[0]).unwrap();

        assert_eq!(p1_key, p2_key);
        (
            p1_key,
            Box::new(p1).finish().unwrap(),
            Box::new(p2).finish().unwrap(),
        )
    }

    #[test]
    fn test_sign() {
        let (pk, p1, p2) = keygen();
        let message = b"hello";

        let mut p1 = SignContext::new(&p1);
        let mut p2 = SignContext::new(&p2);

        let p1_data = p1
            .init(
                &(ProtocolInit {
                    protocol_type: ProtocolType::Frost as i32,
                    index: 1,
                    indices: vec![1, 2],
                    data: message.to_vec(),
                })
                .encode_to_vec(),
            )
            .unwrap();
        let p2_data = p2
            .init(
                &(ProtocolInit {
                    protocol_type: ProtocolType::Frost as i32,
                    index: 2,
                    indices: vec![1, 2],
                    data: message.to_vec(),
                })
                .encode_to_vec(),
            )
            .unwrap();

        let p1_msg = ProtocolMessage::decode(Bytes::from(p1_data))
            .unwrap()
            .message;
        let p2_msg = ProtocolMessage::decode(Bytes::from(p2_data))
            .unwrap()
            .message;

        let p1_data = p1
            .update(
                &(ProtocolMessage {
                    protocol_type: ProtocolType::Frost as i32,
                    message: vec![p2_msg[0].clone()],
                })
                .encode_to_vec(),
            )
            .unwrap();
        let p2_data = p2
            .update(
                &(ProtocolMessage {
                    protocol_type: ProtocolType::Frost as i32,
                    message: vec![p1_msg[0].clone()],
                })
                .encode_to_vec(),
            )
            .unwrap();

        let p1_msg = ProtocolMessage::decode(Bytes::from(p1_data))
            .unwrap()
            .message;
        let p2_msg = ProtocolMessage::decode(Bytes::from(p2_data))
            .unwrap()
            .message;

        let p1_data = p1
            .update(
                &(ProtocolMessage {
                    protocol_type: ProtocolType::Frost as i32,
                    message: vec![p2_msg[0].clone()],
                })
                .encode_to_vec(),
            )
            .unwrap();
        let p2_data = p2
            .update(
                &(ProtocolMessage {
                    protocol_type: ProtocolType::Frost as i32,
                    message: vec![p1_msg[0].clone()],
                })
                .encode_to_vec(),
            )
            .unwrap();

        let p1_msg = ProtocolMessage::decode(Bytes::from(p1_data))
            .unwrap()
            .message;
        let p2_msg = ProtocolMessage::decode(Bytes::from(p2_data))
            .unwrap()
            .message;

        let signature: Signature = serde_json::from_slice(&p1_msg[0]).unwrap();

        assert_eq!(signature, serde_json::from_slice(&p2_msg[0]).unwrap());
        assert_eq!(
            signature,
            serde_json::from_slice(&Box::new(p1).finish().unwrap()).unwrap()
        );
        assert_eq!(
            signature,
            serde_json::from_slice(&Box::new(p2).finish().unwrap()).unwrap()
        );

        assert!(pk.group_public().verify(message, &signature).is_ok());
    }
}