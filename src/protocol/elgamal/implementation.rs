use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType, ServerMessage};
use crate::protocol::*;
use crate::util::{deserialize_map, encode_raw_bcast, serialize_bcast, serialize_uni};
use curve25519_dalek::{
    ristretto::RistrettoPoint,
    scalar::Scalar,
};
use elastic_elgamal::{
    dkg::*,
    group::Ristretto,
    sharing::{ActiveParticipant, Params},
    Ciphertext, LogEqualityProof, VerifiableDecryption,
};
use rand::rngs::OsRng;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes128Gcm,
};
use prost::Message;
use serde::{Deserialize, Serialize};

use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
pub(crate) struct KeygenContext {
    round: KeygenRound,
}

#[derive(Serialize, Deserialize)]
enum KeygenRound {
    R0,
    R1(ParticipantCollectingCommitments<Ristretto>),
    R2(ParticipantCollectingPolynomials<Ristretto>),
    R3(ParticipantExchangingSecrets<Ristretto>),
    Done(ActiveParticipant<Ristretto>),
}

impl KeygenContext {
    fn init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = ProtocolGroupInit::decode(data)?;

        if msg.protocol_type != ProtocolType::Elgamal as i32 {
            return Err("wrong protocol type".into());
        }

        let (parties, threshold, index) =
            (msg.parties as u16, msg.threshold as u16, msg.index as u16);

        let params = Params::new(parties.into(), threshold.into());

        let dkg =
            ParticipantCollectingCommitments::<Ristretto>::new(params, index.into(), &mut OsRng);
        let c = dkg.commitment();
        let msg = serialize_bcast(&c, ProtocolType::Elgamal)?;
        self.round = KeygenRound::R1(dkg);
        Ok(msg)
    }

    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msgs = ServerMessage::decode(data)?;

        let (c, msg) = match &self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),
            KeygenRound::R1(dkg) => {
                let mut dkg = dkg.clone();
                let data = deserialize_map(&msgs.broadcasts)?;
                for (i, msg) in data {
                    dkg.insert_commitment(i as usize, msg);
                }
                if dkg.missing_commitments().next().is_some() {
                    return Err("not enough commitments".into());
                }
                let dkg = dkg.finish_commitment_phase();
                let public_info = dkg.public_info();
                let msg = serialize_bcast(&public_info, ProtocolType::Elgamal)?;

                (KeygenRound::R2(dkg), msg)
            }
            KeygenRound::R2(dkg) => {
                let mut dkg = dkg.clone();
                let data = deserialize_map(&msgs.broadcasts)?;
                for (i, msg) in data {
                    dkg.insert_public_polynomial(i as usize, msg)?
                }
                if dkg.missing_public_polynomials().next().is_some() {
                    return Err("not enough polynomials".into());
                }
                let dkg = dkg.finish_polynomials_phase();

                let shares = msgs
                    .broadcasts
                    .into_keys()
                    .map(|i| (i, dkg.secret_share_for_participant(i as usize)));

                let msg = serialize_uni(shares, ProtocolType::Elgamal)?;

                (KeygenRound::R3(dkg), msg)
            }
            KeygenRound::R3(dkg) => {
                let mut dkg = dkg.clone();
                let data = deserialize_map(&msgs.unicasts)?;
                for (i, msg) in data {
                    dkg.insert_secret_share(i as usize, msg)?;
                }
                if dkg.missing_shares().next().is_some() {
                    return Err("not enough shares".into());
                }
                let dkg = dkg.complete()?;

                let msg = encode_raw_bcast(
                    dkg.key_set().shared_key().as_bytes().to_vec(),
                    ProtocolType::Elgamal,
                );
                (KeygenRound::Done(dkg), msg)
            }
            KeygenRound::Done(_) => return Err("protocol already finished".into()),
        };

        self.round = c;
        Ok(msg)
    }
}

#[typetag::serde(name = "elgamal_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let data = match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }?;
        Ok((data, Recipient::Server))
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            KeygenRound::Done(ctx) => Ok(serde_json::to_vec(&ctx)?),
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
pub(crate) struct DecryptContext {
    ctx: ActiveParticipant<Ristretto>,
    encrypted_key: Ciphertext<Ristretto>,
    data: (Vec<u8>, Vec<u8>, Vec<u8>),
    shares: Vec<(usize, VerifiableDecryption<Ristretto>)>,
    result: Option<Vec<u8>>,
}

impl DecryptContext {
    fn init(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let msg = ProtocolInit::decode(data)?;

        if msg.protocol_type != ProtocolType::Elgamal as i32 {
            return Err("wrong protocol type".into());
        }

        self.data = serde_json::from_slice(&msg.data)?;
        self.encrypted_key = serde_json::from_slice(&self.data.0)?;

        let (share, proof) = self.ctx.decrypt_share(self.encrypted_key, &mut OsRng);

        let msg = serialize_bcast(
            &serde_json::to_string(&(share, proof))?.as_bytes(),
            ProtocolType::Elgamal,
        )?;

        let share = (self.ctx.index(), share);
        self.shares.push(share);

        Ok(msg)
    }

    fn update(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        if self.shares.is_empty() {
            return Err("protocol not initialized".into());
        }
        if self.result.is_some() {
            return Err("protocol already finished".into());
        }

        let msgs = ServerMessage::decode(data)?;

        let data: HashMap<u32, Vec<u8>> = deserialize_map(&msgs.broadcasts)?;
        for (i, msg) in data {
            let msg: (VerifiableDecryption<Ristretto>, LogEqualityProof<Ristretto>) =
                serde_json::from_slice(&msg)?;
            self.ctx
                .key_set()
                .verify_share(msg.0.into(), self.encrypted_key, i as usize, &msg.1)
                .unwrap();
            self.shares.push((i as usize, msg.0));
        }

        let mut key = [0u8; 16];
        key.copy_from_slice(&decode(
            self.encrypted_key.blinded_element()
                - self
                    .ctx
                    .key_set()
                    .params()
                    .combine_shares(self.shares.clone())
                    .unwrap()
                    .as_element(),
        ));
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&self.data.1);

        let cipher = Aes128Gcm::new(&key.into());

        let msg = cipher
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &self.data.2,
                    aad: &self.data.0,
                },
            )
            .unwrap();

        self.result = Some(msg.clone());

        let msg = encode_raw_bcast(msg, ProtocolType::Elgamal);
        Ok(msg)
    }
}

#[typetag::serde(name = "elgamal_decrypt")]
impl Protocol for DecryptContext {
    fn advance(&mut self, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let data = if self.shares.is_empty() {
            self.init(data)
        } else {
            self.update(data)
        }?;
        Ok((data, Recipient::Server))
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        if self.result.is_none() {
            return Err("protocol not finished".into());
        }
        Ok(self.result.unwrap())
    }
}

impl ThresholdProtocol for DecryptContext {
    fn new(group: &[u8]) -> Self {
        Self {
            ctx: serde_json::from_slice(group).expect("could not deserialize group context"),
            encrypted_key: Ciphertext::zero(),
            data: (Vec::new(), Vec::new(), Vec::new()),
            shares: Vec::new(),
            result: None,
        }
    }
}



fn decode(p: RistrettoPoint) -> Vec<u8> {
    let scalar = Scalar::from_bytes_mod_order(p.compress().to_bytes());
    let scalar_bytes = &scalar.as_bytes()[1..];
    scalar_bytes[1..(scalar_bytes[0] as usize + 1)].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tests::{KeygenProtocolTest, ThresholdProtocolTest};
    use rand::seq::IteratorRandom;

    impl KeygenProtocolTest for KeygenContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Elgamal;
        const ROUNDS: usize = 4;
    }

    impl ThresholdProtocolTest for DecryptContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Elgamal;
        const ROUNDS: usize = 2;
    }

    #[test]
    fn test_encode() {
        let message = b"hello";
        let point = try_encode(message).unwrap();
        let decoded = decode(point);
        assert_eq!(message, decoded.as_slice());
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
    fn decrypt() {
        for threshold in 2..6 {
            for parties in threshold..6 {
                let (pks, ctxs) =
                    <KeygenContext as KeygenProtocolTest>::run(threshold as u32, parties as u32);
                let pks: Vec<_> = pks.into_values().collect();
                let msg = b"hello";
                let ct = encrypt(msg, &pks[0]).unwrap();

                let ctxs = ctxs
                    .into_iter()
                    .choose_multiple(&mut OsRng, threshold)
                    .into_iter()
                    .collect();
                let results = <DecryptContext as ThresholdProtocolTest>::run(ctxs, ct.to_vec());

                for result in results {
                    assert_eq!(&msg.to_vec(), &result);
                }
            }
        }
    }
}
