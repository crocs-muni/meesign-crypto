use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType, ServerMessage};
use crate::protocol::*;
use crate::util::{deserialize_map, Message};

use frost::keys::dkg::{self, round1, round2};
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, Signature, SigningPackage};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};

use frost_secp256k1 as frost;
use rand::rngs::OsRng;

#[derive(Serialize, Deserialize, Clone, Copy)]
struct Setup {
    threshold: u16,
    parties: u16,
    index: u16,
}

/// Helper intended for use in `iterator.map`
fn index_to_identifier<T>((i, x): (u32, T)) -> (Identifier, T) {
    assert!(i > 0);
    assert!(i <= u16::MAX as u32);
    (Identifier::try_from(i as u16).unwrap(), x)
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeygenContext {
    round: KeygenRound,
    with_card: bool,
}

#[derive(Serialize, Deserialize)]
enum KeygenRound {
    R0,
    R1(Setup, round1::SecretPackage),
    R2(
        Setup,
        round2::SecretPackage,
        BTreeMap<Identifier, round1::Package>,
    ),
    R21AwaitSetupResp(Setup, PublicKeyPackage),
    Done(Setup, Option<KeyPackage>, PublicKeyPackage),
}

impl KeygenContext {
    pub fn with_card() -> Self {
        Self {
            round: KeygenRound::R0,
            with_card: true,
        }
    }

    fn init(&mut self, data: &[u8]) -> Result<Message> {
        let msg = ProtocolGroupInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Frost as i32 {
            return Err("wrong protocol type".into());
        }

        let setup = Setup {
            threshold: msg.threshold as u16,
            parties: msg.parties as u16,
            index: msg.index as u16,
        };

        let (secret_package, public_package) = dkg::part1(
            setup.index.try_into()?,
            setup.parties,
            setup.threshold,
            OsRng,
        )?;

        let msg = Message::serialize_reliable_broadcast(&public_package)?;
        self.round = KeygenRound::R1(setup, secret_package);
        Ok(msg)
    }

    fn update(&mut self, data: &[u8]) -> Result<Message> {
        let (c, data) = match &self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),
            KeygenRound::R1(setup, secret) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let round1 = deserialize_map(&data)?;
                let indices: Vec<_> = round1.keys().cloned().collect();
                let round1 = round1.into_iter().map(index_to_identifier).collect();
                let (secret, round2) = dkg::part2(secret.clone(), &round1)?;

                let round2 = indices.into_iter().map(|i| {
                    let id = Identifier::try_from(i as u16).unwrap();
                    (i, round2.get(&id))
                });

                (KeygenRound::R2(*setup, secret, round1), Message::serialize_unicast(round2)?)
            }
            KeygenRound::R2(setup, secret, round1) => {
                let data = ServerMessage::decode(data)?.unicasts;
                let round2 = deserialize_map(&data)?;
                let round2 = round2.into_iter().map(index_to_identifier).collect();
                let (key, pubkey) = frost::keys::dkg::part3(secret, round1, &round2)?;

                if !self.with_card {
                    let msg = Message::serialize_broadcast(&pubkey.verifying_key())?;
                    (KeygenRound::Done(*setup, Some(key), pubkey), msg)
                } else {
                    let command = jc::command::setup(
                        setup.threshold as u8,
                        setup.parties as u8,
                        setup.index as u8,
                        key.signing_share(),
                        pubkey.verifying_key(),
                    );
                    (KeygenRound::R21AwaitSetupResp(*setup, pubkey), Message::new_card_command(command))
                }
            }
            KeygenRound::R21AwaitSetupResp(setup, pubkey) => {
                jc::response::setup(data)?;
                let msg =                     Message::serialize_broadcast(&pubkey.verifying_key())?;
                (KeygenRound::Done(*setup, None, pubkey.clone()), msg)
            }
            KeygenRound::Done(_, _, _) => return Err("protocol already finished".into()),
        };
        self.round = c;

        Ok(data)
    }
}

#[typetag::serde(name = "frost_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<Message> {
        match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            KeygenRound::Done(setup, key_package, pubkey_package) => {
                Ok(serde_json::to_vec(&(setup, key_package, pubkey_package))?)
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

#[derive(Serialize, Deserialize)]
pub(crate) struct SignContext {
    setup: Setup,
    key: Option<KeyPackage>,
    pubkey: PublicKeyPackage,
    message: Option<Vec<u8>>,
    indices: Option<Vec<u16>>,
    round: SignRound,
}

#[derive(Serialize, Deserialize)]
enum SignRound {
    R0,
    R01AwaitCommitResp,
    R1(Option<SigningNonces>, SigningCommitments),
    R11AwaitCommitmentResp(usize, SigningPackage),
    R12AwaitSignResp(SigningPackage),
    R2(SigningPackage, SignatureShare),
    Done(Signature),
}

impl SignContext {
    fn participants(&self) -> usize {
        self.indices.as_ref().unwrap().len()
    }

    fn init(&mut self, data: &[u8]) -> Result<Message> {
        let msg = ProtocolInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Frost as i32 {
            return Err("wrong protocol type".into());
        }

        self.indices = Some(msg.indices.iter().map(|i| *i as u16).collect());
        self.message = Some(msg.data);

        if let Some(key) = &self.key {
            let (nonces, commitments) = frost::round1::commit(key.signing_share(), &mut OsRng);

            let msg = Message::serialize_broadcast(&commitments)?;
            self.round = SignRound::R1(Some(nonces), commitments);
            Ok(msg)
        } else {
            self.round = SignRound::R01AwaitCommitResp;
            let command = Message::new_card_command(jc::command::commit());
            Ok(command)
        }
    }

    fn update(&mut self, data: &[u8]) -> Result<Message> {
        match &self.round {
            SignRound::R0 => Err("protocol not initialized".into()),
            SignRound::R01AwaitCommitResp => {
                let commitments = jc::response::commit(data)?;
                let msg = Message::serialize_broadcast(&commitments)?;
                self.round = SignRound::R1(None, commitments);
                Ok(msg)
            }
            SignRound::R1(nonces, commitments) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let commitments_map = deserialize_map(&data)?;
                let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = commitments_map
                    .into_iter()
                    .map(index_to_identifier)
                    .collect();
                let identifier = Identifier::try_from(self.setup.index).unwrap();
                commitments_map.insert(identifier, *commitments);

                let signing_package =
                    frost::SigningPackage::new(commitments_map, self.message.as_ref().unwrap());

                if let Some(key) = &self.key {
                    let share =
                        frost::round2::sign(&signing_package, nonces.as_ref().unwrap(), key)?;
                    let msg = Message::serialize_broadcast(&share)?;
                    self.round = SignRound::R2(signing_package, share);
                    Ok(msg)
                } else {
                    let index = self.indices.as_deref().unwrap()[0];
                    let command = jc::command::commitment(
                        index as u8,
                        &signing_package
                            .signing_commitment(&index.try_into().unwrap())
                            .unwrap(),
                    );
                    self.round = SignRound::R11AwaitCommitmentResp(0, signing_package);
                    Ok(Message::new_card_command(command))
                }
            }
            SignRound::R11AwaitCommitmentResp(i, signing_package)
                if *i < self.participants() - 1 =>
            {
                jc::response::commitment(data)?;

                let i = *i + 1;
                let index = self.indices.as_deref().unwrap()[i];
                let command = jc::command::commitment(
                    index as u8,
                    &signing_package
                        .signing_commitment(&index.try_into().unwrap())
                        .unwrap(),
                );
                self.round = SignRound::R11AwaitCommitmentResp(i, signing_package.clone());
                Ok(Message::new_card_command(command))
            }
            SignRound::R11AwaitCommitmentResp(_, signing_package) => {
                jc::response::commitment(data)?;

                let command = jc::command::sign(self.message.as_ref().unwrap());
                self.round = SignRound::R12AwaitSignResp(signing_package.clone());
                Ok(Message::new_card_command(command))
            }
            SignRound::R12AwaitSignResp(signing_package) => {
                let share = jc::response::sign(data)?;
                let msg = Message::serialize_broadcast(&share)?;
                self.round = SignRound::R2(signing_package.clone(), share);
                Ok(msg)
            }
            SignRound::R2(signing_package, share) => {
                let data = ServerMessage::decode(data)?.broadcasts;
                let shares = deserialize_map(&data)?;
                let mut shares: BTreeMap<Identifier, SignatureShare> =
                    shares.into_iter().map(index_to_identifier).collect();
                let identifier = Identifier::try_from(self.setup.index).unwrap();
                shares.insert(identifier, *share);

                let signature = frost::aggregate(signing_package, &shares, &self.pubkey)?;

                let msg = Message::serialize_broadcast(&signature)?;
                self.round = SignRound::Done(signature);
                Ok(msg)
            }
            SignRound::Done(_) => Err("protocol already finished".into()),
        }
    }
}

#[typetag::serde(name = "frost_sign")]
impl Protocol for SignContext {
    fn advance(&mut self, data: &[u8]) -> Result<Message> {
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
        let (setup, key, pubkey): (Setup, Option<KeyPackage>, PublicKeyPackage) =
            serde_json::from_slice(group).expect("could not deserialize group context");
        Self {
            setup,
            key,
            pubkey,
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
    use frost::VerifyingKey;
    use rand::seq::IteratorRandom;

    impl KeygenProtocolTest for KeygenContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Frost;
        const ROUNDS: usize = 3;
        const INDEX_OFFSET: u32 = 1;
    }

    impl ThresholdProtocolTest for SignContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Frost;
        const ROUNDS: usize = 3;
        const INDEX_OFFSET: u32 = 1;
    }

    #[test]
    fn keygen() {
        for threshold in 2..6 {
            for parties in threshold..6 {
                let (pks, _) =
                    <KeygenContext as KeygenProtocolTest>::run(threshold as u32, parties as u32);

                let pks: Vec<VerifyingKey> = pks
                    .iter()
                    .map(|(_, x)| serde_json::from_slice(&x).unwrap())
                    .collect();

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
                let (_, pk) = pks.iter().take(1).collect::<Vec<_>>()[0];
                let pk: VerifyingKey = serde_json::from_slice(&pk).unwrap();

                let ctxs = ctxs
                    .into_iter()
                    .choose_multiple(&mut OsRng, threshold)
                    .into_iter()
                    .collect();
                let results = <SignContext as ThresholdProtocolTest>::run(ctxs, msg.to_vec());

                let signature: Signature = serde_json::from_slice(&results[0]).unwrap();

                for result in results {
                    assert_eq!(signature, serde_json::from_slice(&result).unwrap());
                }

                assert!(pk.verify(msg, &signature).is_ok());
            }
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
    }

    pub mod command {
        use super::super::frost;
        use super::util::reencode_point;
        use crate::protocol::apdu::CommandBuilder;
        use frost::round1;

        const CLA: u8 = 0;

        const INS_SETUP: u8 = 1;
        const INS_COMMIT: u8 = 2;
        const INS_COMMITMENT: u8 = 3;
        const INS_SIGN: u8 = 4;

        pub fn setup(
            t: u8,
            n: u8,
            identifier: u8,
            secret: &frost::keys::SigningShare,
            group_public: &frost::VerifyingKey,
        ) -> Vec<u8> {
            CommandBuilder::new(CLA, INS_SETUP)
                .p1(t)
                .p2(n)
                .push(identifier)
                .extend(&secret.serialize())
                .extend(&reencode_point(&group_public.serialize(), false).unwrap())
                .build()
        }

        pub fn commit() -> Vec<u8> {
            CommandBuilder::new(CLA, INS_COMMIT).build()
        }

        pub fn commitment(identifier: u8, commitments: &round1::SigningCommitments) -> Vec<u8> {
            CommandBuilder::new(CLA, INS_COMMITMENT)
                .p1(identifier)
                .extend(&reencode_point(&commitments.hiding().serialize(), false).unwrap())
                .extend(&reencode_point(&commitments.binding().serialize(), false).unwrap())
                .build()
        }

        pub fn sign(message: &[u8]) -> Vec<u8> {
            CommandBuilder::new(CLA, INS_SIGN)
                .p1(message.len() as u8)
                .extend(message)
                .build()
        }
    }

    pub mod response {
        use super::super::frost;
        use super::util::reencode_point;
        use crate::protocol::apdu::parse_response;
        use crate::protocol::Result;
        use frost::{round1, round2};
        use std::convert::TryInto;

        pub fn setup(raw: &[u8]) -> Result<()> {
            parse_response(raw)?;
            Ok(())
        }

        pub fn commit(raw: &[u8]) -> Result<round1::SigningCommitments> {
            let data = parse_response(raw)?;
            let (hiding, binding) = data.split_at(data.len() / 2);
            let hiding = round1::NonceCommitment::deserialize(
                reencode_point(hiding, true)?.as_ref().try_into().unwrap(),
            )?;
            let binding = round1::NonceCommitment::deserialize(
                reencode_point(binding, true)?.as_ref().try_into().unwrap(),
            )?;
            Ok(round1::SigningCommitments::new(hiding, binding))
        }

        pub fn commitment(raw: &[u8]) -> Result<()> {
            parse_response(raw)?;
            Ok(())
        }

        pub fn sign(raw: &[u8]) -> Result<round2::SignatureShare> {
            let data = parse_response(raw)?;
            let signature = round2::SignatureShare::deserialize(data.try_into()?)?;
            Ok(signature)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            collections::{BTreeMap, HashMap},
            convert::TryFrom,
            error::Error,
        };

        use crate::protocol::apdu::{parse_response, CommandBuilder};

        use super::{super::frost, command, response};
        use frost::Identifier;
        use pcsc;
        use rand::rngs::OsRng;

        #[test]
        fn sign_card() -> Result<(), Box<dyn Error>> {
            // connect to card
            let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
            let mut readers_buf = [0; 2048];
            let reader = ctx
                .list_readers(&mut readers_buf)?
                .next()
                .ok_or("no reader")?;
            let card = ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;
            let mut resp_buf = [0; pcsc::MAX_BUFFER_SIZE];

            // select JCFROST
            let aid = b"\x6a\x63\x66\x72\x6f\x73\x74\x61\x70\x70";
            let select = CommandBuilder::new(0x00, 0xa4).p1(0x04).extend(aid).build();
            let resp = card.transmit(&select, &mut resp_buf)?;
            parse_response(resp)?;

            let t: u8 = 2;
            let n: u8 = 3;

            // keygen
            let (key_shares, pubkey_pkg) = frost::keys::generate_with_dealer(
                n.into(),
                t.into(),
                frost::keys::IdentifierList::Default,
                rand::thread_rng(),
            )?;

            let mut key_pkgs: HashMap<_, _> = key_shares
                .into_iter()
                .map(|(id, key_share)| (id, frost::keys::KeyPackage::try_from(key_share).unwrap()))
                .collect();

            let card_id = Identifier::try_from(1).unwrap();
            let cmd = command::setup(
                t,
                n,
                1,
                key_pkgs[&card_id].signing_share(),
                pubkey_pkg.verifying_key(),
            );
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            response::setup(resp)?;
            key_pkgs.remove(&card_id);

            // commit
            let cmd = command::commit();
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            let card_commitments = response::commit(resp)?;

            let mut nonces_map = HashMap::new();
            let mut commitments_map = BTreeMap::new();
            commitments_map.insert(card_id, card_commitments);

            for (id, key_pkg) in &key_pkgs {
                let (nonces, commitments) =
                    frost::round1::commit(key_pkg.signing_share(), &mut OsRng);
                nonces_map.insert(*id, nonces);
                commitments_map.insert(*id, commitments);
            }

            // commitments
            for (i, commitments) in commitments_map.values().enumerate() {
                let cmd = command::commitment((i + 1) as u8, commitments);
                let resp = card.transmit(&cmd, &mut resp_buf)?;
                response::commitment(resp)?;
            }

            // sign
            let message = vec![0xff; 16];
            let signing_package = frost::SigningPackage::new(commitments_map, &message);

            let cmd = command::sign(&message);
            let resp = card.transmit(&cmd, &mut resp_buf)?;
            let card_share = response::sign(resp)?;

            let mut share_map = BTreeMap::new();
            share_map.insert(card_id, card_share);
            for (id, key_pkg) in &key_pkgs {
                let share = frost::round2::sign(&signing_package, &nonces_map[id], key_pkg)?;
                share_map.insert(*id, share);
            }

            frost::aggregate(&signing_package, &share_map, &pubkey_pkg)?;

            Ok(())
        }
    }
}
