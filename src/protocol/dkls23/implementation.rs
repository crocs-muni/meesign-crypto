use crate::proto::{ProtocolGroupInit, ProtocolInit, ProtocolType, ServerMessage};
use crate::protocol::*;
use crate::util::{deserialize_map, Message};

use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use dkls23::protocols::dkg::{
    self, BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, KeepInitMulPhase3to4,
    KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment, SessionData,
    TransmitInitZeroSharePhase2to4, UniqueKeepDerivationPhase2to3,
};
use dkls23::protocols::signing::{
    Broadcast3to4, KeepPhase1to2, KeepPhase2to3, SignData, UniqueKeep1to2, UniqueKeep2to3,
};
use dkls23::protocols::{Parameters, Party, PartyIndex, PublicKeyPackage};
use dkls23_secp256k1 as dkls23;
use k256_dkls23::{Scalar, Secp256k1 as Curve};
use sha2::{Digest, Sha256};

/// Performs the analogue of a list zip over hashmaps, requiring the keys of both to be precisely equal
fn zip_map<X, Y>(xs: HashMap<u32, X>, mut ys: HashMap<u32, Y>) -> Result<HashMap<u32, (X, Y)>> {
    let xys = xs
        .into_iter()
        .map(|(i, x)| {
            let y = ys
                .remove(&i)
                .ok_or("zip_maps: ys is missing a key present in xs")?;
            Ok((i, (x, y)))
        })
        .collect::<Result<_>>()?;
    if !ys.is_empty() {
        return Err("zip_maps: xs is missing a key present in ys".into());
    }
    Ok(xys)
}

/// Performs the analogue of a list unzip over hashmaps
fn unzip_map<X, Y>(xys: HashMap<u32, (X, Y)>) -> (HashMap<u32, X>, HashMap<u32, Y>) {
    xys.into_iter()
        .map(|(k, (v1, v2))| ((k, v1), (k, v2)))
        .unzip()
}

/// Turns our party's value and a unicast map of parties -> T into a vector of T indexed by the party index
fn vec_from_uni_map<T>(party_index: u32, value: T, mut map: HashMap<u32, T>) -> Result<Vec<T>> {
    map.insert(party_index, value);
    let n = map.len();
    let mut vec = Vec::with_capacity(n);
    for i in 0..n {
        let party_index = (i + 1) as u32;
        let value = map.remove(&party_index).ok_or(format!(
            "vec_from_map: map should contain party index {}",
            party_index
        ))?;
        vec.push(value);
    }
    Ok(vec)
}

/// Turns a vec of T indexed by party index into a our party's value and a unicast map of parties -> T
fn uni_map_from_vec<T>(vec: Vec<T>, party_index: u32) -> Result<(T, HashMap<u32, T>)> {
    let mut map: HashMap<_, _> = vec
        .into_iter()
        .enumerate()
        .map(|(i, x)| ((i + 1) as u32, x))
        .collect();
    let value = map.remove(&party_index).ok_or(format!(
        "map_from_vec: vec should contain party index {}",
        party_index
    ))?;
    Ok((value, map))
}

#[derive(Serialize, Deserialize)]
pub(crate) struct KeygenContext {
    round: KeygenRound,
}

#[derive(Serialize, Deserialize)]
enum KeygenRound {
    R0,
    R1(SessionData, Scalar),
    R2(
        SessionData,
        Scalar,
        ProofCommitment<Curve>,
        BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>,
        UniqueKeepDerivationPhase2to3,
        BroadcastDerivationPhase2to4,
    ),
    R3(
        SessionData,
        Scalar,
        HashMap<u32, [u8; 32]>,
        ProofCommitment<Curve>,
        BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>,
        Vec<TransmitInitZeroSharePhase2to4>,
        BTreeMap<PartyIndex, KeepInitMulPhase3to4<Curve>>,
        BroadcastDerivationPhase3to4,
        BTreeMap<PartyIndex, BroadcastDerivationPhase2to4>,
    ),
    Done(Party<Curve>, PublicKeyPackage<Curve>),
}

impl KeygenContext {
    fn init(&mut self, data: &[u8]) -> Result<Message> {
        let msg = ProtocolGroupInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Dkls23 as i32 {
            return Err("wrong protocol type".into());
        }

        let parameters = Parameters {
            threshold: msg.threshold as u8,
            share_count: msg.parties as u8,
        };
        let party_index = PartyIndex::new(msg.index as u8)?;
        let session_data = SessionData {
            parameters,
            party_index,
            session_id: Vec::new(), // TODO: create an actual session id?
        };

        let poly = dkg::phase1::<Curve>(&session_data);
        let (poly_point, poly) = uni_map_from_vec(poly, msg.index)?;

        let unicasts = poly;

        let msg = Message::serialize_unicast(unicasts)?;
        self.round = KeygenRound::R1(session_data, poly_point);
        Ok(msg)
    }

    fn update(&mut self, data: &[u8]) -> Result<Message> {
        let (c, data) = match &self.round {
            KeygenRound::R0 => return Err("protocol not initialized".into()),
            KeygenRound::R1(session_data, poly_point) => {
                let data = ServerMessage::decode(data)?.unicasts;
                let party_index = session_data.party_index.as_u8() as u32;
                let poly_points =
                    vec_from_uni_map(party_index, *poly_point, deserialize_map(&data)?)?;

                let (
                    poly_point,
                    proof_commitment,
                    zero_2_3_keep,
                    zero_2_4_uni,
                    bip_2_3_keep,
                    bip_2_4_bcast,
                ) = dkg::phase2(session_data, &poly_points);

                let zero_2_4_uni: HashMap<_, _> = zero_2_4_uni
                    .into_iter()
                    .map(|msg| (msg.parties.receiver.as_u8() as u32, msg))
                    .collect();

                let unicasts = zero_2_4_uni;
                let broadcast = &(proof_commitment.commitment, bip_2_4_bcast.clone());

                (
                    KeygenRound::R2(
                        session_data.clone(),
                        poly_point,
                        proof_commitment,
                        zero_2_3_keep,
                        bip_2_3_keep,
                        bip_2_4_bcast,
                    ),
                    Message::serialize_combined(unicasts, broadcast)?,
                )
            }
            KeygenRound::R2(
                session_data,
                poly_point,
                proof_commitment_our,
                zero_2_3_keep,
                bip_2_3_keep,
                bip_2_4_our,
            ) => {
                let data = ServerMessage::decode(data)?;
                let party_index = session_data.party_index.as_u8() as u32;
                let zero_2_4_rec: Vec<_> = deserialize_map(&data.unicasts)?.into_values().collect();
                let (proof_commitments_rec, mut bip_2_4_rec) =
                    unzip_map(deserialize_map(&data.broadcasts)?);
                bip_2_4_rec.insert(party_index, bip_2_4_our.clone());
                let bip_2_4_rec = bip_2_4_rec
                    .into_iter()
                    .map(|(i, v)| (PartyIndex::new(i as u8).unwrap(), v))
                    .collect();

                let (zero_3_4_keep, zero_3_4_uni, mul_3_4_keep, mul_3_4_uni, bip_3_4_bcast) =
                    dkg::phase3(session_data, zero_2_3_keep, bip_2_3_keep);

                let zero_3_4_uni: HashMap<_, _> = zero_3_4_uni
                    .into_iter()
                    .map(|msg| (msg.parties.receiver.as_u8() as u32, msg))
                    .collect();
                let mul_3_4_uni: HashMap<_, _> = mul_3_4_uni
                    .into_iter()
                    .map(|msg| (msg.parties.receiver.as_u8() as u32, msg))
                    .collect();

                let unicasts = zip_map(zero_3_4_uni, mul_3_4_uni)?;
                let broadcast = &(bip_3_4_bcast.clone(), proof_commitment_our.proof.clone());

                (
                    KeygenRound::R3(
                        session_data.clone(),
                        *poly_point,
                        proof_commitments_rec,
                        proof_commitment_our.clone(),
                        zero_3_4_keep,
                        zero_2_4_rec,
                        mul_3_4_keep,
                        bip_3_4_bcast,
                        bip_2_4_rec,
                    ),
                    Message::serialize_combined(unicasts, broadcast)?,
                )
            }
            KeygenRound::R3(
                session_data,
                poly_point,
                proof_commitments_rec,
                proof_commitment_our,
                zero_3_4_keep,
                zero_2_4_rec,
                mul_3_4_keep,
                bip_3_4_our,
                bip_2_4_rec,
            ) => {
                let data = ServerMessage::decode(data)?;
                let party_index = session_data.party_index.as_u8() as u32;
                let (zero_3_4_rec, mul_3_4_rec) = unzip_map(deserialize_map(&data.unicasts)?);
                let zero_3_4_rec: Vec<_> = zero_3_4_rec.into_values().collect();
                let mul_3_4_rec: Vec<_> = mul_3_4_rec.into_values().collect();

                let (mut bip_3_4_rec, proof_commitment_proofs_rec) =
                    unzip_map(deserialize_map(&data.broadcasts)?);
                bip_3_4_rec.insert(party_index, bip_3_4_our.clone());
                let bip_3_4_rec = bip_3_4_rec
                    .into_iter()
                    .map(|(i, v)| (PartyIndex::new(i as u8).unwrap(), v))
                    .collect();
                let mut proof_commitments_rec: Vec<_> =
                    zip_map(proof_commitments_rec.clone(), proof_commitment_proofs_rec)?
                        .into_iter()
                        .map(|(i, (commitment, proof))| {
                            let index = PartyIndex::new(i as u8).unwrap();
                            ProofCommitment {
                                index,
                                proof,
                                commitment,
                            }
                        })
                        .collect();
                proof_commitments_rec.push(proof_commitment_our.clone());

                let (party, pk) = dkg::phase4(
                    session_data,
                    poly_point,
                    &proof_commitments_rec,
                    zero_3_4_keep,
                    zero_2_4_rec,
                    &zero_3_4_rec,
                    mul_3_4_keep,
                    &mul_3_4_rec,
                    bip_2_4_rec,
                    &bip_3_4_rec,
                    |_| String::from(""),
                )
                .map_err(|abort| abort.description())?;

                let msg = Message::serialize_broadcast(&pk)?;
                (KeygenRound::Done(party, pk), msg)
            }
            KeygenRound::Done(_, _) => return Err("protocol already finished".into()),
        };
        self.round = c;

        Ok(data)
    }
}

#[typetag::serde(name = "dkls23_keygen")]
impl Protocol for KeygenContext {
    fn advance(&mut self, data: &[u8]) -> Result<Message> {
        match self.round {
            KeygenRound::R0 => self.init(data),
            _ => self.update(data),
        }
    }

    fn finish(self: Box<Self>) -> Result<Vec<u8>> {
        match self.round {
            KeygenRound::Done(party, pubkey_package) => {
                Ok(serde_json::to_vec(&(party, pubkey_package))?)
            }
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

#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
struct Signature {
    r: [u8; 32],
    s: [u8; 32],
    recovery_id: u8,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SignContext {
    party: Party<Curve>,
    round: SignRound,
}

#[derive(Serialize, Deserialize)]
enum SignRound {
    R0,
    R1(
        SignData,
        UniqueKeep1to2<Curve>,
        BTreeMap<PartyIndex, KeepPhase1to2<Curve>>,
    ),
    R2(
        SignData,
        UniqueKeep2to3<Curve>,
        BTreeMap<PartyIndex, KeepPhase2to3<Curve>>,
    ),
    R3(SignData, String, Broadcast3to4<Curve>),
    Done(Signature),
}

impl SignContext {
    fn init(&mut self, data: &[u8]) -> Result<Message> {
        let msg = ProtocolInit::decode(data)?;
        if msg.protocol_type != ProtocolType::Dkls23 as i32 {
            return Err("wrong protocol type".into());
        }

        assert_eq!(
            msg.index,
            self.party.party_index.as_u8() as u32,
            "dkls23 sign: party index from protocol init should be the same as the stored one",
        );

        // TODO: Generate unique sign IDs?
        let sign_id = Vec::new();
        let counterparties = msg
            .indices
            .iter()
            .filter(|i| **i != msg.index)
            .map(|i| {
                PartyIndex::new(*i as u8)
                    .map_err(|_| "dkls23 sign: invalid counterparty index".into())
            })
            .collect::<Result<Vec<_>>>()?;

        let message_hash = Sha256::digest(&msg.data).into();

        let sign_data = SignData {
            sign_id,
            counterparties,
            message_hash,
        };

        let (bcast_1_2_keep, uni_1_2_keep, uni_1_2) = self
            .party
            .sign_phase1(&sign_data)
            .map_err(|abort| abort.description())?;

        let uni_1_2 = uni_1_2
            .into_iter()
            .map(|msg| (msg.parties.receiver.as_u8() as u32, msg));

        let unicast = uni_1_2;

        let msg = Message::serialize_unicast(unicast)?;
        self.round = SignRound::R1(sign_data, bcast_1_2_keep, uni_1_2_keep);
        Ok(msg)
    }

    fn update(&mut self, data: &[u8]) -> Result<Message> {
        match &self.round {
            SignRound::R0 => Err("protocol not initialized".into()),
            SignRound::R1(sign_data, bcast_1_2_keep, uni_1_2_keep) => {
                let data = ServerMessage::decode(data)?;
                let uni_1_2_rec: Vec<_> = deserialize_map(&data.unicasts)?.into_values().collect();

                let (bcast_2_3_keep, uni_2_3_keep, uni_2_3) = self
                    .party
                    .sign_phase2(sign_data, bcast_1_2_keep, uni_1_2_keep, &uni_1_2_rec)
                    .map_err(|abort| abort.description())?;

                let uni_2_3 = uni_2_3
                    .into_iter()
                    .map(|msg| (msg.parties.receiver.as_u8() as u32, msg));

                let unicast = uni_2_3;

                let msg = Message::serialize_unicast(unicast)?;
                self.round = SignRound::R2(sign_data.clone(), bcast_2_3_keep, uni_2_3_keep);
                Ok(msg)
            }
            SignRound::R2(sign_data, bcast_2_3_keep, uni_2_3_keep) => {
                let data = ServerMessage::decode(data)?;
                let uni_2_3_rec: Vec<_> = deserialize_map(&data.unicasts)?.into_values().collect();

                let (sig_r, bcast_3_4) = self
                    .party
                    .sign_phase3(sign_data, bcast_2_3_keep, uni_2_3_keep, &uni_2_3_rec)
                    .map_err(|abort| abort.description())?;

                let broadcast = &bcast_3_4;

                let msg = Message::serialize_broadcast(broadcast)?;
                self.round = SignRound::R3(sign_data.clone(), sig_r, bcast_3_4.clone());
                Ok(msg)
            }
            SignRound::R3(sign_data, sig_r, bcast_3_4_our) => {
                let data = ServerMessage::decode(data)?;
                let mut bcast_3_4_rec: Vec<_> =
                    deserialize_map(&data.broadcasts)?.into_values().collect();
                bcast_3_4_rec.push(bcast_3_4_our.clone());

                let x_coord = sig_r;
                // TODO: Decide on the "normalize" parameter
                let normalize = true;

                let (sig_s, recovery_id) = self
                    .party
                    .sign_phase4(sign_data, x_coord, &bcast_3_4_rec, normalize)
                    .map_err(|abort| abort.description())?;

                let mut r = [0u8; 32];
                let mut s = [0u8; 32];
                hex::decode_to_slice(sig_r, &mut r)
                    .map_err(|_| "dkls23 sign: library produced invalid signature (ECDSA 'r')")?;
                hex::decode_to_slice(&sig_s, &mut s)
                    .map_err(|_| "dkls23 sign: library produced invalid signature (ECDSA 's')")?;

                let signature = Signature { r, s, recovery_id };

                let msg = Message::serialize_broadcast(&signature)?;
                self.round = SignRound::Done(signature);
                Ok(msg)
            }
            SignRound::Done(_) => Err("protocol already finished".into()),
        }
    }
}

#[typetag::serde(name = "dkls23_sign")]
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
        let (party, _pubkey_package): (Party<Curve>, PublicKeyPackage<Curve>) =
            serde_json::from_slice(group).expect("could not deserialize group context");
        Self {
            party,
            round: SignRound::R0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::tests::{KeygenProtocolTest, ThresholdProtocolTest};
    use rand::rngs::OsRng;
    use rand::seq::IteratorRandom;

    use dkls23::protocols::signing::verify_ecdsa_signature;

    impl KeygenProtocolTest for KeygenContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Dkls23;
        const ROUNDS: usize = 4;
        const INDEX_OFFSET: u32 = 1;
    }

    impl ThresholdProtocolTest for SignContext {
        const PROTOCOL_TYPE: ProtocolType = ProtocolType::Dkls23;
        const ROUNDS: usize = 4;
        const INDEX_OFFSET: u32 = 1;
    }

    #[test]
    fn keygen() {
        for threshold in 2..6 {
            for parties in threshold..6 {
                let (_pks, results) =
                    <KeygenContext as KeygenProtocolTest>::run(threshold as u32, parties as u32);

                let party = results.values().next().unwrap();
                let (party, _pubkey_package): (Party<Curve>, PublicKeyPackage<Curve>) =
                    serde_json::from_slice(&party).unwrap();
                let expected_pk = party.pk;
                let expected_chain_code = party.derivation_data.chain_code;
                for party in results.values() {
                    let (party, _pubkey_package): (Party<Curve>, PublicKeyPackage<Curve>) =
                        serde_json::from_slice(&party).unwrap();
                    assert_eq!(expected_pk, party.pk);
                    assert_eq!(expected_chain_code, party.derivation_data.chain_code);
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

                let pk = pks.values().next().unwrap();
                let pk: PublicKeyPackage<Curve> = serde_json::from_slice(&pk).unwrap();

                let ctxs = ctxs
                    .into_iter()
                    .choose_multiple(&mut OsRng, threshold)
                    .into_iter()
                    .collect();

                let results = <SignContext as ThresholdProtocolTest>::run(ctxs, msg.to_vec());

                let signature: Signature = serde_json::from_slice(&results[0]).unwrap();

                assert_ne!(signature.r, [0u8; 32]);
                assert_ne!(signature.s, [0u8; 32]);

                for result in results {
                    assert_eq!(signature, serde_json::from_slice(&result).unwrap());
                }

                let msg_hash: [u8; 32] = Sha256::digest(&msg).into();

                let r_hex = hex::encode(signature.r);
                let s_hex = hex::encode(signature.s);

                assert!(verify_ecdsa_signature::<Curve>(
                    &msg_hash,
                    pk.verifying_key(),
                    &r_hex,
                    &s_hex,
                ));
            }
        }
    }
}
