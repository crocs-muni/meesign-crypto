use crate::auth::{extract_public_bundle_der, MeeSignPrivateBundle, MeeSignPublicBundle};
use crate::proto::{self, ClientMessage, ProtocolGroupInit, ProtocolInit, ServerMessage, SignedMessage};
use crate::protocol::{Protocol, Recipient, Result};
use der::{self, Decode as _};
use p256::ecdsa;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Copy, Clone, Deserialize, Serialize)]
pub enum ProtocolType {
    Gg18,
    Elgamal,
    Frost,
}

impl From<ProtocolType> for proto::ProtocolType {
    fn from(pt: ProtocolType) -> proto::ProtocolType {
        match pt {
            ProtocolType::Gg18 => proto::ProtocolType::Gg18,
            ProtocolType::Elgamal => proto::ProtocolType::Elgamal,
            ProtocolType::Frost => proto::ProtocolType::Frost,
        }
    }
}

impl From<ProtocolType> for i32 {
    fn from(pt: ProtocolType) -> i32 {
        proto::ProtocolType::from(pt).into()
    }
}

fn verify_message(signed_message: &[u8], key: &ecdsa::VerifyingKey) -> Result<Vec<u8>> {
    let signed_message = SignedMessage::decode(signed_message)?;
    let signature = ecdsa::Signature::from_slice(&signed_message.signature)?;
    key.verify(&signed_message.message, &signature)?;
    Ok(signed_message.message)
}

fn secure_message(
    mut message: ClientMessage,
    private_bundle: &MeeSignPrivateBundle,
    public_bundles: &HashMap<u32, MeeSignPublicBundle>,
) -> Result<ClientMessage> {
    if let Some(msg) = &mut message.broadcast {
        let pkey = ecdsa::SigningKey::from_pkcs8_der(&private_bundle.broadcast_sign)?;
        let signature: ecdsa::Signature = pkey.sign(msg);
        *msg = SignedMessage {
            message: msg.to_vec(),
            signature: signature.to_vec(),
        }
        .encode_to_vec();
    }
    if message.unicasts.len() > 0 {
        let sign_key = ecdsa::SigningKey::from_pkcs8_der(&private_bundle.unicast_sign)?;
        for (recipient, unicast) in &mut message.unicasts {
            let enc_key = &public_bundles[recipient].unicast_encrypt;
            let encrypted = ecies::encrypt(enc_key, unicast).map_err(|_| "failed to encrypt unicast")?;
            let signature: ecdsa::Signature = sign_key.sign(&encrypted);
            *unicast = SignedMessage {
                message: encrypted,
                signature: signature.to_vec(),
            }
            .encode_to_vec();
        }
    }
    Ok(message)
}

fn finalize_round(
    data: Vec<u8>,
    recipient: Recipient,
    private_bundle: &MeeSignPrivateBundle,
    public_bundles: &HashMap<u32, MeeSignPublicBundle>,
) -> Result<(State, Vec<u8>, Recipient)> {
    if let Recipient::Card = recipient {
        return Ok((State::CardResponse, data, recipient));
    }

    let data = ClientMessage::decode(data.as_ref()).unwrap();
    let data = secure_message(data, private_bundle, public_bundles)?;
    let state = if data.broadcast.is_some() {
        assert_eq!(data.unicasts.len(), 0);
        State::BroadcastExchange
    } else {
        State::Running
    };
    let data = data.encode_to_vec();

    Ok((state, data, recipient))
}

/// The `SecureLayer` wraps each `Protocol` in a state machine
#[derive(Deserialize, Serialize, Debug, Clone)]
pub enum State {
    /// An offset round to allow the server to pass the certificates here
    CertSwap,
    /// Initializes the protocols
    Init,
    /// Computes one protocol round
    Running,
    /// Handles the response of a smart card
    CardResponse,
    /// Reached after a broadcast is sent. Implements echo-broadcast round 2. Does not compute a protocol round
    BroadcastExchange,
    /// Finished echo-broadcast and continues with another protocol round
    BroadcastCheck(HashMap<u32, Vec<u8>>),
}

/// A wrapper around the raw threshold protocols providing necessary security guarantees,
/// namely reliable, authenticated broadcasts
#[derive(Deserialize, Serialize)]
pub struct SecureLayer {
    /// Share indices of all participants
    participant_indices: Vec<u32>,
    /// Share indices corresponding to the `shares` field
    share_indices: Vec<u32>,
    /// The respective computation states for each share of this participant
    shares: Vec<(State, Box<dyn Protocol>)>,
    /// MeeSignPublicBundles in DER format for each share index
    public_bundles: HashMap<u32, Vec<u8>>,
    /// MeeSignPrivateBundle in DER format
    private_bundle: Vec<u8>,
    /// The underlying threshold protocol
    protocol_type: ProtocolType,
}

impl SecureLayer {
    /// Secures the communication of protocols in `shares`
    pub fn new(
        initial_state: State,
        shares: Vec<Box<dyn Protocol>>,
        certs: &[u8],
        pfx_der: &[u8],
        protocol_type: ProtocolType,
    ) -> Self {
        let public_bundles = ServerMessage::decode(certs)
            .unwrap()
            .broadcasts
            .into_iter()
            .map(|(party, cert)| {
                let bundle = extract_public_bundle_der(&cert)?;
                Ok((party, bundle))
            })
            .collect::<Result<HashMap<_, _>>>()
            .unwrap();

        let private_bundle = p12::PFX::parse(pfx_der)
            .unwrap()
            .bags("")
            .unwrap()
            .into_iter()
            .find(|bag| bag.friendly_name().unwrap() == MeeSignPrivateBundle::FRIENDLY_NAME)
            .unwrap();

        let p12::SafeBagKind::OtherBagKind(p12::OtherBag {
            bag_value: private_bundle,
            ..
        }) = private_bundle.bag
        else {
            panic!("unexpected PKCS#12 SafeBag");
        };

        Self {
            participant_indices: Vec::new(),  // NOTE: initialized in round 0
            share_indices: vec![0; shares.len()], // NOTE: initialized in round 0
            shares: shares
                .into_iter()
                .map(|share| (initial_state.clone(), share))
                .collect(),
            public_bundles,
            private_bundle,
            protocol_type,
        }
    }

    /// Advances the computation of one share
    pub fn advance_share(&mut self, share_idx: usize, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let (state, protocol) = &mut self.shares[share_idx];

        let public_bundles = self
            .public_bundles
            .iter()
            .map(|(&party, bundle)| {
                let bundle = MeeSignPublicBundle::from_der(bundle)?;
                Ok((party, bundle))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let private_bundle = MeeSignPrivateBundle::from_der(&self.private_bundle)?;

        let (msg, recipient);
        (*state, msg, recipient) = match state {
            State::CertSwap => {
                let ack = ClientMessage {
                    broadcast: Some(Vec::from("certificates received")),
                    unicasts: HashMap::new(),
                    protocol_type: self.protocol_type.into(),
                }
                .encode_to_vec();
                (State::Init, ack, Recipient::Server)
            },
            State::Init => {
                if let Ok(pgi) = ProtocolGroupInit::decode(data) {
                    let index_offset = match self.protocol_type {
                        ProtocolType::Frost => 1,
                        _ => 0,
                    };
                    self.participant_indices = (index_offset..pgi.parties+index_offset).collect();
                    self.share_indices[share_idx] = pgi.index;
                } else if let Ok(pi) = ProtocolInit::decode(data) {
                    self.participant_indices = pi.indices;
                    self.share_indices[share_idx] = pi.index;
                } else {
                    return Err("invalid data in round 0".into());
                }

                let (data, recipient) = protocol.advance(&data)?;

                finalize_round(data, recipient, &private_bundle, &public_bundles)?
            },
            State::BroadcastExchange => {
                let data_dec = ServerMessage::decode(data)?;
                let mut original_msgs = HashMap::new();
                for (sender, message) in &data_dec.broadcasts {
                    let key = &public_bundles[sender].broadcast_sign;
                    let key = ecdsa::VerifyingKey::from_public_key_der(key)?;
                    let message = verify_message(message, &key)?;
                    original_msgs.insert(*sender, message);
                }
                assert_eq!(data_dec.unicasts.len(), 0);

                let bcast_sign_key = ecdsa::SigningKey::from_pkcs8_der(&private_bundle.broadcast_sign)?;
                let signature: ecdsa::Signature = bcast_sign_key.sign(data);
                let data = ClientMessage{
                    unicasts: HashMap::new(),
                    broadcast: Some(SignedMessage {
                        message: data.to_vec(),
                        signature: signature.to_vec(),
                    }.encode_to_vec()),
                    protocol_type: self.protocol_type.into(),
                }
                .encode_to_vec();

                (State::BroadcastCheck(original_msgs), data, Recipient::Server)
            },
            State::BroadcastCheck(original_msgs) => {
                let data = ServerMessage::decode(data)?;
                assert!(!data.broadcasts.contains_key(&self.share_indices[share_idx]));
                assert_eq!(data.broadcasts.len(), self.participant_indices.len() - 1);

                let sign_pub_keys: HashMap<_, _> = public_bundles
                    .iter()
                    .map(|(party, bundle)| {
                        let key = ecdsa::VerifyingKey::from_public_key_der(&bundle.broadcast_sign)?;
                        Ok((party, key))
                    })
                    .collect::<Result<_>>()?;

                for (relayer, relayed_msgs) in &data.broadcasts {
                    let relayed_msgs = verify_message(relayed_msgs, &sign_pub_keys[relayer])?;
                    let relayed_msgs = ServerMessage::decode(relayed_msgs.as_slice())?;
                    assert_eq!(relayed_msgs.broadcasts.len(), self.participant_indices.len() - 1);

                    for (sender, relayed_msg) in &relayed_msgs.broadcasts {
                        let relayed_msg = verify_message(relayed_msg, &sign_pub_keys[sender])?;

                        if sender == relayer || *sender == self.share_indices[share_idx] {
                            continue;
                        }
                        if !original_msgs.get(sender).is_some_and(|msg| msg == &relayed_msg) {
                            return Err("broadcast compromised".into());
                        }
                    }
                }
                assert_eq!(data.unicasts.len(), 0);

                let data = ServerMessage {
                    unicasts: HashMap::new(),
                    broadcasts: original_msgs.clone(),
                    protocol_type: self.protocol_type.into(),
                }
                .encode_to_vec();

                let (data, recipient) = protocol.advance(&data)?;

                finalize_round(data, recipient, &private_bundle, &public_bundles)?
            },
            State::CardResponse => {
                let (data, recipient) = protocol.advance(&data)?;

                finalize_round(data, recipient, &private_bundle, &public_bundles)?
            },
            State::Running => {
                let mut data = ServerMessage::decode(data)?;
                for (sender, unicast) in &mut data.unicasts {
                    let verifying_key = &public_bundles[sender].unicast_sign;
                    let verifying_key = ecdsa::VerifyingKey::from_public_key_der(verifying_key)?;
                    *unicast = verify_message(unicast, &verifying_key)?;

                    *unicast = ecies::decrypt(&private_bundle.unicast_decrypt, unicast).map_err(|_| "unicast compromised")?;
                }
                for (sender, broadcast) in &mut data.broadcasts {
                    let verifying_key = &public_bundles[sender].broadcast_sign;
                    let verifying_key = ecdsa::VerifyingKey::from_public_key_der(verifying_key)?;
                    *broadcast = verify_message(broadcast, &verifying_key)?;
                }
                let data = data.encode_to_vec();

                let (data, recipient) = protocol.advance(&data)?;

                finalize_round(data, recipient, &private_bundle, &public_bundles)?
            }
        };
        Ok((msg, recipient))
    }

    /// Finishes the computation of all shares
    pub fn finish_all(self) -> Result<Vec<Vec<u8>>> {
        self.shares
            .into_iter()
            .map(|(_, share)| share.finish())
            .collect()
    }
}
