use crate::auth::{MeeSignPrivateBundle, MeeSignPublicBundle};
use crate::proto::{self, ClientMessage, ServerMessage, SignedMessage};
use crate::protocol::{Protocol, Recipient, Result};
use const_oid::AssociatedOid;
use der::{self, Decode as _};
use p256::ecdsa;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::pkcs8::{DecodePrivateKey as _, DecodePublicKey as _};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use x509_cert::Certificate;

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

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub enum State {
    CertSwap,
    Init,
    Running,
}

#[derive(Deserialize, Serialize)]
pub struct SecureLayer {
    shares: Vec<(State, Box<dyn Protocol>)>,
    public_bundles: HashMap<u32, Vec<u8>>, // MeeSignPublicBundles in DER format for each share index
    private_bundle: Vec<u8>,               // MeeSignPrivateBundle in DER format
    protocol_type: ProtocolType,
}

impl SecureLayer {
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
                let bundle = Certificate::from_der(&cert)?
                    .tbs_certificate
                    .extensions
                    .ok_or("certificate does not contain public bundle")?
                    .into_iter()
                    .find(|ext| ext.extn_id == MeeSignPublicBundle::OID)
                    .ok_or("certificate does not contain public bundle")?
                    .extn_value
                    .into_bytes();
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
            shares: shares
                .into_iter()
                .map(|share| (initial_state, share))
                .collect(),
            public_bundles,
            private_bundle,
            protocol_type,
        }
    }

    pub fn advance_share(&mut self, index: usize, data: &[u8]) -> Result<(Vec<u8>, Recipient)> {
        let (state, protocol) = &mut self.shares[index];

        let sign_pub_keys = self
            .public_bundles
            .iter()
            .map(|(&party, bundle)| {
                let bundle = MeeSignPublicBundle::from_der(bundle)?;
                let key = ecdsa::VerifyingKey::from_public_key_der(&bundle.broadcast_sign)?;
                Ok((party, key))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        let private_bundle = MeeSignPrivateBundle::from_der(&self.private_bundle)?;
        let sign_key = ecdsa::SigningKey::from_pkcs8_der(&private_bundle.broadcast_sign)?;

        let (msg, recipient);
        (*state, msg, recipient) = match state {
            State::CertSwap => (State::Init, Vec::new(), Recipient::Server),
            State::Init => {
                let (data, recipient) = protocol.advance(&data)?;

                let mut data = ClientMessage::decode(data.as_ref()).unwrap();
                if let Some(msg) = &mut data.broadcast {
                    let signature: ecdsa::Signature = sign_key.sign(msg);
                    *msg = SignedMessage {
                        message: msg.to_vec(),
                        signature: signature.to_vec(),
                    }
                    .encode_to_vec();
                }
                let data = data.encode_to_vec();

                (State::Running, data, recipient)
            }
            State::Running => {
                let mut data = ServerMessage::decode(data)?;
                for (sender, broadcast) in &mut data.broadcasts {
                    let sm = SignedMessage::decode(broadcast.as_slice())?;
                    let signature = ecdsa::Signature::from_slice(&sm.signature)?;
                    sign_pub_keys[sender]
                        .verify(&sm.message, &signature)
                        .map_err(|_| "broadcast signature mismatch")?;
                    *broadcast = sm.message;
                }
                let data = data.encode_to_vec();

                let (data, recipient) = protocol.advance(&data)?;

                let mut data = ClientMessage::decode(data.as_ref()).unwrap();
                if let Some(msg) = &mut data.broadcast {
                    let signature: ecdsa::Signature = sign_key.sign(msg);
                    *msg = SignedMessage {
                        message: msg.to_vec(),
                        signature: signature.to_vec(),
                    }
                    .encode_to_vec();
                }
                let data = data.encode_to_vec();

                (State::Running, data, recipient)
            }
        };
        Ok((msg, recipient))
    }

    pub fn finish_all(self) -> Result<Vec<Vec<u8>>> {
        self.shares
            .into_iter()
            .map(|(_, share)| share.finish())
            .collect()
    }
}

pub fn unpack_broadcast(msg: &[u8]) -> Vec<u8> {
    let bcast = SignedMessage::decode(msg).unwrap();
    bcast.message
}
