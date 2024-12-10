use crate::proto::SignedMessage;
use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{Decode, Encode};
use p256::ecdsa::{self, DerSignature, SigningKey, signature::Verifier as _};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, DecodePublicKey};
use rand::rngs::OsRng;
use std::{error::Error, str::FromStr};
use x509_cert::{
    builder::{Builder, RequestBuilder},
    ext::{AsExtension, Extension},
    name::Name,
    Certificate,
};
use yasna;

/// A bundle of private keys corresponding to `MeeSignPublicBundle`
/// stored inside of a PKCS#12 SecretBag
#[derive(der::Sequence)]
pub struct MeeSignPrivateBundle {
    pub broadcast_sign: Vec<u8>,
    pub unicast_sign: Vec<u8>,
    pub unicast_decrypt: Vec<u8>,
}

impl MeeSignPrivateBundle {
    pub const FRIENDLY_NAME: &'static str = "meesign private bundle";
}

/// A bundle of public keys corresponding to `MeeSignPrivateBundle`
/// stored inside of an X.509 certificate
#[derive(der::Sequence)]
pub struct MeeSignPublicBundle {
    pub broadcast_sign: Vec<u8>,
    pub unicast_sign: Vec<u8>,
    pub unicast_encrypt: Vec<u8>,
}

/// An OID from a testing namespace as documented here:
/// https://web.archive.org/web/20100430054707/http://www.imc.org/ietf-pkix/pkix-oid.asn
impl AssociatedOid for MeeSignPublicBundle {
    const OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.13.9939");
}

impl AsExtension for MeeSignPublicBundle {
    fn critical(&self, _subject: &Name, _extensions: &[Extension]) -> bool {
        false
    }
}

#[derive(der::Sequence)]
struct PrivateKeys {
    tls: Vec<u8>,
    bundle: Vec<u8>,
}

pub fn gen_key_with_csr(name: &str) -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    let tls_key = SigningKey::random(&mut OsRng);
    let tls_key_der = tls_key.to_pkcs8_der()?.as_bytes().to_vec();

    let bcast_key = SigningKey::random(&mut OsRng);
    let bcast_pub_key = bcast_key
        .verifying_key()
        .to_public_key_der()?
        .as_bytes()
        .to_vec();
    let bcast_key_der = bcast_key.to_pkcs8_der()?.as_bytes().to_vec();

    let uni_sign_key = SigningKey::random(&mut OsRng);
    let uni_sign_pub_key = uni_sign_key
        .verifying_key()
        .to_public_key_der()?
        .as_bytes()
        .to_vec();
    let uni_sign_key_der = uni_sign_key.to_pkcs8_der()?.as_bytes().to_vec();

    let (uni_dec_key, uni_enc_key) = ecies::utils::generate_keypair();
    let (uni_dec_key, uni_enc_key) = (uni_dec_key.serialize(), uni_enc_key.serialize());

    let subject = Name::from_str(&format!("CN={name}"))?;
    let mut builder = RequestBuilder::new(subject, &tls_key)?;
    builder.add_extension(&MeeSignPublicBundle {
        broadcast_sign: bcast_pub_key,
        unicast_sign: uni_sign_pub_key,
        unicast_encrypt: uni_enc_key.into(),
    })?;
    let csr = builder.build::<DerSignature>()?;
    let csr_der = csr.to_der()?;

    let private_bundle = MeeSignPrivateBundle {
        broadcast_sign: bcast_key_der,
        unicast_sign: uni_sign_key_der,
        unicast_decrypt: uni_dec_key.into(),
    }
    .to_der()?;

    let keys_der = PrivateKeys {
        tls: tls_key_der,
        bundle: private_bundle,
    }
    .to_der()?;

    Ok((keys_der, csr_der))
}

pub fn cert_key_to_pkcs12(keys_der: &[u8], cert_der: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let PrivateKeys {
        tls: key_der,
        bundle,
    } = PrivateKeys::from_der(keys_der)?;
    let password = b"";

    // The p12 library does not directly support the PKCS#12 features we need,
    // so we have to construct some structures ourselves.
    // In particular, we are using the KeyBag and SecretBag types described in
    // RFC7292 Section 4.2.1 and Section 4.2.5 respectively.
    // p12 also provides no direct way to use these Bags in the PFX, so we have to
    // construct the container types (ContentInfo, SafeContents) as well.

    let tls_auth_friendly_name = p12::PKCS12Attribute::FriendlyName("meesign auth key".to_string());
    let contents = yasna::construct_der(|w| {
        w.write_sequence_of(|w| {
            p12::ContentInfo::Data(yasna::construct_der(|w| {
                // RFC7292 Section 4.2: The SafeContents is made up of SafeBags.
                w.write_sequence_of(|w| {
                    p12::SafeBag {
                        bag: p12::SafeBagKind::CertBag(p12::CertBag::X509(cert_der.to_vec())),
                        attributes: vec![tls_auth_friendly_name.clone()],
                    }
                    .write(w.next());
                    p12::SafeBag {
                        bag: p12::SafeBagKind::OtherBagKind(p12::OtherBag {
                            bag_id: yasna::models::ObjectIdentifier::from_slice(&[
                                // RFC7292 Appendix D, Bag types: KeyBag OID
                                1, 2, 840, 113549, 1, 12, 10, 1, 1,
                            ]),
                            bag_value: key_der.to_vec(),
                        }),
                        attributes: vec![tls_auth_friendly_name],
                    }
                    .write(w.next());
                    p12::SafeBag {
                        bag: p12::SafeBagKind::OtherBagKind(p12::OtherBag {
                            bag_id: yasna::models::ObjectIdentifier::from_slice(&[
                                // RFC7292 Appendix D, Bag types: SecretBag OID
                                1, 2, 840, 113549, 1, 12, 10, 1, 5,
                            ]),
                            bag_value: bundle,
                        }),
                        attributes: vec![p12::PKCS12Attribute::FriendlyName(
                            MeeSignPrivateBundle::FRIENDLY_NAME.to_string(),
                        )],
                    }
                    .write(w.next());
                });
            }))
            .write(w.next());
        })
    });
    let mac_data = p12::MacData::new(&contents, password);
    let pfx = p12::PFX {
        version: 3,
        auth_safe: p12::ContentInfo::Data(contents),
        mac_data: Some(mac_data),
    }
    .to_der();
    Ok(pfx)
}

/// Extracts a DER-encoded MeeSignPublicBundle from a DER-encoded X.509 certificate
pub fn extract_public_bundle_der(cert_der: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(Certificate::from_der(cert_der)?
        .tbs_certificate
        .extensions
        .ok_or("certificate does not contain public bundle")?
        .into_iter()
        .find(|ext| ext.extn_id == MeeSignPublicBundle::OID)
        .ok_or("certificate does not contain public bundle")?
        .extn_value
        .into_bytes())
}

/// Verifies a signed broadcast and extracts the message
pub fn verify_broadcast(msg: &[u8], cert_der: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    use crate::proto::Message as _;
    let public_bundle = extract_public_bundle_der(cert_der)?;
    let public_bundle = MeeSignPublicBundle::from_der(&public_bundle)?;
    let msg = SignedMessage::decode(msg)?;
    let signature = ecdsa::Signature::from_slice(&msg.signature)?;
    let key = ecdsa::VerifyingKey::from_public_key_der(&public_bundle.broadcast_sign)?;
    key.verify(&msg.message, &signature)
        .map_err(|_| "broadcast signature mismatch")?;
    Ok(msg.message)
}
