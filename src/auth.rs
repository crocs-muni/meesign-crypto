use const_oid::{AssociatedOid, ObjectIdentifier};
use der::{Decode, Encode};
use p256::ecdsa::{DerSignature, SigningKey};
use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rand::rngs::OsRng;
use std::{error::Error, str::FromStr};
use x509_cert::{
    builder::{Builder, RequestBuilder},
    ext::{AsExtension, Extension},
    name::Name,
};
use yasna;

/// A bundle of private keys corresponding to `MeeSignPublicBundle`
/// stored inside of a PKCS#12 SecretBag
#[derive(der::Sequence)]
pub struct MeeSignPrivateBundle {
    pub broadcast_sign: Vec<u8>,
}

impl MeeSignPrivateBundle {
    pub const FRIENDLY_NAME: &'static str = "meesign private bundle";
}

/// A bundle of public keys corresponding to `MeeSignPrivateBundle`
/// stored inside of an X.509 certificate
#[derive(der::Sequence)]
pub struct MeeSignPublicBundle {
    pub broadcast_sign: Vec<u8>,
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
    let key = SigningKey::random(&mut OsRng);
    let key_der = key.to_pkcs8_der()?.as_bytes().to_vec();

    let bcast_key = SigningKey::random(&mut OsRng);
    let bcast_pub_key = bcast_key
        .verifying_key()
        .to_public_key_der()?
        .as_bytes()
        .to_vec();
    let bcast_key_der = bcast_key.to_pkcs8_der()?.as_bytes().to_vec();

    let subject = Name::from_str(&format!("CN={name}"))?;
    let mut builder = RequestBuilder::new(subject, &key)?;
    builder.add_extension(&MeeSignPublicBundle {
        broadcast_sign: bcast_pub_key,
    })?;
    let csr = builder.build::<DerSignature>()?;
    let csr_der = csr.to_der()?;

    let private_bundle = MeeSignPrivateBundle {
        broadcast_sign: bcast_key_der,
    }
    .to_der()?;

    let keys_der = PrivateKeys {
        tls: key_der,
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
    let tls_auth_friendly_name = p12::PKCS12Attribute::FriendlyName("meesign auth key".to_string());
    let contents = yasna::construct_der(|w| {
        w.write_sequence_of(|w| {
            p12::ContentInfo::Data(yasna::construct_der(|w| {
                w.write_sequence_of(|w| {
                    p12::SafeBag {
                        bag: p12::SafeBagKind::CertBag(p12::CertBag::X509(cert_der.to_vec())),
                        attributes: vec![tls_auth_friendly_name.clone()],
                    }
                    .write(w.next());
                    p12::SafeBag {
                        bag: p12::SafeBagKind::OtherBagKind(p12::OtherBag {
                            bag_id: yasna::models::ObjectIdentifier::from_slice(&[
                                1, 2, 840, 113549, 1, 12, 10, 1, 1, // KeyBag OID
                            ]),
                            bag_value: key_der.to_vec(),
                        }),
                        attributes: vec![tls_auth_friendly_name],
                    }
                    .write(w.next());
                    p12::SafeBag {
                        bag: p12::SafeBagKind::OtherBagKind(p12::OtherBag {
                            bag_id: yasna::models::ObjectIdentifier::from_slice(&[
                                1, 2, 840, 113549, 1, 12, 10, 1, 5, // SecretBag OID
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
