use crate::protocol::*;
use curve25519_dalek::{
    ristretto::{CompressedRistretto, RistrettoPoint},
    scalar::Scalar,
};
use elastic_elgamal::{group::{ElementOps, Ristretto}, PublicKey};
use aes_gcm::{aead::{Aead, AeadCore, KeyInit, Payload}, Aes128Gcm};
use rand::rngs::OsRng;

pub(crate) fn try_encode(message: &[u8]) -> Option<RistrettoPoint> {
    if message.len() > 30 {
        return None;
    }

    let mut message_buffer = [0u8; 32];
    message_buffer[0] = message.len() as u8;
    message_buffer[1..(message.len() + 1)].copy_from_slice(message);
    let mut scalar = Scalar::from_bytes_mod_order(message_buffer);

    let offset = Scalar::from(2u32.pow(8));
    scalar *= offset;
    let mut d = Scalar::ZERO;
    while d != offset {
        if let Some(p) = CompressedRistretto((scalar + d).to_bytes()).decompress() {
            return Some(p);
        }

        d += Scalar::ONE;
    }
    None
}

pub fn encrypt(msg: &[u8], pk: &[u8]) -> Result<Vec<u8>> {
    let pk: PublicKey<Ristretto> = PublicKey::from_bytes(pk).unwrap();
    let key = Aes128Gcm::generate_key(&mut OsRng);

    let encoded_key: <Ristretto as ElementOps>::Element =
        try_encode(&key).ok_or("encoding failed")?;
    let encrypted_key = serde_json::to_vec(&pk.encrypt_element(encoded_key, &mut OsRng))?;

    let cipher = Aes128Gcm::new(&key);
    let nonce = Aes128Gcm::generate_nonce(&mut OsRng);
    let ct = cipher
        .encrypt(
            &nonce,
            Payload {
                msg,
                aad: &encrypted_key,
            },
        )
        .unwrap();

    Ok(serde_json::to_vec(&(&encrypted_key, &nonce.to_vec(), &ct))?)
}
