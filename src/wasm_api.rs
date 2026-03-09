use wasm_bindgen::prelude::*;

use crate::auth;

#[cfg(feature = "protocol")]
use crate::protocol::{self, KeygenProtocol, ThresholdProtocol};
#[cfg(feature = "protocol")]
use crate::security::{ProtocolBox, ProtocolType, SecureLayer, State as SecureLayerState};

#[cfg(feature = "gg18")]
use crate::protocol::gg18;
#[cfg(feature = "elgamal")]
use crate::protocol::elgamal;
#[cfg(feature = "frost")]
use crate::protocol::frost;
#[cfg(feature = "musig2")]
use crate::protocol::musig2;

/// Result of a protocol advance step, returned as a JS object.
#[wasm_bindgen]
pub struct WasmProtocolData {
    context: Vec<u8>,
    data: Vec<u8>,
    recipient: u32,
}

#[wasm_bindgen]
impl WasmProtocolData {
    #[wasm_bindgen(getter)]
    pub fn context(&self) -> Vec<u8> {
        self.context.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn recipient(&self) -> u32 {
        self.recipient
    }
}

/// Result of auth keygen, returned as a JS object.
#[wasm_bindgen]
pub struct WasmAuthKey {
    key: Vec<u8>,
    csr: Vec<u8>,
}

#[wasm_bindgen]
impl WasmAuthKey {
    #[wasm_bindgen(getter)]
    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn csr(&self) -> Vec<u8> {
        self.csr.clone()
    }
}

#[cfg(feature = "protocol")]
fn build_keygen_proto(proto_id: u32, with_card: bool) -> ProtocolBox {
    match (proto_id, with_card) {
        #[cfg(feature = "gg18")]
        (0, false) => ProtocolBox::Gg18Keygen(gg18::KeygenContext::new()),
        #[cfg(feature = "elgamal")]
        (1, false) => ProtocolBox::ElgamalKeygen(elgamal::KeygenContext::new()),
        #[cfg(feature = "frost")]
        (2, false) => ProtocolBox::FrostKeygen(frost::KeygenContext::new()),
        #[cfg(feature = "frost")]
        (2, true) => ProtocolBox::FrostKeygen(frost::KeygenContext::with_card()),
        #[cfg(feature = "musig2")]
        (3, false) => ProtocolBox::Musig2Keygen(musig2::KeygenContext::new()),
        #[cfg(feature = "musig2")]
        (3, true) => ProtocolBox::Musig2Keygen(musig2::KeygenContext::with_card()),
        _ => panic!("Protocol not supported"),
    }
}

#[cfg(feature = "protocol")]
fn proto_id_to_type(proto_id: u32) -> ProtocolType {
    match proto_id {
        0 => ProtocolType::Gg18,
        1 => ProtocolType::Elgamal,
        2 => ProtocolType::Frost,
        3 => ProtocolType::Musig2,
        _ => panic!("Unknown protocol ID"),
    }
}

#[cfg(feature = "protocol")]
#[wasm_bindgen]
pub fn wasm_protocol_keygen(
    proto_id: u32,
    certs: &[u8],
    pkcs12: &[u8],
    with_card: bool,
    shares: usize,
) -> Result<Vec<u8>, JsError> {
    let build_proto = |_| build_keygen_proto(proto_id, with_card);
    let sl = SecureLayer::new(
        SecureLayerState::CertSwap,
        (0..shares).map(build_proto).collect(),
        certs,
        pkcs12,
        proto_id_to_type(proto_id),
    );
    serde_json::to_vec(&sl).map_err(|e| JsError::new(&e.to_string()))
}

#[cfg(feature = "protocol")]
#[wasm_bindgen]
pub fn wasm_protocol_init(
    proto_id: u32,
    group: &[u8],
    certs: &[u8],
    pkcs12: &[u8],
    shares: usize,
) -> Result<Vec<u8>, JsError> {
    let shares_ser: Vec<Vec<u8>> =
        serde_json::from_slice(group).map_err(|e| JsError::new(&e.to_string()))?;

    let build_proto = |share_ser: &Vec<u8>| -> ProtocolBox {
        match proto_id {
            #[cfg(feature = "gg18")]
            0 => ProtocolBox::Gg18Sign(gg18::SignContext::new(share_ser)),
            #[cfg(feature = "elgamal")]
            1 => ProtocolBox::ElgamalDecrypt(elgamal::DecryptContext::new(share_ser)),
            #[cfg(feature = "frost")]
            2 => ProtocolBox::FrostSign(frost::SignContext::new(share_ser)),
            #[cfg(feature = "musig2")]
            3 => ProtocolBox::Musig2Sign(musig2::SignContext::new(share_ser)),
            _ => panic!("Protocol not supported"),
        }
    };

    let sl = SecureLayer::new(
        SecureLayerState::Init,
        shares_ser[..shares].iter().map(build_proto).collect(),
        certs,
        pkcs12,
        proto_id_to_type(proto_id),
    );
    serde_json::to_vec(&sl).map_err(|e| JsError::new(&e.to_string()))
}

#[cfg(feature = "protocol")]
#[wasm_bindgen]
pub fn wasm_protocol_advance(
    context: &[u8],
    index: usize,
    data: &[u8],
) -> Result<WasmProtocolData, JsError> {
    let mut sl: SecureLayer =
        serde_json::from_slice(context).map_err(|e| JsError::new(&e.to_string()))?;

    let (out_data, recipient) = sl
        .advance_share(index, data)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let recipient_code = match recipient {
        protocol::Recipient::Card => 1,
        protocol::Recipient::Server => 2,
    };

    let new_context = serde_json::to_vec(&sl).map_err(|e| JsError::new(&e.to_string()))?;

    Ok(WasmProtocolData {
        context: new_context,
        data: out_data,
        recipient: recipient_code,
    })
}

#[cfg(feature = "protocol")]
#[wasm_bindgen]
pub fn wasm_protocol_finish(context: &[u8]) -> Result<Vec<u8>, JsError> {
    let sl: SecureLayer =
        serde_json::from_slice(context).map_err(|e| JsError::new(&e.to_string()))?;

    let result = sl.finish_all().map_err(|e| JsError::new(&e.to_string()))?;
    serde_json::to_vec(&result).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_auth_keygen(name: &str) -> Result<WasmAuthKey, JsError> {
    let (key, csr) = auth::gen_key_with_csr(name).map_err(|e| JsError::new(&e.to_string()))?;
    Ok(WasmAuthKey { key, csr })
}

#[wasm_bindgen]
pub fn wasm_auth_cert_key_to_pkcs12(key: &[u8], cert: &[u8]) -> Result<Vec<u8>, JsError> {
    auth::cert_key_to_pkcs12(key, cert).map_err(|e| JsError::new(&e.to_string()))
}

#[cfg(feature = "elgamal")]
#[wasm_bindgen]
pub fn wasm_encrypt(message: &[u8], public_key: &[u8]) -> Result<Vec<u8>, JsError> {
    elgamal::encrypt(message, public_key).map_err(|e| JsError::new(&e.to_string()))
}
