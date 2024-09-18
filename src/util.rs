use crate::proto::{ClientMessage, ProtocolType};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Deserializes values in a `HashMap`
pub fn deserialize_map<'de, T: Deserialize<'de>>(
    map: &'de HashMap<u32, Vec<u8>>,
) -> serde_json::Result<HashMap<u32, T>> {
    map.iter()
        .map(|(k, v)| Ok((*k, serde_json::from_slice::<T>(v.as_slice())?)))
        .collect()
}

/// Encode a broadcast message to protobuf format
pub fn encode_raw_bcast(message: Vec<u8>, protocol_type: ProtocolType) -> Vec<u8> {
    ClientMessage {
        protocol_type: protocol_type.into(),
        unicasts: HashMap::new(),
        broadcast: Some(message),
    }
    .encode_to_vec()
}

/// Serialize and encode a broadcast message to protobuf format
pub fn serialize_bcast<T: Serialize>(
    value: &T,
    protocol_type: ProtocolType,
) -> serde_json::Result<Vec<u8>> {
    let message = serde_json::to_vec(value)?;
    Ok(encode_raw_bcast(message, protocol_type))
}

/// Encode unicast messages to protobuf format
///
/// Each message is associated with an index as used by a respective protocol
pub fn encode_raw_uni(messages: HashMap<u32, Vec<u8>>, protocol_type: ProtocolType) -> Vec<u8> {
    ClientMessage {
        protocol_type: protocol_type.into(),
        unicasts: messages,
        broadcast: None,
    }
    .encode_to_vec()
}

/// Serialize and encode unicast messages to protobuf format
///
/// Each message is associated with an index as used by a respective protocol
pub fn serialize_uni<T, I>(kvs: I, protocol_type: ProtocolType) -> serde_json::Result<Vec<u8>>
where
    I: IntoIterator<Item = (u32, T)>,
    T: Serialize,
{
    let messages = kvs
        .into_iter()
        .map(|(k, v)| Ok((k, serde_json::to_vec(&v)?)))
        .collect::<serde_json::Result<_>>()?;
    Ok(encode_raw_uni(messages, protocol_type))
}
