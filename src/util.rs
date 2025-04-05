use crate::proto::{ClientMessage, ProtocolType};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone)]
pub(crate) enum Message {
    Unicast(HashMap<u32, Vec<u8>>),
    ReliableBroadcast(Vec<u8>),
    CardCommand(Vec<u8>),
}

impl Message {
    pub fn raw_unicast(data: HashMap<u32, Vec<u8>>) -> Self {
        Self::Unicast(data.into_iter().collect())
    }
    pub fn raw_reliable_broadcast(data: Vec<u8>) -> Self {
        Self::ReliableBroadcast(data)
    }
    pub fn new_card_command(data: Vec<u8>) -> Self {
        Self::CardCommand(data)
    }
    pub fn serialize_unicast<T, I>(kvs: I) -> serde_json::Result<Self>
    where
        I: IntoIterator<Item = (u32, T)>,
        T: Serialize,
    {
        let data = kvs
            .into_iter()
            .map(|(k, v)| Ok((k, serde_json::to_vec(&v)?)))
            .collect::<serde_json::Result<_>>()?;
        Ok(Self::raw_unicast(data))
    }
    pub fn serialize_reliable_broadcast<T: Serialize>(value: &T) -> serde_json::Result<Self> {
        Ok(Self::raw_reliable_broadcast(serde_json::to_vec(value)?))
    }
    pub fn encode(self, protocol_type: ProtocolType) -> ClientMessage {
        match self {
            Self::Unicast(data) => ClientMessage {
                protocol_type: protocol_type.into(),
                unicasts: data,
                broadcast: None,
            },
            Self::ReliableBroadcast(data) => ClientMessage {
                protocol_type: protocol_type.into(),
                unicasts: HashMap::new(),
                broadcast: Some(data),
            },
            Self::CardCommand(_) => unreachable!(),
        }
    }
    pub fn encode_to_vec(self, protocol_type: ProtocolType) -> Vec<u8> {
        self.encode(protocol_type).encode_to_vec()
    }
}

/// Deserializes values in a `HashMap`
pub fn deserialize_map<'de, T: Deserialize<'de>>(
    map: &'de HashMap<u32, Vec<u8>>,
) -> serde_json::Result<HashMap<u32, T>> {
    map.iter()
        .map(|(k, v)| Ok((*k, serde_json::from_slice::<T>(v.as_slice())?)))
        .collect()
}
