pub mod elgamal;
pub mod frost;
pub mod gg18;

#[cfg(feature = "frost")]
mod apdu;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(feature = "protocol")]
pub enum Recipient {
    Card,
    Server,
}

#[cfg(feature = "protocol")]
use crate::util::Message;

#[cfg(feature = "protocol")]
#[typetag::serde]
pub(crate) trait Protocol {
    fn advance(&mut self, data: &[u8]) -> Result<Message>;
    fn finish(self: Box<Self>) -> Result<Vec<u8>>;
}

#[cfg(feature = "protocol")]
pub(crate) trait KeygenProtocol: Protocol {
    fn new() -> Self
    where
        Self: Sized;
}

#[cfg(feature = "protocol")]
pub(crate) trait ThresholdProtocol: Protocol {
    fn new(group: &[u8]) -> Self
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;

    use prost::{bytes::Bytes, Message as _};
    use std::collections::HashMap;

    use crate::proto::{
        ClientMessage, ProtocolGroupInit, ProtocolInit, ProtocolType, ServerMessage,
    };

    pub(super) trait KeygenProtocolTest: KeygenProtocol + Sized {
        // Cannot be added in Protocol (yet) due to typetag Trait limitations
        const PROTOCOL_TYPE: ProtocolType;
        const ROUNDS: usize;
        const INDEX_OFFSET: u32 = 0;

        fn run(threshold: u32, parties: u32) -> (HashMap<u32, Vec<u8>>, HashMap<u32, Vec<u8>>) {
            assert!(threshold <= parties);

            // initialize
            let mut ctxs: HashMap<u32, Self> = (0..parties)
                .map(|i| (i as u32 + Self::INDEX_OFFSET, Self::new()))
                .collect();

            let mut messages: HashMap<u32, _> = ctxs
                .iter_mut()
                .map(|(&index, ctx)| {
                    let msg = ClientMessage::decode::<Bytes>(
                        ctx.advance(
                            &(ProtocolGroupInit {
                                protocol_type: Self::PROTOCOL_TYPE as i32,
                                index,
                                parties,
                                threshold,
                            })
                            .encode_to_vec(),
                        )
                        .unwrap()
                        .0
                        .into(),
                    )
                    .unwrap();
                    (index, msg)
                })
                .collect();

            // protocol rounds
            for _ in 0..(Self::ROUNDS - 1) {
                messages = ctxs
                    .iter_mut()
                    .map(|(&idx, ctx)| {
                        let mut unicasts = HashMap::new();
                        let mut broadcasts = HashMap::new();

                        for (&sender, msg) in &messages {
                            if sender == idx {
                                continue;
                            }
                            if let Some(broadcast) = &msg.broadcast {
                                broadcasts.insert(sender, broadcast.clone());
                            }
                            if let Some(unicast) = msg.unicasts.get(&idx) {
                                unicasts.insert(sender, unicast.clone());
                            }
                        }

                        let msg = ClientMessage::decode::<Bytes>(
                            ctx.advance(
                                &(ServerMessage {
                                    protocol_type: Self::PROTOCOL_TYPE as i32,
                                    unicasts,
                                    broadcasts,
                                })
                                .encode_to_vec(),
                            )
                            .unwrap()
                            .0
                            .into(),
                        )
                        .unwrap();
                        (idx, msg)
                    })
                    .collect();
            }

            let pks = messages
                .into_iter()
                .map(|(i, msgs)| (i, msgs.broadcast.unwrap()))
                .collect();

            let results = ctxs
                .into_iter()
                .map(|(i, ctx)| (i, Box::new(ctx).finish().unwrap()))
                .collect();

            (pks, results)
        }
    }

    pub(super) trait ThresholdProtocolTest: ThresholdProtocol + Sized {
        // Cannot be added in Protocol (yet) due to typetag Trait limitations
        const PROTOCOL_TYPE: ProtocolType;
        const ROUNDS: usize;
        const INDEX_OFFSET: u32 = 0;

        fn run(ctxs: HashMap<u32, Vec<u8>>, data: Vec<u8>) -> Vec<Vec<u8>> {
            // initialize
            let mut ctxs: HashMap<u32, _> = ctxs
                .into_iter()
                .map(|(i, ctx)| (i, Self::new(&ctx)))
                .collect();

            let mut indices: Vec<_> = ctxs.keys().cloned().collect();
            indices.sort();

            let mut messages: HashMap<u32, _> = ctxs
                .iter_mut()
                .map(|(&index, ctx)| {
                    let msg = ClientMessage::decode::<Bytes>(
                        ctx.advance(
                            &(ProtocolInit {
                                protocol_type: Self::PROTOCOL_TYPE as i32,
                                indices: indices.clone(),
                                index,
                                data: data.clone(),
                            })
                            .encode_to_vec(),
                        )
                        .unwrap()
                        .0
                        .into(),
                    )
                    .unwrap();
                    (index, msg)
                })
                .collect();

            // protocol rounds
            for _ in 0..(Self::ROUNDS - 1) {
                messages = ctxs
                    .iter_mut()
                    .map(|(&idx, ctx)| {
                        let mut unicasts = HashMap::new();
                        let mut broadcasts = HashMap::new();

                        for (&sender, msg) in &messages {
                            if sender == idx {
                                continue;
                            }
                            if let Some(broadcast) = &msg.broadcast {
                                broadcasts.insert(sender, broadcast.clone());
                            }
                            if let Some(unicast) = msg.unicasts.get(&idx) {
                                unicasts.insert(sender, unicast.clone());
                            }
                        }

                        let msg = ClientMessage::decode::<Bytes>(
                            ctx.advance(
                                &(ServerMessage {
                                    protocol_type: Self::PROTOCOL_TYPE as i32,
                                    unicasts,
                                    broadcasts,
                                })
                                .encode_to_vec(),
                            )
                            .unwrap()
                            .0
                            .into(),
                        )
                        .unwrap();
                        (idx, msg)
                    })
                    .collect();
            }

            ctxs.into_iter()
                .map(|(_, ctx)| Box::new(ctx).finish().unwrap())
                .collect()
        }
    }
}
