pub mod dkls23;
pub mod elgamal;
pub mod frost;
pub mod gg18;
pub mod musig2;

#[cfg(any(feature = "frost", feature = "musig2"))]
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

    use prost::Message as _;
    use std::collections::HashMap;
    use std::sync::mpsc;
    use std::thread;

    use crate::proto::{
        ClientMessage, ProtocolGroupInit, ProtocolInit, ProtocolType, ServerMessage,
    };

    enum Cmd {
        Advance(Vec<u8>),
        Stop,
    }

    pub(super) trait KeygenProtocolTest: KeygenProtocol + Sized {
        // Cannot be added in Protocol (yet) due to typetag Trait limitations
        const PROTOCOL_TYPE: ProtocolType;
        const ROUNDS: usize;
        const INDEX_OFFSET: u32 = 0;

        fn run(threshold: u32, parties: u32) -> (HashMap<u32, Vec<u8>>, HashMap<u32, Vec<u8>>) {
            assert!(threshold <= parties);

            let mut txs = HashMap::<u32, mpsc::Sender<Cmd>>::new();
            let (done_tx, done_rx) = mpsc::channel();

            let mut join_handles = Vec::new();

            for i in 0..parties {
                let idx = i as u32 + Self::INDEX_OFFSET;

                let (tx, rx_cmd) = mpsc::channel::<Cmd>();
                txs.insert(idx, tx);

                let done_tx = done_tx.clone();

                let join_handle = thread::spawn(move || {
                    let mut ctx = Self::new();

                    loop {
                        match rx_cmd.recv().unwrap() {
                            Cmd::Advance(msg) => {
                                let msg = ctx.advance(&msg).unwrap().encode(Self::PROTOCOL_TYPE);

                                done_tx.send((idx, msg)).unwrap();
                            }

                            Cmd::Stop => {
                                let result = Box::new(ctx).finish().unwrap();
                                let msg = ClientMessage {
                                    unicasts: HashMap::new(),
                                    broadcast: Some(result),
                                    protocol_type: Self::PROTOCOL_TYPE as i32,
                                };
                                done_tx.send((idx, msg)).unwrap();
                                break;
                            }
                        }
                    }
                });
                join_handles.push(join_handle);
            }

            // initialize
            for (&idx, tx) in &txs {
                tx.send(Cmd::Advance(
                    ProtocolGroupInit {
                        protocol_type: Self::PROTOCOL_TYPE as i32,
                        index: idx,
                        parties,
                        threshold,
                    }
                    .encode_to_vec(),
                ))
                .unwrap();
            }

            let mut messages: HashMap<u32, ClientMessage> =
                (0..parties).map(|_| done_rx.recv().unwrap()).collect();

            // protocol rounds
            for _ in 0..(Self::ROUNDS - 1) {
                for (&idx, tx) in &txs {
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

                    tx.send(Cmd::Advance(
                        ServerMessage {
                            protocol_type: Self::PROTOCOL_TYPE as i32,
                            unicasts,
                            broadcasts,
                        }
                        .encode_to_vec(),
                    ))
                    .unwrap();
                }

                messages = (0..parties).map(|_| done_rx.recv().unwrap()).collect();
            }

            for (_, tx) in txs {
                tx.send(Cmd::Stop).unwrap();
            }

            let pks = messages
                .into_iter()
                .map(|(i, msgs)| (i, msgs.broadcast.unwrap()))
                .collect();

            let results = (0..parties)
                .map(|_| {
                    let (idx, msg) = done_rx.recv().unwrap();
                    (idx, msg.broadcast.unwrap())
                })
                .collect();

            for join_handle in join_handles {
                join_handle.join().unwrap();
            }

            (pks, results)
        }
    }

    pub(super) trait ThresholdProtocolTest:
        ThresholdProtocol + Sized + Send + 'static
    {
        // Cannot be added in Protocol (yet) due to typetag Trait limitations
        const PROTOCOL_TYPE: ProtocolType;
        const ROUNDS: usize;
        const INDEX_OFFSET: u32 = 0;

        fn run(ctxs: HashMap<u32, Vec<u8>>, data: Vec<u8>) -> Vec<Vec<u8>> {
            let mut txs = HashMap::<u32, mpsc::Sender<Cmd>>::new();
            let (done_tx, done_rx) = mpsc::channel();

            let mut join_handles = Vec::new();

            let mut indices: Vec<_> = ctxs.keys().cloned().collect();
            indices.sort();

            for (idx, ctx) in ctxs {
                let (tx, rx_cmd) = mpsc::channel::<Cmd>();
                txs.insert(idx, tx);

                let done_tx = done_tx.clone();
                let ctx = Self::new(&ctx);

                let join_handle = thread::spawn(move || {
                    let mut ctx = ctx;

                    loop {
                        match rx_cmd.recv().unwrap() {
                            Cmd::Advance(msg) => {
                                let msg = match ctx.advance(&msg) {
                                    Ok(msg) => msg.encode(Self::PROTOCOL_TYPE),
                                    Err(err) => {
                                        eprintln!("participant {}: {:?}", idx, err);
                                        return;
                                    }
                                };

                                done_tx.send((idx, msg)).unwrap();
                            }

                            Cmd::Stop => {
                                let result = Box::new(ctx).finish().unwrap();
                                let msg = ClientMessage {
                                    unicasts: HashMap::new(),
                                    broadcast: Some(result),
                                    protocol_type: Self::PROTOCOL_TYPE as i32,
                                };
                                done_tx.send((idx, msg)).unwrap();
                                break;
                            }
                        }
                    }
                });
                join_handles.push(join_handle);
            }

            // initialize
            for (&idx, tx) in &txs {
                tx.send(Cmd::Advance(
                    ProtocolInit {
                        protocol_type: Self::PROTOCOL_TYPE as i32,
                        index: idx,
                        indices: indices.clone(),
                        data: data.clone(),
                    }
                    .encode_to_vec(),
                ))
                .unwrap();
            }

            let mut messages: HashMap<u32, ClientMessage> =
                indices.iter().map(|_| done_rx.recv().unwrap()).collect();

            // protocol rounds
            for _ in 0..(Self::ROUNDS - 1) {
                for (&idx, tx) in &txs {
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

                    tx.send(Cmd::Advance(
                        ServerMessage {
                            protocol_type: Self::PROTOCOL_TYPE as i32,
                            unicasts,
                            broadcasts,
                        }
                        .encode_to_vec(),
                    ))
                    .unwrap();
                }

                messages = indices.iter().map(|_| done_rx.recv().unwrap()).collect();
            }

            for (_, tx) in txs {
                tx.send(Cmd::Stop).unwrap();
            }

            let results = indices
                .iter()
                .map(|_| {
                    let (_idx, msg) = done_rx.recv().unwrap();
                    msg.broadcast.unwrap()
                })
                .collect();

            for join_handle in join_handles {
                join_handle.join().unwrap();
            }

            results
        }
    }
}
