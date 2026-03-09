use crate::protocol::{Protocol, Result};
use crate::util::Message;
use serde::{Deserialize, Serialize};

#[cfg(feature = "gg18")]
use crate::protocol::gg18;
#[cfg(feature = "elgamal")]
use crate::protocol::elgamal;
#[cfg(feature = "frost")]
use crate::protocol::frost;
#[cfg(feature = "musig2")]
use crate::protocol::musig2;

/// An enum-based wrapper around concrete protocol types, used on WASM builds
/// where `typetag` (which relies on `inventory`/`ctor`) is not available.
#[derive(Serialize, Deserialize)]
pub(crate) enum ProtocolBox {
    #[cfg(feature = "gg18")]
    Gg18Keygen(gg18::KeygenContext),
    #[cfg(feature = "gg18")]
    Gg18Sign(gg18::SignContext),
    #[cfg(feature = "elgamal")]
    ElgamalKeygen(elgamal::KeygenContext),
    #[cfg(feature = "elgamal")]
    ElgamalDecrypt(elgamal::DecryptContext),
    #[cfg(feature = "frost")]
    FrostKeygen(frost::KeygenContext),
    #[cfg(feature = "frost")]
    FrostSign(frost::SignContext),
    #[cfg(feature = "musig2")]
    Musig2Keygen(musig2::KeygenContext),
    #[cfg(feature = "musig2")]
    Musig2Sign(musig2::SignContext),
}

impl ProtocolBox {
    pub fn advance(&mut self, data: &[u8]) -> Result<Message> {
        match self {
            #[cfg(feature = "gg18")]
            Self::Gg18Keygen(ctx) => ctx.advance(data),
            #[cfg(feature = "gg18")]
            Self::Gg18Sign(ctx) => ctx.advance(data),
            #[cfg(feature = "elgamal")]
            Self::ElgamalKeygen(ctx) => ctx.advance(data),
            #[cfg(feature = "elgamal")]
            Self::ElgamalDecrypt(ctx) => ctx.advance(data),
            #[cfg(feature = "frost")]
            Self::FrostKeygen(ctx) => ctx.advance(data),
            #[cfg(feature = "frost")]
            Self::FrostSign(ctx) => ctx.advance(data),
            #[cfg(feature = "musig2")]
            Self::Musig2Keygen(ctx) => ctx.advance(data),
            #[cfg(feature = "musig2")]
            Self::Musig2Sign(ctx) => ctx.advance(data),
        }
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        match self {
            #[cfg(feature = "gg18")]
            Self::Gg18Keygen(ctx) => Box::new(ctx).finish(),
            #[cfg(feature = "gg18")]
            Self::Gg18Sign(ctx) => Box::new(ctx).finish(),
            #[cfg(feature = "elgamal")]
            Self::ElgamalKeygen(ctx) => Box::new(ctx).finish(),
            #[cfg(feature = "elgamal")]
            Self::ElgamalDecrypt(ctx) => Box::new(ctx).finish(),
            #[cfg(feature = "frost")]
            Self::FrostKeygen(ctx) => Box::new(ctx).finish(),
            #[cfg(feature = "frost")]
            Self::FrostSign(ctx) => Box::new(ctx).finish(),
            #[cfg(feature = "musig2")]
            Self::Musig2Keygen(ctx) => Box::new(ctx).finish(),
            #[cfg(feature = "musig2")]
            Self::Musig2Sign(ctx) => Box::new(ctx).finish(),
        }
    }
}
