#[cfg(feature = "musig2")]
mod implementation;
#[cfg(feature = "musig2")]
mod signer;
#[cfg(feature = "musig2")]
pub(crate) use implementation::*;

pub const KEYGEN_ROUNDS: u16 = 2;
pub const SIGN_ROUNDS: u16 = 3;
