#[cfg(feature = "gg18")]
mod implementation;
#[cfg(feature = "gg18")]
pub(crate) use implementation::*;

pub const KEYGEN_ROUNDS: u16 = 6 + 4;
pub const SIGN_ROUNDS: u16 = 10;
