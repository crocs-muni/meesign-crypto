#[cfg(feature = "dkls23")]
mod implementation;
#[cfg(feature = "dkls23")]
pub(crate) use implementation::*;

pub const KEYGEN_ROUNDS: u16 = 4;
pub const SIGN_ROUNDS: u16 = 4;
