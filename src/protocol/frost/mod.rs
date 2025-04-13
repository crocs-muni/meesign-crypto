#[cfg(feature = "frost")]
mod implementation;
#[cfg(feature = "frost")]
pub(crate) use implementation::*;

pub const KEYGEN_ROUNDS: u16 = 3 + 1;
pub const SIGN_ROUNDS: u16 = 3;
