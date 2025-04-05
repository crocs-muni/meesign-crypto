#[cfg(feature = "elgamal")]
mod implementation;
#[cfg(feature = "elgamal")]
pub(crate) use implementation::*;

pub const KEYGEN_ROUNDS: u16 = 4 + 2;
pub const DECRYPT_ROUNDS: u16 = 2;

#[cfg(feature = "elgamal-encrypt")]
mod encrypt;
#[cfg(feature = "elgamal-encrypt")]
pub use encrypt::*;
