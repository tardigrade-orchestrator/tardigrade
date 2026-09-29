//! A sealed value, as it lies in the log (ADR-0004, ADR-0095).
//!
//! # Why the data lie here and the procedure does not
//!
//! The command set carries a sealed value (`SetSecret`), and the command set
//! has lain in this crate since ADR-0134 — so that a client formulating a
//! command does not link the consensus core. Were the type still in
//! `tg-identity`, `tg-model` would hang on it, and that would be a circle:
//! `tg-identity` knows `tg-model` (ADR-0065).
//!
//! What does **not** lie here is the procedure. Sealing, opening and the length
//! of the authentication tag stay in `tg_identity::secrets`, where `ring` is;
//! this crate links no crypto library and shall link none.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}
