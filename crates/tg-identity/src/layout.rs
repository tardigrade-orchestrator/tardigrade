//! Where a node keeps its identity material -- named at **one** place.
//!
//! # Why this stands here
//!
//! These names are no implementation detail but a **contract over three parties**:
//! `tgd` writes its cluster leaf, an **operator** copies it (ADR-0043 demands that
//! expressly: "distribute peer leaves"), and `tg-agent` reads it.
//! `docs/OPERATIONS.md` names the paths verbatim, and whoever types them out relies on
//! them being right.
//!
//! Measured, every one of these names was written out at **two to four** places,
//! and the interesting ones crossed crate boundaries: `node.key.pem` in `tg-agent`
//! (three files) **and** in `tgd`, `node.leaf.pem` and `bundle.pem` in both.
//! Whoever renames one side breaks the other -- and the error shows up as "without
//! an anchor no session", that is, like an operational error and not like code
//! drift.
//!
//! `tg-identity` is the place below: `tgd` and `tg-agent` both hang on it, and the
//! material is identity material. A crate of its own for twelve names would not be
//! appropriate (ADR-0023).
//!
//! ```text
//! <data-dir>/identity/node.key.pem          the node's key (ADR-0037)
//! <data-dir>/identity/node.leaf.pem         its cluster leaf (ADR-0043) -- tgd writes it
//! <data-dir>/identity/control-plane.pem     the anchor for the counter-direction
//! <data-dir>/identity/join-token            the invitation (ADR-0037)
//! <data-dir>/identity/intermediate.pem      the agent intermediate (ADR-0006)
//! <data-dir>/identity/intermediate.key.pem  its key
//! <data-dir>/identity/bundle.pem            the trust anchor of the workload SVIDs
//! <data-dir>/identity/underlay.key          the X25519 key (ADR-0039)
//! <data-dir>/identity/ordinal               the ordinal (ADR-0039)
//! <data-dir>/peers/<id>.pem                 the other nodes' leaves
//! ```

use std::path::{Path, PathBuf};

pub const DIR: &str = "identity";

pub const NODE_KEY: &str = "node.key.pem";

pub const NODE_LEAF: &str = "node.leaf.pem";

pub const CONTROL_PLANE: &str = "control-plane.pem";

pub const JOIN_TOKEN: &str = "join-token";

pub const INTERMEDIATE: &str = "intermediate.pem";

pub const INTERMEDIATE_KEY: &str = "intermediate.key.pem";

pub const BUNDLE: &str = "bundle.pem";

pub const UNDERLAY_KEY: &str = "underlay.key";

pub const ORDINAL: &str = "ordinal";

pub const SECRETS_KEY: &str = "secrets.key";

pub const SECRETS_KEY_PREVIOUS: &str = "secrets.key.previous";

pub const SIGNING_DIR: &str = "signing";

pub const SIGNERS_DIR: &str = "signers";

pub const SHARE: &str = "share";

pub const GROUP: &str = "group";

pub const CA: &str = "ca.pem";

pub const CA_KEY: &str = "ca.key.pem";

#[must_use]
pub fn signing(data_dir: &Path) -> PathBuf {
    data_dir.join(SIGNING_DIR)
}

#[must_use]
pub fn signers(data_dir: &Path) -> PathBuf {
    data_dir.join(SIGNERS_DIR)
}

#[must_use]
pub fn dir(data_dir: &Path) -> PathBuf {
    data_dir.join(DIR)
}

#[must_use]
pub fn at(data_dir: &Path, file: &str) -> PathBuf {
    dir(data_dir).join(file)
}

#[must_use]
pub fn peers(data_dir: &Path) -> PathBuf {
    data_dir.join("peers")
}
