//! The path: a bidirectional gRPC stream (ADR-0040, determination 8).
//!
//! The payload is JSON over `serde`, as on the Raft path (phase 5c) and in the
//! identity path (ADR-0037). The format is fixed by the types in [`super`]; the
//! codec is the adapter, not the protocol — and since the third occurrence it
//! lies in [`tg_wire`].
//!
//! This copy reported an unreadable foreign message as `internal`, the other two
//! as `invalid_argument`. `internal` means "something is broken at my end", and
//! an operator then looks at us — although the bytes came from the peer. It also
//! quoted the objected value **unabridged**, whereby the sender determined the
//! length of our answer. Both were the reason the PLAN names for a shared crate:
//! the three copies claimed they could not diverge. They already had.

/// The service name (ADR-0040: **not** the API from ADR-0018).
pub const SERVICE: &str = "tardigrade.node.v1.Node";

/// The one method.
pub const SESSION: &str = "/tardigrade.node.v1.Node/Session";

pub use tg_wire::JsonCodec;
