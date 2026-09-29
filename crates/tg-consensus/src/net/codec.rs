//! The Raft transport's codec — borrowed, not written.
//!
//! It lay here since phase 5c built the transport, and was the first of three
//! identical ones. Now it lies in [`tg_wire`], and this module is only the name
//! under which the consensus core knows it — so that the call sites stay where
//! they are and the provenance is nevertheless visible.
//!
//! Why JSON and not Protobuf, and what that costs: see [`tg_wire`].

pub use tg_wire::{JsonCodec, from_bytes, to_bytes};
