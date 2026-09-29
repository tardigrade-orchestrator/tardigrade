//! Userspace CNI: veth and nftables, no eBPF.
//!
//! "Userspace" here means that the **control** lies in userspace, while the
//! **datapath** stays in the kernel. No eBPF, no kernel modules — but no
//! packet copying by a userspace process either, for that would cost exactly
//! the tail latency for whose sake pasta/slirp were rejected.
//!
//! Two parts manage **without a kernel** and are therefore pure, easily
//! tested logic:
//!
//! - [`ipam`] — which address a node and which a container gets,
//! - [`discovery`] — which name points at which address.
//!
//! The kernel path (netns, veth, bridge, nftables) and the resolver on the
//! socket build on top of that.
//!
//! # Why this crate knows so little
//!
//! It depends neither on `tg-store` nor on `tg-model`. That is deliberate: what
//! lies here is computing on addresses and names. The connection to the
//! projection is drawn by the caller — `tg-agent` and `tgd` —, and with that
//! this crate stays fully buildable in a test without a projection existing.

#![forbid(unsafe_code)]
// **No panic-capable call on the production path**: a panic costs its task
// and not the node -- and that is a state an operator sees only at a metric.
// `not(test)`, because the unit tests in `src` need them; the guard lies in
// `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod discovery;
pub mod ipam;
pub mod link;
pub mod nft;
pub mod probe;
pub mod resolver;
pub mod rules;
pub mod wireguard;
