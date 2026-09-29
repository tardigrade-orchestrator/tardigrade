//! The underlay into the kernel — the connection that had been missing since 9d
//! (ADR-0039).
//!
//! `tg-net::wireguard` was built and checked on real packets with
//! `cargo xtask net`, but **no process called it**: `configure` had no caller,
//! and the agent wrote `peers.json` without anybody reading it. That is the same
//! pattern as with `tg-identity` and `tg-proxy` before the wiring.
//!
//! # What the reconciliation lives off
//!
//! From the slice (ADR-0040), and only from it: the **peers** together with
//! their ordinals and the **network parameters**. The `AllowedIPs` expressly do
//! not stand there — they are **computed** from the ordinal (ADR-0039). Two
//! sources for the same fact would be two opportunities to drift apart.
//!
//! # Why the interface gets no address — and why 9d gave one
//!
//! The kernel-path test from 9d (`underlay_path.rs`) calls `ensure_overlay` and
//! gives the interface an address. That is **right** there: it connects out of
//! the namespace to the neighbour's overlay address, that is, **locally
//! generated** traffic, and that needs a source address. What is checked there
//! is the mechanism — does the tunnel carry packets —, in a namespace pair
//! without a bridge.
//!
//! A real node has a different topology: the traffic arises in the container,
//! goes over `veth` onto `tg0` and is **forwarded**. An address on `tgwg0` out
//! of its own /24 would collide with the bridge that already carries this
//! network.
//!
//! Over `tgwg0` runs **forwarded** container traffic. An address would make the
//! node itself reachable over the tunnel and would pull the management ports in
//! — exactly the question ADR-0043 left open after unmasking the opposite claim
//! (that the underlay already carries the management traffic) as **false**. What
//! the kernel needs are routes: `AllowedIPs` says what *may* go through the
//! tunnel, a route says what *takes* it.

use std::path::Path;

use tg_net::ipam::{ClusterNet, Mtu};
use tg_net::wireguard::{self, Member};
use tg_store::session::{ClusterNetwork, UnderlayPeer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Applied {
    pub(crate) peers: usize,
    pub(crate) members: usize,
}

pub(crate) fn reconcile(data_dir: &Path, node: &str) -> Result<Applied, String> {
    let paths = crate::session::Paths::new(data_dir);

    let cluster = read_network(&paths.cluster_network())?;
    let members: Vec<UnderlayPeer> = read_peers(&paths.peers())?;

    // The own key is **read, not generated**: creating it here would mean
    // configuring an underlay the cluster does not know (the minting path
    // announces it, ADR-0042).
    let keypair = crate::join::underlay_keypair(data_dir)
        .ok_or_else(|| "no underlay key -- nothing to connect".to_owned())?;

    let borrowed: Vec<Member<'_>> = members
        .iter()
        .map(|peer| Member {
            name: &peer.node,
            ordinal: peer.ordinal,
            key: Some(&peer.key),
            endpoint: Some(&peer.endpoint),
        })
        .collect();

    let peers = wireguard::peers(&cluster, &borrowed, node).map_err(|err| err.to_string())?;

    let mtu = Mtu::for_overlay(1500).map_err(|err| err.to_string())?;
    wireguard::ensure_link(mtu.get()).map_err(|err| err.to_string())?;
    wireguard::configure(&keypair, wireguard::PORT, &peers).map_err(|err| err.to_string())?;

    // The routes come **after** the configuration: a route onto an interface
    // without peers would lead packets into a device that discards them.
    let routes: Vec<ipnet::Ipv4Net> = peers.iter().map(|peer| peer.allowed).collect();
    tg_net::link::ensure_routes(wireguard::DEVICE, &routes).map_err(|err| err.to_string())?;

    Ok(Applied {
        peers: peers.len(),
        members: members.len(),
    })
}

pub(crate) fn read_network(path: &Path) -> Result<ClusterNet, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("{}: {err} -- no network parameters yet", path.display()))?;
    let network: ClusterNetwork =
        serde_json::from_str(&raw).map_err(|err| format!("{}: {err}", path.display()))?;

    let cidr = network
        .cidr
        .parse()
        .map_err(|_| format!("'{}' is no network", network.cidr.escape_debug()))?;

    ClusterNet::new(cidr, network.node_prefix).map_err(|err| err.to_string())
}

fn read_peers(path: &Path) -> Result<Vec<UnderlayPeer>, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|err| format!("{}: {err} -- no peer list yet", path.display()))?;

    serde_json::from_str(&raw).map_err(|err| format!("{}: {err}", path.display()))
}
