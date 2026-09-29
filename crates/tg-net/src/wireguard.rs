//! The underlay: kernel `WireGuard` in a full mesh.
//!
//! A uniform, encrypted, node-authenticated underlay that at the same time
//! **is** the flat L3 — the physical network then need not route the
//! container subnets.
//!
//! # The load-bearing determination
//!
//! A peer's `AllowedIPs` are **computed**, not read. They follow via
//! [`crate::ipam::ClusterNet::subnet`] from the ordinal that consensus assigned
//! at admission. In the log stands only what cannot be computed: the public key
//! and the endpoint.
//!
//! The reason is not thrift. Two sources for the same fact are two
//! opportunities to let them diverge — and the day that happens produces a
//! network that tunnels packets to the wrong place without an error appearing
//! anywhere.
//!
//! # Kernel `WireGuard`, no userspace
//!
//! The datapath stays in the kernel; this module only configures. boringtun
//! stays out: it is a userspace datapath, and precisely that is what a kernel
//! implementation avoids because of its tail latency. A fallback that gives
//! up the property for whose sake the decision was made is none.
//!
//! # The control path is netlink, not a program
//!
//! Unlike with nftables there is a licence-clean netlink way here, and it
//! lies on the same stack `rtnetlink` brings along anyway for the rest of the
//! kernel path.

use std::net::SocketAddr;

use base64::Engine as _;
use ipnet::Ipv4Net;

use crate::ipam::ClusterNet;

pub const PORT: u16 = 51820;

pub const DEVICE: &str = "tgwg0";

const KEY_LEN: usize = 32;

fn engine() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

#[derive(Debug)]
pub enum WgError {
    Key {
        node: String,
        detail: String,
    },
    Endpoint {
        node: String,
        raw: String,
    },
    Ordinal {
        node: String,
        source: crate::ipam::IpamError,
    },
    Netlink {
        step: &'static str,
        detail: String,
    },
}

impl std::fmt::Display for WgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key { node, detail } => write!(f, "key of '{node}': {detail}"),
            Self::Endpoint { node, raw } => write!(
                f,
                "endpoint of '{node}': '{}' is no address with a port",
                raw.escape_debug()
            ),
            Self::Ordinal { node, source } => write!(f, "ordinal of '{node}': {source}"),
            Self::Netlink { step, detail } => write!(f, "{step}: {detail}"),
        }
    }
}

impl std::error::Error for WgError {}

#[derive(Clone)]
pub struct Keypair {
    private: [u8; KEY_LEN],
    public: [u8; KEY_LEN],
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("public", &self.public_base64())
            .finish_non_exhaustive()
    }
}

impl Keypair {
    #[must_use]
    pub fn generate() -> Self {
        let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
        Self::from_secret(&secret)
    }

    fn from_secret(secret: &x25519_dalek::StaticSecret) -> Self {
        let public = x25519_dalek::PublicKey::from(secret);
        Self {
            private: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    pub fn from_private_base64(text: &str) -> Result<Self, WgError> {
        let bytes = decode_key("<own>", text)?;
        Ok(Self::from_secret(&x25519_dalek::StaticSecret::from(bytes)))
    }

    #[must_use]
    pub fn private_base64(&self) -> String {
        engine().encode(self.private)
    }

    #[must_use]
    pub fn public_base64(&self) -> String {
        engine().encode(self.public)
    }

    fn private_bytes(&self) -> [u8; KEY_LEN] {
        self.private
    }
}

fn decode_key(node: &str, text: &str) -> Result<[u8; KEY_LEN], WgError> {
    let bytes = engine().decode(text).map_err(|err| WgError::Key {
        node: node.to_owned(),
        detail: format!("not base64: {err}"),
    })?;

    <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| WgError::Key {
        node: node.to_owned(),
        detail: format!("{KEY_LEN} bytes expected, {} received", bytes.len()),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Member<'a> {
    pub name: &'a str,
    pub ordinal: u32,
    pub key: Option<&'a str>,
    pub endpoint: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub name: String,
    pub key: String,
    pub endpoint: SocketAddr,
    pub allowed: Ipv4Net,
}

pub fn peers(cluster: &ClusterNet, members: &[Member<'_>], me: &str) -> Result<Vec<Peer>, WgError> {
    let mut out = Vec::new();

    for member in members {
        if member.name == me {
            continue;
        }
        // Whoever has announced nothing is no peer: one knows neither their
        // key nor their endpoint.
        let (Some(key), Some(endpoint)) = (member.key, member.endpoint) else {
            continue;
        };

        // The check throws the key away — it is only about it being one. On the
        // wire goes the base64 form that also stands in the log.
        let _ = decode_key(member.name, key)?;

        let endpoint: SocketAddr = endpoint.parse().map_err(|_| WgError::Endpoint {
            node: member.name.to_owned(),
            raw: endpoint.to_owned(),
        })?;

        let subnet = cluster
            .subnet(member.ordinal)
            .map_err(|source| WgError::Ordinal {
                node: member.name.to_owned(),
                source,
            })?;

        out.push(Peer {
            name: member.name.to_owned(),
            key: key.to_owned(),
            endpoint,
            allowed: subnet.net(),
        });
    }

    out.sort_by(|left, right| left.name.cmp(&right.name));

    Ok(out)
}

// =========================================================== The kernel path

pub fn ensure_link(mtu: u16) -> Result<(), WgError> {
    crate::link::ensure_wireguard_link(DEVICE, mtu).map_err(|err| WgError::Netlink {
        step: "create WireGuard interface",
        detail: err.to_string(),
    })
}

pub fn configure(keypair: &Keypair, port: u16, peers: &[Peer]) -> Result<(), WgError> {
    use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
    use netlink_packet_generic::GenlMessage;
    use netlink_packet_wireguard::{
        WireguardAddressFamily, WireguardAllowedIp, WireguardAllowedIpAttr, WireguardAttribute,
        WireguardCmd, WireguardMessage, WireguardPeer, WireguardPeerAttribute,
    };

    let mut attributes = vec![
        WireguardAttribute::IfName(DEVICE.to_owned()),
        WireguardAttribute::PrivateKey(keypair.private_bytes()),
        WireguardAttribute::ListenPort(port),
        // The desired state, not a difference: what is missing here disappears.
        WireguardAttribute::Flags(netlink_packet_wireguard::WireguardDeviceFlags::ReplacePeers),
    ];

    let mut wire = Vec::new();
    for peer in peers {
        let key = decode_key(&peer.name, &peer.key)?;
        wire.push(WireguardPeer(vec![
            WireguardPeerAttribute::PublicKey(key),
            WireguardPeerAttribute::Endpoint(peer.endpoint),
            WireguardPeerAttribute::AllowedIps(vec![WireguardAllowedIp(vec![
                WireguardAllowedIpAttr::Family(WireguardAddressFamily::Ipv4),
                WireguardAllowedIpAttr::IpAddr(std::net::IpAddr::V4(peer.allowed.network())),
                WireguardAllowedIpAttr::Cidr(peer.allowed.prefix_len()),
            ])]),
            // Without regular signs of life a peer behind NAT falls out of the
            // table after a short time, and the other side reaches it again only
            // when it sends of its own accord.
            WireguardPeerAttribute::PersistentKeepalive(25),
        ]));
    }
    attributes.push(WireguardAttribute::Peers(wire));

    // A thread of its own, as in `link::with_netlink` and for the same reason:
    // `block_on` panics if a runtime is already active.
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| WgError::Netlink {
                        step: "tokio runtime",
                        detail: err.to_string(),
                    })?;

                runtime.block_on(async move {
                    let (connection, mut handle, _) =
                        genetlink::new_connection().map_err(|err| WgError::Netlink {
                            step: "genetlink connection",
                            detail: err.to_string(),
                        })?;
                    let pump = tokio::spawn(connection);

                    let message: GenlMessage<WireguardMessage> =
                        GenlMessage::from_payload(WireguardMessage {
                            cmd: WireguardCmd::SetDevice,
                            attributes,
                        });
                    let mut packet = NetlinkMessage::from(message);
                    packet.header.flags = NLM_F_REQUEST | NLM_F_ACK;

                    let mut answers =
                        handle
                            .request(packet)
                            .await
                            .map_err(|err| WgError::Netlink {
                                step: "send SetDevice",
                                detail: err.to_string(),
                            })?;

                    let mut failure = None;
                    while let Some(answer) = futures_util::StreamExt::next(&mut answers).await {
                        match answer {
                            Ok(packet) => {
                                if let NetlinkPayload::Error(err) = packet.payload
                                    && err.code.is_some()
                                {
                                    failure = Some(err.to_io().to_string());
                                }
                            }
                            Err(err) => failure = Some(err.to_string()),
                        }
                    }
                    pump.abort();

                    match failure {
                        None => Ok(()),
                        Some(detail) => Err(WgError::Netlink {
                            step: "SetDevice",
                            detail,
                        }),
                    }
                })
            })
            .join()
            .unwrap_or_else(|_| {
                Err(WgError::Netlink {
                    step: "genetlink thread",
                    detail: "the thread died".to_owned(),
                })
            })
    })
}
