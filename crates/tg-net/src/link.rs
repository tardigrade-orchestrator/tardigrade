//! The kernel path: bridge, veth, addresses, routes.
//!
//! All via `rtnetlink` — pure Rust, MIT, no FFI. That is the pleasant part of
//! this piece of the kernel path: unlike with nftables there is a
//! licence-clean netlink way here, and it is also the better one.
//!
//! # Why the surface is synchronous
//!
//! `rtnetlink` is asynchronous, this module is not. The reason is the
//! namespace: netlink work **in** a namespace has to run on a thread that sits
//! there (`tg_syscall::netns::run_in`), and threading a `tokio` executor across
//! such a thread boundary gains nothing — the calls here are rare, short and
//! not in the hot path.
//!
//! The own runtime runs on a **thread of its own** in the process, and that is
//! no convenience: `Runtime::block_on` panics if a runtime is already active. A
//! caller from `#[tokio::main]` — that is, the agent — would take the process
//! down with it. Writing that as a condition into the doc header would have
//! been the worse solution: a seam one must uphold is one that somebody
//! eventually does not uphold.
//!
//! # What this module changes on the host
//!
//! Two things, and both are to be written down because they reach beyond the
//! orchestrator:
//!
//! 1. A bridge named `tg0` together with an address.
//! 2. `net.ipv4.ip_forward = 1`. Without it no container reaches anything. It
//!    is **never reset**: the setting is host-wide, and switching it off
//!    afterwards would possibly take the routing from a foreign service. What
//!    one cannot safely undo, one does not undo.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use futures_util::TryStreamExt as _;
use rtnetlink::{Handle, LinkBridge, LinkUnspec, LinkVeth, RouteMessageBuilder, new_connection};

use crate::ipam::{CONTAINER_LINK, LinkName, NodeSubnet};

const IP_FORWARD: &str = "/proc/sys/net/ipv4/ip_forward";

#[derive(Debug)]
pub enum LinkError {
    Netlink {
        step: &'static str,
        detail: String,
    },
    NoSuchLink {
        name: String,
    },
    Namespace {
        detail: String,
    },
    Host {
        what: &'static str,
        source: std::io::Error,
    },
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Netlink { step, detail } => write!(f, "{step}: {detail}"),
            Self::NoSuchLink { name } => write!(f, "interface '{name}' does not exist"),
            Self::Namespace { detail } => write!(f, "{detail}"),
            Self::Host { what, source } => write!(f, "{what}: {source}"),
        }
    }
}

impl std::error::Error for LinkError {}

fn netlink(step: &'static str) -> impl Fn(rtnetlink::Error) -> LinkError {
    move |err| LinkError::Netlink {
        step,
        detail: err.to_string(),
    }
}

fn already_exists(err: &rtnetlink::Error) -> bool {
    matches!(
        err,
        rtnetlink::Error::NetlinkError(message)
            if message.to_io().kind() == std::io::ErrorKind::AlreadyExists
    )
}

fn with_netlink<T, F>(body: F) -> Result<T, LinkError>
where
    T: Send,
    F: AsyncFnOnce(Handle) -> Result<T, LinkError> + Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|source| LinkError::Host {
                        what: "tokio runtime",
                        source,
                    })?;

                runtime.block_on(async {
                    let (connection, handle, _) =
                        new_connection().map_err(|source| LinkError::Host {
                            what: "netlink connection",
                            source,
                        })?;
                    let pump = tokio::spawn(connection);
                    let result = body(handle).await;
                    pump.abort();
                    result
                })
            })
            .join()
            .unwrap_or_else(|_| {
                Err(LinkError::Host {
                    what: "netlink thread",
                    source: std::io::Error::other("the thread died"),
                })
            })
    })
}

async fn index_of(handle: &Handle, name: &str) -> Result<Option<u32>, LinkError> {
    let mut found = handle.link().get().match_name(name.to_owned()).execute();

    match found.try_next().await {
        Ok(Some(message)) => Ok(Some(message.header.index)),
        // An unknown name is no error but the answer "no".
        Ok(None) | Err(_) => Ok(None),
    }
}

pub fn ensure_bridge(subnet: &NodeSubnet, mtu: u16) -> Result<u32, LinkError> {
    // Without forwarding no container reaches anything. See the module header:
    // it is never reset.
    std::fs::write(IP_FORWARD, "1\n").map_err(|source| LinkError::Host {
        what: "net.ipv4.ip_forward",
        source,
    })?;

    let bridge = crate::ipam::BRIDGE;
    let gateway = subnet.gateway();
    let prefix = subnet.net().prefix_len();

    with_netlink(async |handle| {
        let index = if let Some(index) = index_of(&handle, bridge).await? {
            index
        } else {
            handle
                .link()
                .add(LinkBridge::new(bridge).build())
                .execute()
                .await
                .map_err(netlink("create bridge"))?;
            index_of(&handle, bridge)
                .await?
                .ok_or_else(|| LinkError::NoSuchLink {
                    name: bridge.to_owned(),
                })?
        };

        handle
            .link()
            .set(
                LinkUnspec::new_with_index(index)
                    .mtu(u32::from(mtu))
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(netlink("bring bridge up"))?;

        // An address that is already present is no error — `EEXIST` means here:
        // the desired state is already in place.
        match handle
            .address()
            .add(index, IpAddr::V4(gateway), prefix)
            .execute()
            .await
        {
            Ok(()) => Ok(index),
            Err(err) if already_exists(&err) => Ok(index),
            Err(err) => Err(netlink("set bridge address")(err)),
        }
    })
}

fn create_pair(
    host_name: &str,
    peer_name: &str,
    ns: &std::os::fd::OwnedFd,
    mtu: u16,
) -> Result<(), LinkError> {
    let bridge = crate::ipam::BRIDGE;
    let host_name = host_name.to_owned();
    let peer_name = peer_name.to_owned();
    let ns_fd = std::os::fd::AsRawFd::as_raw_fd(ns);

    with_netlink(async |handle| {
        handle
            .link()
            .add(LinkVeth::new(&host_name, &peer_name).build())
            .execute()
            .await
            .map_err(netlink("create veth pair"))?;

        let bridge_index =
            index_of(&handle, bridge)
                .await?
                .ok_or_else(|| LinkError::NoSuchLink {
                    name: bridge.to_owned(),
                })?;
        let host_index =
            index_of(&handle, &host_name)
                .await?
                .ok_or_else(|| LinkError::NoSuchLink {
                    name: host_name.clone(),
                })?;
        let peer_index =
            index_of(&handle, &peer_name)
                .await?
                .ok_or_else(|| LinkError::NoSuchLink {
                    name: peer_name.clone(),
                })?;

        handle
            .link()
            .set(
                LinkUnspec::new_with_index(host_index)
                    .controller(bridge_index)
                    .mtu(u32::from(mtu))
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(netlink("host side into the bridge"))?;

        handle
            .link()
            .set(
                LinkUnspec::new_with_index(peer_index)
                    .setns_by_fd(ns_fd)
                    .build(),
            )
            .execute()
            .await
            .map_err(netlink("far side into the namespace"))
    })
}

fn configure_inside(
    peer_name: &str,
    address: Ipv4Addr,
    prefix: u8,
    gateway: Ipv4Addr,
    mtu: u16,
) -> Result<(), LinkError> {
    with_netlink(async |handle| {
        let peer_index =
            index_of(&handle, peer_name)
                .await?
                .ok_or_else(|| LinkError::NoSuchLink {
                    name: peer_name.to_owned(),
                })?;

        handle
            .link()
            .set(
                LinkUnspec::new_with_index(peer_index)
                    .name(CONTAINER_LINK)
                    .mtu(u32::from(mtu))
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(netlink("set up interface in the namespace"))?;

        // Without `lo` everything a process does over 127.0.0.1 fails — with
        // the sidecar that is the whole way to its workload.
        if let Some(loopback) = index_of(&handle, "lo").await? {
            handle
                .link()
                .set(LinkUnspec::new_with_index(loopback).up().build())
                .execute()
                .await
                .map_err(netlink("bring lo up"))?;
        }

        handle
            .address()
            .add(peer_index, IpAddr::V4(address), prefix)
            .execute()
            .await
            .map_err(netlink("set address"))?;

        handle
            .route()
            .add(
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .gateway(gateway)
                    .output_interface(peer_index)
                    .build(),
            )
            .execute()
            .await
            .map_err(netlink("set default route"))
    })
}

pub fn attach(
    netns: &str,
    host: &LinkName,
    address: Ipv4Addr,
    subnet: &NodeSubnet,
    mtu: u16,
) -> Result<(), LinkError> {
    let host_name = host.as_str().to_owned();
    let peer_name = format!("{host_name}p");

    let already = {
        let host_name = host_name.clone();
        with_netlink(async |handle| index_of(&handle, &host_name).await)?
    };
    if already.is_some() {
        return Ok(());
    }

    let ns = tg_syscall::netns::open(netns).map_err(|err| LinkError::Namespace {
        detail: err.to_string(),
    })?;

    create_pair(&host_name, &peer_name, &ns, mtu)?;

    let prefix = subnet.net().prefix_len();
    let gateway = subnet.gateway();

    tg_syscall::netns::run_in(netns, move || {
        configure_inside(&peer_name, address, prefix, gateway, mtu)
    })
    .map_err(|err| LinkError::Namespace {
        detail: err.to_string(),
    })?
}

pub fn ensure_instance(
    netns: &str,
    address: Ipv4Addr,
    subnet: &NodeSubnet,
    mtu: u16,
) -> Result<PathBuf, LinkError> {
    let namespace = |detail: String| LinkError::Namespace { detail };

    let path = match tg_syscall::netns::create(netns) {
        Ok(path) => path,
        // Already there: the same instance, one more pass.
        Err(tg_syscall::netns::NetNsError::Exists { .. }) => {
            tg_syscall::netns::path(netns).map_err(|err| namespace(err.to_string()))?
        }
        Err(err) => return Err(namespace(err.to_string())),
    };

    attach(
        netns,
        &crate::ipam::host_link(address),
        address,
        subnet,
        mtu,
    )?;

    Ok(path)
}

pub fn release_instance(netns: &str, address: Option<Ipv4Addr>) -> Result<(), LinkError> {
    if let Some(address) = address {
        detach(&crate::ipam::host_link(address))?;
    }

    match tg_syscall::netns::delete(netns) {
        // Already gone is done: clearing away shall be repeatable.
        Ok(()) | Err(tg_syscall::netns::NetNsError::Missing { .. }) => Ok(()),
        Err(err) => Err(LinkError::Namespace {
            detail: err.to_string(),
        }),
    }
}

pub fn detach(host: &LinkName) -> Result<(), LinkError> {
    let host_name = host.as_str().to_owned();

    with_netlink(async |handle| {
        let Some(index) = index_of(&handle, &host_name).await? else {
            return Ok(());
        };

        handle
            .link()
            .del(index)
            .execute()
            .await
            .map_err(netlink("delete veth pair"))
    })
}

pub fn ensure_loopback(netns: &str) -> Result<(), LinkError> {
    tg_syscall::netns::run_in(netns, move || {
        with_netlink(async |handle| {
            let Some(loopback) = index_of(&handle, "lo").await? else {
                return Err(LinkError::NoSuchLink {
                    name: "lo".to_owned(),
                });
            };

            handle
                .link()
                .set(LinkUnspec::new_with_index(loopback).up().build())
                .execute()
                .await
                .map_err(netlink("bring lo up"))
        })
    })
    .map_err(|err| LinkError::Namespace {
        detail: err.to_string(),
    })?
}

pub fn ensure_wireguard_link(name: &str, mtu: u16) -> Result<(), LinkError> {
    use rtnetlink::packet_route::link::InfoKind;

    let name = name.to_owned();

    with_netlink(async |handle| {
        let index = if let Some(index) = index_of(&handle, &name).await? {
            index
        } else {
            handle
                .link()
                .add(
                    rtnetlink::LinkMessageBuilder::<rtnetlink::LinkUnspec>::new_with_info_kind(
                        InfoKind::Wireguard,
                    )
                    .name(name.clone())
                    .build(),
                )
                .execute()
                .await
                .map_err(netlink("create WireGuard interface"))?;
            index_of(&handle, &name)
                .await?
                .ok_or_else(|| LinkError::NoSuchLink { name: name.clone() })?
        };

        handle
            .link()
            .set(
                LinkUnspec::new_with_index(index)
                    .mtu(u32::from(mtu))
                    .up()
                    .build(),
            )
            .execute()
            .await
            .map_err(netlink("bring WireGuard interface up"))
    })
}

pub fn ensure_overlay(
    device: &str,
    address: Ipv4Addr,
    prefix: u8,
    routes: &[ipnet::Ipv4Net],
) -> Result<(), LinkError> {
    let device = device.to_owned();
    let routes = routes.to_vec();

    with_netlink(async |handle| {
        let index = index_of(&handle, &device)
            .await?
            .ok_or_else(|| LinkError::NoSuchLink {
                name: device.clone(),
            })?;

        match handle
            .address()
            .add(index, IpAddr::V4(address), prefix)
            .execute()
            .await
        {
            Ok(()) => {}
            Err(err) if already_exists(&err) => {}
            Err(err) => return Err(netlink("set overlay address")(err)),
        }

        add_routes(&handle, index, &routes).await
    })
}

pub fn ensure_routes(device: &str, routes: &[ipnet::Ipv4Net]) -> Result<(), LinkError> {
    let device = device.to_owned();
    let routes = routes.to_vec();

    with_netlink(async |handle| {
        let index = index_of(&handle, &device)
            .await?
            .ok_or_else(|| LinkError::NoSuchLink {
                name: device.clone(),
            })?;

        add_routes(&handle, index, &routes).await
    })
}

async fn add_routes(
    handle: &rtnetlink::Handle,
    index: u32,
    routes: &[ipnet::Ipv4Net],
) -> Result<(), LinkError> {
    for route in routes {
        match handle
            .route()
            .add(
                RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(route.network(), route.prefix_len())
                    .output_interface(index)
                    .build(),
            )
            .execute()
            .await
        {
            Ok(()) => {}
            Err(err) if already_exists(&err) => {}
            Err(err) => return Err(netlink("set route")(err)),
        }
    }

    Ok(())
}

pub fn exists(name: &str) -> Result<bool, LinkError> {
    let name = name.to_owned();
    with_netlink(async |handle| Ok(index_of(&handle, &name).await?.is_some()))
}
