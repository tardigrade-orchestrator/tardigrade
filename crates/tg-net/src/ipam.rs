//! Deterministic address assignment.
//!
//! A deterministic IP assignment from node subnets, derived from topology and
//! desired state, needs an answer for how. This module answers that in **two
//! layers with different responsibilities** — the division between what is
//! cluster-wide and what is node-local is the actual content of the design.
//!
//! # A node's subnet is cluster-wide
//!
//! Two nodes with the same subnet are a cluster error, not a local one. So the
//! assignment belongs in consensus: a node gets the **ordinal** at its
//! admission and keeps it as long as it exists. From it the subnet follows by
//! pure computation.
//!
//! What is decisive is what the ordinal is **not**: a position in a list. Were
//! it that, the failure of one node would shift the subnets of all the following
//! ones — and every route, every nftables rule and every `WireGuard`
//! `AllowedIP` in the cluster would afterwards point into the void, without an
//! error appearing anywhere. That is why it is an input here.
//!
//! # A container's address is node-local
//!
//! It by contrast must **not** depend on the control plane: an agent that after
//! a restart first had to ask which address its running container has would be
//! exactly the kind of coupling that makes workload availability depend on
//! reaching the control plane. So it assigns it itself, writes it beside its
//! desired-state cache and finds it again — [`Leases::restore`].
//!
//! The ledger is **checked** on re-reading, not believed: an address outside the
//! subnet or assigned twice is a finding, not a state one carries on with.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

pub const BRIDGE: &str = "tg0";

pub const CONTAINER_LINK: &str = "eth0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpamError {
    NodePrefixTooWide {
        cluster: u8,
        node: u8,
    },
    NodeSubnetTooSmall {
        node: u8,
    },
    ClusterFull {
        ordinal: u32,
        capacity: u32,
    },
    SubnetFull {
        subnet: Ipv4Net,
        capacity: u32,
    },
    LeaseOutsideSubnet {
        workload: String,
        instance: u32,
        address: Ipv4Addr,
        subnet: Ipv4Net,
    },
    DuplicateLease {
        address: Ipv4Addr,
        workload: String,
        instance: u32,
    },
    MtuTooSmall {
        underlay: u16,
        minimum: u16,
    },
}

impl fmt::Display for IpamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodePrefixTooWide { cluster, node } => write!(
                f,
                "node prefix /{node} is not narrower than the cluster CIDR /{cluster}"
            ),
            Self::NodeSubnetTooSmall { node } => write!(
                f,
                "node prefix /{node} carries no container after deducting \
                 network, broadcast and gateway"
            ),
            Self::ClusterFull { ordinal, capacity } => write!(
                f,
                "ordinal {ordinal} lies outside the cluster CIDR — it carries \
                 {capacity} node subnets"
            ),
            Self::SubnetFull { subnet, capacity } => {
                write!(f, "{subnet} is full — {capacity} addresses are assigned")
            }
            Self::LeaseOutsideSubnet {
                workload,
                instance,
                address,
                subnet,
            } => write!(
                f,
                "'{workload}' instance {instance} carries {address}, which does \
                 not lie in {subnet} — has the cluster CIDR changed?"
            ),
            Self::DuplicateLease {
                address,
                workload,
                instance,
            } => write!(
                f,
                "{address} is assigned twice, last to '{workload}' instance \
                 {instance}"
            ),
            Self::MtuTooSmall { underlay, minimum } => write!(
                f,
                "underlay MTU {underlay} does not carry the overlay MTU; at \
                 least {minimum} needed"
            ),
        }
    }
}

impl std::error::Error for IpamError {}

impl From<tg_model::network::PlanError> for IpamError {
    fn from(err: tg_model::network::PlanError) -> Self {
        use tg_model::network::PlanError as P;
        match err {
            P::NodePrefixTooWide { cluster, node } => Self::NodePrefixTooWide { cluster, node },
            P::NodeSubnetTooSmall { node } => Self::NodeSubnetTooSmall { node },
            P::ClusterFull { ordinal, capacity } => Self::ClusterFull { ordinal, capacity },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterNet {
    plan: tg_model::network::Plan,
}

impl ClusterNet {
    pub fn new(net: Ipv4Net, node_prefix: u8) -> Result<Self, IpamError> {
        Ok(Self {
            plan: tg_model::network::Plan::new(net, node_prefix)?,
        })
    }

    #[must_use]
    pub fn net(&self) -> Ipv4Net {
        self.plan.net()
    }

    #[must_use]
    pub fn capacity(&self) -> u32 {
        self.plan.capacity()
    }

    pub fn subnet(&self, ordinal: u32) -> Result<NodeSubnet, IpamError> {
        Ok(NodeSubnet {
            net: self.plan.subnet_of(ordinal)?,
            ordinal,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSubnet {
    net: Ipv4Net,
    ordinal: u32,
}

impl NodeSubnet {
    #[must_use]
    pub fn net(&self) -> Ipv4Net {
        self.net
    }

    #[must_use]
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    #[must_use]
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.net.network()) + 1)
    }

    #[must_use]
    pub fn capacity(&self) -> u32 {
        let size = 1u32 << (32 - self.net.prefix_len());
        // Network, broadcast and gateway are deducted.
        size - 3
    }

    #[must_use]
    pub fn holds(&self, address: Ipv4Addr) -> bool {
        self.net.contains(&address)
            && address != self.net.network()
            && address != self.net.broadcast()
            && address != self.gateway()
    }

    fn assignable(&self) -> impl Iterator<Item = Ipv4Addr> + '_ {
        let first = u32::from(self.gateway()) + 1;
        let last = u32::from(self.net.broadcast()) - 1;
        (first..=last).map(Ipv4Addr::from)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub workload: String,
    pub instance: u32,
    pub address: Ipv4Addr,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseTable {
    leases: Vec<Lease>,
}

impl LeaseTable {
    #[must_use]
    pub fn leases(&self) -> &[Lease] {
        &self.leases
    }

    pub fn push_raw(&mut self, workload: &str, instance: u32, address: Ipv4Addr) {
        self.leases.push(Lease {
            workload: workload.to_owned(),
            instance,
            address,
        });
    }
}

#[derive(Debug, Clone)]
pub struct Leases {
    subnet: NodeSubnet,
    by_instance: BTreeMap<(String, u32), Ipv4Addr>,
    taken: BTreeSet<Ipv4Addr>,
}

impl Leases {
    #[must_use]
    pub fn new(subnet: NodeSubnet) -> Self {
        Self {
            subnet,
            by_instance: BTreeMap::new(),
            taken: BTreeSet::new(),
        }
    }

    pub fn restore(subnet: NodeSubnet, table: LeaseTable) -> Result<Self, IpamError> {
        let mut leases = Self::new(subnet);

        for lease in table.leases {
            if !leases.subnet.holds(lease.address) {
                return Err(IpamError::LeaseOutsideSubnet {
                    workload: lease.workload,
                    instance: lease.instance,
                    address: lease.address,
                    subnet: leases.subnet.net(),
                });
            }
            if !leases.taken.insert(lease.address) {
                return Err(IpamError::DuplicateLease {
                    address: lease.address,
                    workload: lease.workload,
                    instance: lease.instance,
                });
            }
            leases
                .by_instance
                .insert((lease.workload, lease.instance), lease.address);
        }

        Ok(leases)
    }

    #[must_use]
    pub fn subnet(&self) -> &NodeSubnet {
        &self.subnet
    }

    pub fn lease(&mut self, workload: &str, instance: u32) -> Result<Ipv4Addr, IpamError> {
        let key = (workload.to_owned(), instance);
        if let Some(address) = self.by_instance.get(&key) {
            return Ok(*address);
        }

        let address = self
            .subnet
            .assignable()
            .find(|candidate| !self.taken.contains(candidate))
            .ok_or_else(|| IpamError::SubnetFull {
                subnet: self.subnet.net(),
                capacity: self.subnet.capacity(),
            })?;

        self.taken.insert(address);
        self.by_instance.insert(key, address);

        Ok(address)
    }

    #[must_use]
    pub fn get(&self, workload: &str, instance: u32) -> Option<Ipv4Addr> {
        self.by_instance
            .get(&(workload.to_owned(), instance))
            .copied()
    }

    pub fn release(&mut self, workload: &str, instance: u32) -> Option<Ipv4Addr> {
        let address = self.by_instance.remove(&(workload.to_owned(), instance))?;
        self.taken.remove(&address);
        Some(address)
    }

    #[must_use]
    pub fn entries(&self) -> Vec<Lease> {
        self.by_instance
            .iter()
            .map(|((workload, instance), address)| Lease {
                workload: workload.clone(),
                instance: *instance,
                address: *address,
            })
            .collect()
    }

    #[must_use]
    pub fn snapshot(&self) -> LeaseTable {
        LeaseTable {
            leases: self.entries(),
        }
    }
}

pub const MAX_LINK_NAME: usize = 15;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkName(String);

impl LinkName {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for LinkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[must_use]
pub fn host_link(address: Ipv4Addr) -> LinkName {
    LinkName(format!("tg{:08x}", u32::from(address)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Mtu(u16);

impl Mtu {
    pub const WIREGUARD_OVERHEAD: u16 = 80;

    pub const MINIMUM: u16 = 1280;

    pub fn for_overlay(underlay: u16) -> Result<Self, IpamError> {
        let minimum = Self::MINIMUM + Self::WIREGUARD_OVERHEAD;
        if underlay < minimum {
            return Err(IpamError::MtuTooSmall { underlay, minimum });
        }

        Ok(Self(underlay - Self::WIREGUARD_OVERHEAD))
    }

    #[must_use]
    pub fn get(&self) -> u16 {
        self.0
    }
}

impl fmt::Display for Mtu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
