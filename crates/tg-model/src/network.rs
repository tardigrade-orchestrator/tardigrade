//! The cluster's address plan (ADR-0012, ADR-0039).
//!
//! From a node's **ordinal** its subnet follows by pure computation. The number
//! is handed out by consensus at admission (ADR-0037/0039) and the node holds
//! it for as long as it exists; what is decisive is what it is **not**: a
//! position in a list. Were it that, the failure of one node would shift the
//! subnets of all the following ones — and every route, every nftables rule and
//! every `WireGuard` `AllowedIP` in the cluster would afterwards point into the
//! void, without an error appearing anywhere.
//!
//! # Why the calculation stands here
//!
//! It has **two** readers with different tasks:
//!
//! - **Consensus** hands out the ordinal and for that has to know how many
//!   there are at all.
//! - The **node** computes from it its subnet, its bridge address and its
//!   peers' `AllowedIPs`.
//!
//! It lay at first only at the node (`tg_net::ipam`). With that consensus could
//! hand out a number from which no network ever follows: it admitted the node,
//! reported `Applied`, and the error appeared only on the node — there
//! fail-soft and once per slice. An address space nobody can read went the same
//! way.
//!
//! The consensus core must not link `tg-net`: netlink and nftables lie there.
//! So the calculation belongs **under** both, and then it stands there once
//! instead of twice.

use std::fmt;
use std::net::Ipv4Addr;

use ipnet::Ipv4Net;

const NARROWEST_NODE_PREFIX: u8 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
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
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodePrefixTooWide { cluster, node } => write!(
                f,
                "the node prefix /{node} is not narrower than the cluster CIDR /{cluster}"
            ),
            Self::NodeSubnetTooSmall { node } => write!(
                f,
                "a node subnet /{node} carries no container — narrower than \
                 /{NARROWEST_NODE_PREFIX} nothing remains after network, \
                 broadcast and gateway"
            ),
            Self::ClusterFull { ordinal, capacity } => write!(
                f,
                "ordinal {ordinal} lies outside the cluster CIDR — it carries \
                 {capacity} node subnets"
            ),
        }
    }
}

impl std::error::Error for PlanError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    NotACidr {
        cidr: String,
    },
    Plan(PlanError),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotACidr { cidr } => {
                write!(f, "'{cidr}' is no IPv4 CIDR (expected <address>/<prefix>)")
            }
            Self::Plan(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<PlanError> for ParseError {
    fn from(err: PlanError) -> Self {
        Self::Plan(err)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    net: Ipv4Net,
    node_prefix: u8,
}

impl Plan {
    pub fn parse(cidr: &str, node_prefix: u8) -> Result<Self, ParseError> {
        let net = cidr.parse::<Ipv4Net>().map_err(|_| ParseError::NotACidr {
            cidr: cidr.to_owned(),
        })?;

        Ok(Self::new(net, node_prefix)?)
    }

    pub fn new(net: Ipv4Net, node_prefix: u8) -> Result<Self, PlanError> {
        if node_prefix <= net.prefix_len() {
            return Err(PlanError::NodePrefixTooWide {
                cluster: net.prefix_len(),
                node: node_prefix,
            });
        }
        if node_prefix > NARROWEST_NODE_PREFIX {
            return Err(PlanError::NodeSubnetTooSmall { node: node_prefix });
        }

        Ok(Self {
            net: net.trunc(),
            node_prefix,
        })
    }

    #[must_use]
    pub fn net(&self) -> Ipv4Net {
        self.net
    }

    #[must_use]
    pub fn node_prefix(&self) -> u8 {
        self.node_prefix
    }

    #[must_use]
    pub fn capacity(&self) -> u32 {
        1u32 << (self.node_prefix - self.net.prefix_len())
    }

    #[must_use]
    pub fn holds(&self, ordinal: u32) -> bool {
        ordinal < self.capacity()
    }

    pub fn subnet_of(&self, ordinal: u32) -> Result<Ipv4Net, PlanError> {
        let capacity = self.capacity();
        if !self.holds(ordinal) {
            return Err(PlanError::ClusterFull { ordinal, capacity });
        }

        let size = 1u32 << (32 - self.node_prefix);
        let base = u32::from(self.net.network()) + ordinal * size;

        // Not reachable: `node_prefix` is bounded to at most 30 in `new`, and
        // after the check `base` lies within the network.
        Ipv4Net::new(Ipv4Addr::from(base), self.node_prefix)
            .map_err(|_| PlanError::ClusterFull { ordinal, capacity })
    }
}
