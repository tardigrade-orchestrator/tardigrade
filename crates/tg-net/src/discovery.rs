//! Service discovery: name → endpoint.
//!
//! What this module does **not** do: discovery delivers **only** name →
//! endpoint(s). The identity is checked by the mTLS handshake via the SPIFFE
//! ID, the permission comes from the `may_talk` edges.
//!
//! The temptation to filter additionally here is great and the error subtle: a
//! resolution that hands out only what the asker may also address looks like
//! defence in depth. It is, however, a **displacement** — the enforcement would
//! then sit in two places, and the one here is the weaker, because a container
//! can guess the address without resolution too. This registry therefore knows
//! no edges.
//!
//! # Two negative answers, not one
//!
//! **NXDOMAIN** means "this name does not exist", **NODATA** means "the name
//! exists, right now nothing is healthy". Whoever collapses both into NXDOMAIN
//! lets resolvers cache a negative result that is immediately wrong again: a
//! workload that is still starting would stay unreachable until the cache
//! expires. And that a client starts before its target is no error but what a
//! `Wants` edge means: a dependency may come up after its dependant asks for it.
//!
//! # No forwarder
//!
//! For everything outside its own zone comes [`Answer::Refused`] — no
//! forwarding. A resolver in the mesh that resolves arbitrary names is an open
//! resolver; whoever wants to resolve into the internet asks their second one.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;

pub const TTL_SECONDS: u32 = 5;

const _: () = assert!(
    TTL_SECONDS as i64 * 3 <= tg_model::lease::LEASE_SECONDS,
    "the DNS TTL has to carry a third of the lease (ADR-0013, ADR-0014):      otherwise a failover sees fewer than two resolutions"
);

pub const NEGATIVE_TTL_SECONDS: u32 = 1;

const MAX_LABEL: usize = 63;

const MAX_NAME: usize = 253;

impl Domain {
    #[must_use]
    pub fn longest_workload_name(&self) -> Option<usize> {
        // `<name>` + `.` + the zone.
        MAX_NAME
            .checked_sub(self.as_str().len() + 1)
            .map(|room| room.min(MAX_LABEL))
            .filter(|room| *room > 0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameError {
    Empty,
    EmptyLabel,
    LabelTooLong {
        length: usize,
    },
    TooLong {
        length: usize,
    },
    IllegalLabel {
        label: String,
    },
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty name"),
            Self::EmptyLabel => f.write_str("empty label"),
            Self::LabelTooLong { length } => {
                write!(
                    f,
                    "label with {length} characters, permitted are {MAX_LABEL}"
                )
            }
            Self::TooLong { length } => {
                write!(f, "name with {length} characters, permitted are {MAX_NAME}")
            }
            Self::IllegalLabel { label } => {
                write!(f, "'{}' is no hostname label", label.escape_debug())
            }
        }
    }
}

impl std::error::Error for NameError {}

fn canonical(raw: &str) -> Result<String, NameError> {
    let trimmed = raw.strip_suffix('.').unwrap_or(raw);
    if trimmed.is_empty() {
        return Err(NameError::Empty);
    }
    if trimmed.len() > MAX_NAME {
        return Err(NameError::TooLong {
            length: trimmed.len(),
        });
    }

    let lowered = trimmed.to_ascii_lowercase();
    for label in lowered.split('.') {
        if label.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        if label.len() > MAX_LABEL {
            return Err(NameError::LabelTooLong {
                length: label.len(),
            });
        }
        let legal = label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-');
        if !legal {
            return Err(NameError::IllegalLabel {
                label: label.to_owned(),
            });
        }
    }

    Ok(lowered)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Domain(String);

impl Domain {
    pub fn new(raw: &str) -> Result<Self, NameError> {
        canonical(raw).map(Self)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    Healthy,
    Unhealthy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub workload: String,
    pub instance: u32,
    pub address: Ipv4Addr,
    pub health: Health,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Addresses(Vec<Ipv4Addr>),
    NoData,
    NxDomain,
    Refused,
}

#[derive(Debug, Clone)]
pub struct Registry {
    domain: Domain,
    by_workload: BTreeMap<String, BTreeMap<u32, Endpoint>>,
}

impl Registry {
    #[must_use]
    pub fn new(domain: Domain, endpoints: Vec<Endpoint>) -> Self {
        let mut by_workload: BTreeMap<String, BTreeMap<u32, Endpoint>> = BTreeMap::new();

        for endpoint in endpoints {
            by_workload
                .entry(endpoint.workload.clone())
                .or_default()
                .insert(endpoint.instance, endpoint);
        }

        Self {
            domain,
            by_workload,
        }
    }

    #[must_use]
    pub fn domain(&self) -> &Domain {
        &self.domain
    }

    #[must_use]
    pub fn resolve(&self, name: &str) -> Answer {
        // A name that is none gets NXDOMAIN and not Refused: whether it would
        // have belonged in the zone cannot be said.
        let Ok(name) = canonical(name) else {
            return Answer::NxDomain;
        };

        let Some(prefix) = name.strip_suffix(self.domain.as_str()) else {
            return Answer::Refused;
        };
        // `strip_suffix` alone does not suffice: `evil-tardigrade.internal`
        // also ends in the zone but does not belong in it.
        let prefix = match prefix {
            "" => return Answer::NxDomain, // the zone itself is no service
            other => match other.strip_suffix('.') {
                Some(labels) => labels,
                None => return Answer::Refused,
            },
        };

        let labels: Vec<&str> = prefix.split('.').collect();
        match labels[..] {
            [workload] => self.service(workload),
            [instance, workload] => match instance.parse::<u32>() {
                // Only the canonical spelling resolves. `00` parses to 0, and
                // `000` too — without this check the same endpoint would have
                // arbitrarily many names. That breaks every cache key and every
                // comparison that later builds on a name.
                Ok(number) if number.to_string() == instance => self.instance(workload, number),
                _ => Answer::NxDomain,
            },
            _ => Answer::NxDomain,
        }
    }

    fn service(&self, workload: &str) -> Answer {
        let Some(instances) = self.by_workload.get(workload) else {
            return Answer::NxDomain;
        };

        let addresses: Vec<Ipv4Addr> = instances
            .values()
            .filter(|endpoint| endpoint.health == Health::Healthy)
            .map(|endpoint| endpoint.address)
            .collect();

        if addresses.is_empty() {
            Answer::NoData
        } else {
            Answer::Addresses(addresses)
        }
    }

    fn instance(&self, workload: &str, instance: u32) -> Answer {
        let Some(endpoint) = self
            .by_workload
            .get(workload)
            .and_then(|instances| instances.get(&instance))
        else {
            return Answer::NxDomain;
        };

        match endpoint.health {
            Health::Healthy => Answer::Addresses(vec![endpoint.address]),
            Health::Unhealthy => Answer::NoData,
        }
    }
}
