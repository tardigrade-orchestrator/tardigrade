//! SPIFFE IDs and trust domains.
//!
//! The format is `spiffe://<trust-domain>/<path>` (SPIFFE standard). The path
//! carries here **one** role and **one** name:
//!
//! ```text
//! spiffe://cluster.local/workload/api
//! spiffe://cluster.local/node/node-1
//! ```
//!
//! A namespace-qualified form such as `…/ns/<namespace>/workload/<name>` was
//! considered. A namespace concept does not exist in the definition format, and
//! inventing one merely so that the path looks longer would be a level without
//! meaning. The path is cut so that a namespace fits **before** the role later
//! without breaking existing IDs -- a new role would otherwise get the same
//! place.
//!
//! The separation of the roles is no ornament: without it a workload named
//! `node-1` could assume the identity of the node `node-1`, and with it the latter's
//! authority to mint SVIDs.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdError {
    detail: String,
}

impl IdError {
    fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for IdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no valid SPIFFE ID: {}", self.detail)
    }
}

impl std::error::Error for IdError {}

pub const DEFAULT_TRUST_DOMAIN: &str = "cluster.local";

const MAX_TRUST_DOMAIN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustDomain(String);

impl TrustDomain {
    pub fn new(raw: impl Into<String>) -> Result<Self, IdError> {
        let raw = raw.into();

        if raw.is_empty() {
            return Err(IdError::new("the trust domain is empty"));
        }
        if raw.len() > MAX_TRUST_DOMAIN {
            return Err(IdError::new(format!(
                "the trust domain is longer than {MAX_TRUST_DOMAIN} characters"
            )));
        }
        if !raw.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        }) {
            return Err(IdError::new(format!(
                "the trust domain '{raw}' contains impermissible characters"
            )));
        }

        Ok(Self(raw))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TrustDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Workload,
    Node,
    Operator,
}

impl Role {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Workload => "workload",
            Self::Node => "node",
            Self::Operator => "operator",
        }
    }

    fn from_segment(segment: &str) -> Option<Self> {
        match segment {
            "workload" => Some(Self::Workload),
            "node" => Some(Self::Node),
            "operator" => Some(Self::Operator),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpiffeId {
    trust_domain: TrustDomain,
    role: Role,
    name: String,
}

impl SpiffeId {
    pub fn for_workload(domain: &TrustDomain, name: &str) -> Result<Self, IdError> {
        Self::new(domain, Role::Workload, name)
    }

    pub fn for_node(domain: &TrustDomain, name: &str) -> Result<Self, IdError> {
        Self::new(domain, Role::Node, name)
    }

    pub fn for_operator(domain: &TrustDomain, name: &str) -> Result<Self, IdError> {
        Self::new(domain, Role::Operator, name)
    }

    fn new(domain: &TrustDomain, role: Role, name: &str) -> Result<Self, IdError> {
        if !is_valid_name(name) {
            return Err(IdError::new(format!(
                "'{name}' is no valid name (expected [a-z][a-z0-9-]{{0,62}})"
            )));
        }

        Ok(Self {
            trust_domain: domain.clone(),
            role,
            name: name.to_owned(),
        })
    }

    #[must_use]
    pub fn trust_domain(&self) -> &TrustDomain {
        &self.trust_domain
    }

    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    #[must_use]
    pub fn workload(&self) -> Option<&str> {
        (self.role == Role::Workload).then_some(self.name.as_str())
    }

    #[must_use]
    pub fn node(&self) -> Option<&str> {
        self.named(Role::Node)
    }

    #[must_use]
    pub fn named(&self, role: Role) -> Option<&str> {
        (self.role == role).then_some(self.name.as_str())
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spiffe://{}/{}/{}",
            self.trust_domain,
            self.role.as_str(),
            self.name
        )
    }
}

impl FromStr for SpiffeId {
    type Err = IdError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let Some(rest) = raw.strip_prefix("spiffe://") else {
            return Err(IdError::new("the scheme is not 'spiffe://'"));
        };
        if rest.contains(['?', '#', '@']) {
            return Err(IdError::new(
                "query, fragment and user part are not permissible",
            ));
        }

        let mut segments = rest.split('/');
        let authority = segments.next().unwrap_or_default();
        if authority.contains(':') {
            return Err(IdError::new("a port is not permissible"));
        }
        let domain = TrustDomain::new(authority)?;

        let role_segment = segments
            .next()
            .ok_or_else(|| IdError::new("the path is missing"))?;
        let role = Role::from_segment(role_segment)
            .ok_or_else(|| IdError::new(format!("unknown role '{role_segment}'")))?;

        let name = segments
            .next()
            .ok_or_else(|| IdError::new("the name is missing"))?;
        if segments.next().is_some() {
            return Err(IdError::new("additional path segments"));
        }

        Self::new(&domain, role, name)
    }
}

fn is_valid_name(name: &str) -> bool {
    tg_model::names::is_plausible(name)
}
