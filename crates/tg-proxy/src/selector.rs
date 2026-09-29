//! The selectors of a `may_talk` edge (ADR-0025).
//!
//! ADR-0025 provides for "an exact SPIFFE ID **or** a path-prefix selector",
//! "to bound edge proliferation".
//!
//! # A deviation from ADR-0025, and why it is unavoidable
//!
//! The ADR names as an example for a prefix `/ns/trading/` -- "all workloads
//! in the namespace hierarchy". That hierarchy does **not** exist in our IDs:
//! ADR-0006 and phase 7a fixed the path at exactly two segments,
//! `/<role>/<name>`, and the name follows the facet from the XSD. A path
//! prefix in the sense of the example would have nothing to bite on here --
//! there would only be `/workload/`, and that would be "all".
//!
//! The prefix therefore acts on the **name**: `ledger-*` covers `ledger-read`
//! and `ledger-write`. That fulfils the ADR's purpose (fewer edges for a
//! family of related services) without inventing a hierarchy the identity
//! model does not know. Whoever wants real namespaces changes ADR-0006 -- and
//! with a new ADR, not here.
//!
//! # Three forms, syntactically distinguishable
//!
//! | Form | Example | Meaning |
//! |------|---------|---------|
//! | full ID | `spiffe://cluster.local/workload/api` | exactly this identity |
//! | prefix | `ledger-*` | every workload whose name begins that way |
//! | name | `api` | the workload of this name |
//!
//! The forms cannot collide: `*` and `:` are not permitted in the name facet
//! (`[a-z][a-z0-9-]{0,62}`), so a name can look neither like a prefix nor like
//! a URL.

use std::fmt;

use tg_identity::{Role, SpiffeId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorError {
    Empty,
    Name {
        got: String,
    },
    Id {
        detail: String,
    },
}

impl fmt::Display for SelectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("an empty selector permits nothing and nobody"),
            Self::Name { got } => write!(
                f,
                "'{got}' is no workload name (expected [a-z][a-z0-9-]{{0,62}}, ADR-0008)"
            ),
            Self::Id { detail } => write!(f, "no readable SPIFFE ID: {detail}"),
        }
    }
}

impl std::error::Error for SelectorError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Exact(SpiffeId),
    Prefix(String),
    Workload(String),
}

impl Selector {
    pub fn parse(raw: &str) -> Result<Self, SelectorError> {
        if raw.is_empty() {
            return Err(SelectorError::Empty);
        }

        if raw.starts_with("spiffe://") {
            return raw
                .parse::<SpiffeId>()
                .map(Self::Exact)
                .map_err(|err| SelectorError::Id {
                    detail: err.to_string(),
                });
        }

        if let Some(prefix) = raw.strip_suffix('*') {
            // An empty prefix would be "all" -- that is no bounding of the
            // proliferation but its abandonment. ADR-0025 wants least
            // privilege; whoever really means all writes all the edges.
            if prefix.is_empty() {
                return Err(SelectorError::Name {
                    got: raw.to_owned(),
                });
            }
            if !is_name_fragment(prefix) {
                return Err(SelectorError::Name {
                    got: prefix.to_owned(),
                });
            }
            return Ok(Self::Prefix(prefix.to_owned()));
        }

        if !is_name(raw) {
            return Err(SelectorError::Name {
                got: raw.to_owned(),
            });
        }

        Ok(Self::Workload(raw.to_owned()))
    }

    #[must_use]
    pub fn matches(&self, id: &SpiffeId) -> bool {
        let Some(name) = id.workload() else {
            return false;
        };

        match self {
            Self::Exact(expected) => expected == id && expected.role() == Role::Workload,
            Self::Prefix(prefix) => name.starts_with(prefix.as_str()),
            Self::Workload(expected) => name == expected,
        }
    }
}

impl fmt::Display for Selector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(id) => write!(f, "{id}"),
            Self::Prefix(prefix) => write!(f, "{prefix}*"),
            Self::Workload(name) => f.write_str(name),
        }
    }
}

fn is_name(raw: &str) -> bool {
    let mut bytes = raw.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };

    first.is_ascii_lowercase()
        && raw.len() <= 63
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn is_name_fragment(raw: &str) -> bool {
    is_name(raw)
}
