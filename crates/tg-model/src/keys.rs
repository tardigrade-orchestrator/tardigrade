//! A node's key generations (ADR-0055).
//!
//! A node carries two keys, and until ADR-0055 **neither** of them had a
//! replacement path: generated when the file is missing, read when it is there,
//! never replaced. For operation under DORA that is the wrong state — a
//! compromise could only be answered by re-admitting the node, and with the
//! ordinal that is a renumbering (ADR-0039).
//!
//! # Why a number and not a shout
//!
//! "Rotate now" gets lost if the node does not hear it — and then one needs a
//! catch-up protocol for something that needs none. A **wanted generation** in
//! the log does not get lost: whoever was away compares on return (ADR-0010,
//! level-triggered). The same consideration out of which ADR-0054 built detach
//! as a state and ADR-0042 the deletion as a tombstone.
//!
//! # Why two numbers
//!
//! The two keys rotate for different reasons, and the one shall not pull the
//! other along: a compromised underlay key is no reason to register the node's
//! identity anew.

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    Identity,
    Underlay,
}

impl KeyKind {
    pub const ALL: [Self; 2] = [Self::Identity, Self::Underlay];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Underlay => "underlay",
        }
    }
}

impl std::fmt::Display for KeyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for KeyKind {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text {
            "identity" => Ok(Self::Identity),
            "underlay" => Ok(Self::Underlay),
            other => Err(format!("unknown key kind '{other}' — identity or underlay")),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generations {
    #[serde(default)]
    pub identity: u64,
    #[serde(default)]
    pub underlay: u64,
}

impl Generations {
    #[must_use]
    pub const fn of(&self, kind: KeyKind) -> u64 {
        match kind {
            KeyKind::Identity => self.identity,
            KeyKind::Underlay => self.underlay,
        }
    }

    pub const fn set(&mut self, kind: KeyKind, generation: u64) {
        match kind {
            KeyKind::Identity => self.identity = generation,
            KeyKind::Underlay => self.underlay = generation,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RotationPolicy(std::collections::BTreeMap<KeyKind, u32>);

impl RotationPolicy {
    #[must_use]
    pub fn with(mut self, kind: KeyKind, period_days: u32) -> Self {
        self.0.insert(kind, period_days);
        self
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.values().all(|period| *period == 0)
    }

    #[must_use]
    pub fn entries(&self) -> Vec<(KeyKind, u32)> {
        self.0.iter().map(|(kind, days)| (*kind, *days)).collect()
    }

    #[must_use]
    pub fn wanted(&self, node: &str, kind: KeyKind, day: u64) -> Option<u64> {
        let period = u64::from(*self.0.get(&kind)?);
        if period == 0 {
            return None;
        }

        Some((day + offset(node, period)) / period)
    }
}

#[must_use]
pub const fn day_of(unix_seconds: u64) -> u64 {
    unix_seconds / 86_400
}

fn offset(node: &str, period: u64) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in node.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }

    hash % period
}
