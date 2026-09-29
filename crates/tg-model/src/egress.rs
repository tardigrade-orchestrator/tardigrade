//! The transport of an egress permission.
//!
//! Egress policy binds the way out to a **name** the connection itself names.
//! Over TCP it stands in the TLS `ClientHello`; over QUIC likewise, only in
//! the CRYPTO frames of an Initial packet. Both are the same trust cut, and
//! both are the same notion for an operator: a name, a port, a transport.
//!
//! # Why the enum stands here — and a second one in the sidecar
//!
//! This side is shared by `tg-consensus` (the command), `tg-store` (the slice)
//! and `tg-agent` (which writes the file); all three hang on `tg-model`.
//!
//! Here it stood that the **sidecar** does not hang on it and that the edge
//! would be disproportionate: `tg-model` would pull `tg-defs` along, that is,
//! an XSD parser and a regex engine into the data plane. **Re-measured that is
//! not the case.** `tg-proxy` hangs on `tg-identity`, and that hangs on
//! `tg-model` — without `dev-dependencies`, so in the shipped binary:
//!
//! ```text
//! tg-model └── tg-identity └── tg-proxy
//! ```
//!
//! The direct edge thereby costs **zero** additional crates (370 before as
//! after, measured). It is drawn because the sidecar and the resolver must
//! use the same comparison — and two versions of the same comparison are two
//! opportunities to differ.
//!
//! The **format of the line** nevertheless stays the contract, as already for
//! name and port: `tg_proxy::egress` reads the same words. That both sides
//! agree is recorded by no text comparison but by a run in which the agent
//! writes and the sidecar reads — and a skew would come out **fail-closed**: a
//! line the sidecar does not understand is no permission.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Quic,
    Udp,
}

impl Transport {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Quic => "quic",
            Self::Udp => "udp",
        }
    }

    #[must_use]
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "tcp" => Some(Self::Tcp),
            "quic" => Some(Self::Quic),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

impl Default for Transport {
    fn default() -> Self {
        Self::Tcp
    }
}

impl std::fmt::Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::Transport;

    #[test]
    fn every_transport_survives_the_round_trip() {
        for transport in [Transport::Tcp, Transport::Quic, Transport::Udp] {
            assert_eq!(
                Transport::parse(transport.as_str()),
                Some(transport),
                "{transport} does not read back"
            );
        }
    }

    #[test]
    fn an_unknown_word_is_refused() {
        for word in ["UDP", "TCP", "", "tcp ", "sctp"] {
            assert_eq!(
                Transport::parse(word),
                None,
                "'{word}' was read as a transport"
            );
        }
    }

    #[test]
    fn the_default_is_what_older_entries_meant() {
        assert_eq!(Transport::default(), Transport::Tcp);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetForm {
    Exact,
    Wildcard,
}

#[must_use]
pub fn target_form(host: &str) -> Option<TargetForm> {
    let (pattern, rest) = match host.split_once('.') {
        Some(("*", rest)) => (TargetForm::Wildcard, rest),
        // **A star anywhere else is no wildcard but an error.** Letting it
        // through as an ordinary name would be exactly the measured state:
        // accepted and without effect.
        _ if host.contains('*') => return None,
        _ => (TargetForm::Exact, host),
    };

    if !is_dns_name(rest) {
        return None;
    }
    // A wildcard needs two labels behind it: `*.com` would cover a whole
    // top-level domain.
    if pattern == TargetForm::Wildcard && !rest.contains('.') {
        return None;
    }

    Some(pattern)
}

#[must_use]
pub fn target_allows(pattern: &str, name: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();

    let Some(rest) = pattern.strip_prefix("*.") else {
        return pattern == name;
    };

    // Exactly one label before it: the part before the first dot must not be
    // empty and must itself contain no dot.
    let Some((label, tail)) = name.split_once('.') else {
        return false;
    };
    !label.is_empty() && tail == rest
}

fn is_dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }

    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

#[cfg(test)]
mod adr_0124 {
    use super::{TargetForm, target_allows, target_form};

    #[test]
    fn only_one_shape_of_wildcard_is_a_wildcard() {
        assert_eq!(target_form("s3.example.com"), Some(TargetForm::Exact));
        assert_eq!(target_form("*.s3.example.com"), Some(TargetForm::Wildcard));

        for broken in [
            // The star is not the whole label.
            "ab*.s3.example.com",
            "*ab.s3.example.com",
            "s3.*.example.com",
            // Too little behind it: that would cover a whole top-level domain.
            "*.com",
            "*",
            "*.",
            // Two stars.
            "*.*.example.com",
            // No DNS name.
            "",
            "-ab.example.com",
            "ab-.example.com",
            "a..b",
            "a b.example.com",
            "sample.example.com.",
        ] {
            assert_eq!(
                target_form(broken),
                None,
                "'{broken}' has no form that could ever permit anything"
            );
        }
    }

    #[test]
    fn a_wildcard_covers_exactly_one_label() {
        let star = "*.s3.example.com";

        assert!(target_allows(star, "bucket.s3.example.com"));
        assert!(
            target_allows(star, "BUCKET.S3.Example.COM"),
            "DNS is blind to spelling"
        );

        // **Not two labels** — otherwise a star would cover arbitrarily deep.
        assert!(!target_allows(star, "a.b.s3.example.com"));
        // **Not the name itself** — it is often something other than its
        // children (with S3 the account administration instead of a bucket).
        assert!(!target_allows(star, "s3.example.com"));
        // **No empty label.**
        assert!(!target_allows(star, ".s3.example.com"));
        // No suffix comparison either.
        assert!(!target_allows(star, "bucket.s3.example.com.evil.net"));
        assert!(!target_allows("s3.example.com", "evil-s3.example.com"));
    }

    #[test]
    fn without_a_star_the_comparison_is_exact() {
        assert!(target_allows("s3.example.com", "s3.example.com"));
        assert!(!target_allows("s3.example.com", "bucket.s3.example.com"));
        assert!(!target_allows("example.com", "s3.example.com"));
    }
}

#[must_use]
pub fn registry_of(reference: &str) -> String {
    const HUB: &str = "docker.io";

    let first = reference.split('/').next().unwrap_or_default();
    // Without a path separator there is no registry component: `api:1` is a
    // name on Docker Hub, and the colon in it is the tag.
    if !reference.contains('/') {
        return HUB.to_owned();
    }
    if first.contains('.') || first.contains(':') || first == "localhost" {
        first.to_ascii_lowercase()
    } else {
        HUB.to_owned()
    }
}

#[cfg(test)]
mod adr_0125 {
    use super::registry_of;

    #[test]
    fn the_first_component_is_the_registry_only_if_it_looks_like_a_host() {
        for (reference, expected) in [
            ("registry.example.com/api:1", "registry.example.com"),
            (
                "registry.example.com:5000/api:1",
                "registry.example.com:5000",
            ),
            ("localhost:5000/api:1", "localhost:5000"),
            ("localhost/api:1", "localhost"),
            ("ghcr.io/org/api:1", "ghcr.io"),
            ("registry.example.com/a/b/c:1", "registry.example.com"),
            // No host: that is Docker Hub, and the colon is the tag.
            ("api:1", "docker.io"),
            ("library/api:1", "docker.io"),
            ("example/api:1", "docker.io"),
            // **Lowercased** — the find that triggered this ADR.
            ("REGISTRY.example.com/api:1", "registry.example.com"),
        ] {
            assert_eq!(
                registry_of(reference),
                expected,
                "'{reference}' belongs to '{expected}'"
            );
        }
    }
}
