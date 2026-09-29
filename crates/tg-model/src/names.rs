//! The name part of a SPIFFE identifier — in **one** place.
//!
//! ADR-0036 fixes the path form: `spiffe://<domain>/<role>/<name>`. The
//! `<name>` part is thereby **one** fact for all roles — workload, node,
//! operator —, and measured, its check stood rebuilt by hand **five times** in
//! the tree, in four crates and in two variants. Four of the five bodies were
//! byte for byte identical.
//!
//! What hangs on it is the identity boundary: if one of the versions runs away,
//! one layer accepts a name another refuses — and then a container runs with a
//! name for which there is no SVID (ADR-0006). The error shows up not at apply
//! time but at the first connection; the same shape as the finding from the
//! wiring ("mints SVIDs without complaint, and none of them is accepted").
//!
//! **The schema's facet is separate from this.** `schema/workload.xsd`
//! prescribes `[a-z][a-z0-9-]{0,62}` for a *workload* name; that is a decision
//! of its own (ADR-0008), and it only has to **fit inside**:
//!
//! > XSD facet **≤** [`MAX_NAME`]
//!
//! The condition is held by the guard `the_workload_name_fits_a_dns_label` in
//! `tg-defs` — it reads the schema, because the source there is a **file**. The
//! three rebuilds of the check did not stand among its consumers.
//!
//! **`tg-proxy` expressly does not call here.** It deliberately does not hang
//! on `tg-model` (no XSD parser in the data plane, the decision from the
//! transport cut to ADR-0092), so the form there is a contract about the line —
//! like the transport enum, and with the same rationale in both places.

pub const MAX_NAME: usize = 63;

#[must_use]
pub fn is_plausible(name: &str) -> bool {
    let mut bytes = name.bytes();

    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() || name.len() > MAX_NAME {
        return false;
    }

    bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

#[must_use]
pub fn is_plausible_secret(name: &str) -> bool {
    let mut bytes = name.bytes();

    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() || name.len() > MAX_NAME {
        return false;
    }

    bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

pub const CONTAINER_PREFIX: &str = "tg-";
