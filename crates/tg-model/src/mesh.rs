//! The sidecar derivation (ADR-0007, ADR-0009, ADR-0025).
//!
//! A workload that declares `<mesh port="…"/>` gets a sidecar. The sidecar is
//! **no annotation on the workload but a unit of its own**: it is placed,
//! started, watched and stopped like any other workload. ADR-0007 names that as
//! a cost of the sidecar choice — "additional orchestration load" —, and that
//! load is paid here instead of being smuggled into the agent.
//!
//! # The coupling, and why it goes only in one direction
//!
//! The sidecar declares **`bindsTo` and `after`** on its workload (ADR-0009):
//!
//! - `after` — it starts afterwards. It has nothing to proxy as long as the
//!   workload is not listening.
//! - `bindsTo` — it goes with it. A sidecar without its workload is pointless,
//!   and one that stayed standing would hold a port open behind which there is
//!   nothing any more.
//!
//! The reverse does **not** exist: the workload does not hang on the sidecar. A
//! workload that the failure of its sidecar dragged along would be less
//! available than one without a mesh, and ADR-0019 decouples workload
//! availability precisely from everything that lies above it. Reachable it is
//! nevertheless not without a sidecar — from phase 9 on the traffic is directed
//! through it, there is no way past it. The coupling is thereby fail-closed
//! without endangering the workload.
//!
//! # Which identity the sidecar puts on the wire
//!
//! Here a tension between two ADRs became visible, and neither of the two had
//! thought of the sidecar:
//!
//! - **ADR-0006** binds the identity to the container. By that `api-proxy`
//!   would get the ID `spiffe://…/workload/api-proxy` — it is a container of
//!   its own.
//! - **ADR-0025** draws the `may_talk` edges between **workloads**: `api →
//!   ledger`. For the edge to take effect, `api` would have to stand on the
//!   wire.
//!
//! **ADR-0036 decided that, and without deciding between the two:** the sidecar
//! keeps its own identity and **additionally** gets a delegated SVID for its
//! workload. The workload API has always handed out several SVIDs with a
//! `hint` — that is what the specification says, and it did not have to be
//! extended. With that ADR-0006 and ADR-0025 both stay valid unchanged; the ADR
//! at the same time fixes the path form (`spiffe://<domain>/<role>/<name>`,
//! without a namespace) and replaces ADR-0006 in that.
//!
//! The edge at issue precisely did **not** stay open: the name suffix is the
//! address and not the credential. Who gets a delegation is decided by
//! [`delegations`] over four conditions — the suffix is one of them, and alone
//! it carries nothing.
//!
//! # Why the derivation runs over XML
//!
//! [`expand`] builds the sidecar's document and reads it through the same
//! loader as a hand-written definition. That costs a round trip at ingest and
//! brings an assurance in exchange: **a derived unit fulfils the same contract
//! as a written one.** Were it built as a structure, it would be the only
//! definition in the system that was never validated — and an error in it would
//! stand out only in operation.

use std::collections::BTreeMap;
use std::fmt;

use tg_defs::generated::WorkloadType;
use tg_defs::{
    DependencyKind, ImageExt as _, MeshExt as _, PlacementExt as _, WorkloadExt, from_str,
};

const SUFFIX: &str = "-proxy";

pub const SIDECAR_UID: u32 = 65532;

pub const PROGRAM_IN_CONTAINER: &str = "/usr/local/bin/tg-proxy";

pub const SOCKET_IN_CONTAINER: &str = "/run/tardigrade/workload-api.sock";

pub const SECRETS_IN_CONTAINER: &str = "/run/tardigrade/secrets";

pub const EDGES_IN_CONTAINER: &str = "/etc/tardigrade/may-talk";

pub const EGRESS_IN_CONTAINER: &str = "/etc/tardigrade/egress";

pub const MESH_UDP_IN_CONTAINER: &str = "/etc/tardigrade/mesh-udp";

pub const ROLE_IN_CONTAINER: &str = "/etc/tardigrade/active-role";

pub const SIDECAR_INBOUND: u16 = 15006;

pub const SIDECAR_OUTBOUND: u16 = 15001;

pub const SIDECAR_EGRESS: u16 = 15002;

pub const SIDECAR_MESH_UDP_BASE: u16 = 15100;

pub const SIDECAR_MESH_UDP: u16 = 15007;

pub use crate::names::MAX_NAME;

pub const MAX_IMAGE: usize = 512;

pub const MAX_TRUST_DOMAIN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshError {
    NameTooLong {
        workload: String,
        derived: String,
    },
    NameTaken {
        workload: String,
        derived: String,
    },
    Image {
        detail: String,
    },
    Malformed {
        detail: String,
    },
}

impl MeshError {
    #[must_use]
    pub fn workload(&self) -> Option<&str> {
        match self {
            Self::NameTooLong { workload, .. } | Self::NameTaken { workload, .. } => Some(workload),
            _ => None,
        }
    }
}

impl fmt::Display for MeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameTooLong { workload, derived } => write!(
                f,
                "the sidecar of '{workload}' would be called '{derived}' and thereby no \
                 longer fits into the name facet ({MAX_NAME} characters). The name is not \
                 shortened: two long names that differ only in the last character would \
                 yield the same sidecar"
            ),
            Self::NameTaken { workload, derived } => write!(
                f,
                "the sidecar of '{workload}' would be called '{derived}', and this workload \
                 already exists. It is not overwritten — otherwise a written definition \
                 would vanish without an error standing anywhere"
            ),
            Self::Image { detail } => write!(f, "proxy image unusable: {detail}"),
            Self::Malformed { detail } => {
                write!(f, "the derived sidecar document is not readable: {detail}")
            }
        }
    }
}

impl std::error::Error for MeshError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarSpec {
    image: String,
    trust_domain: String,
    pin_shards: bool,
}

impl SidecarSpec {
    pub fn new(
        image: impl Into<String>,
        trust_domain: impl Into<String>,
    ) -> Result<Self, MeshError> {
        let image = image.into();
        let trust_domain = trust_domain.into();

        if image.is_empty() || image.len() > MAX_IMAGE {
            return Err(MeshError::Image {
                detail: format!(
                    "an image reference has 1 to {MAX_IMAGE} characters, this one has {}",
                    image.len()
                ),
            });
        }
        if image.contains(['<', '>', '&', '"']) {
            return Err(MeshError::Image {
                detail: "the reference contains XML special characters".to_owned(),
            });
        }

        // **What is checked is the form the document carries**, not the
        // SPIFFE semantics: `tg_identity::TrustDomain` knows those, and
        // `tg-model` lies beneath it. What counts here is that the value fits
        // into an `<arg>` line — otherwise a document would arise that the
        // loader no longer reads, and the error would show up as a schema
        // violation on a derived unit nobody wrote.
        if trust_domain.is_empty() || trust_domain.len() > MAX_TRUST_DOMAIN {
            return Err(MeshError::Image {
                detail: format!(
                    "a trust domain has 1 to {MAX_TRUST_DOMAIN} characters, this one has {}",
                    trust_domain.len()
                ),
            });
        }
        if trust_domain.contains(['<', '>', '&', '"']) {
            return Err(MeshError::Image {
                detail: "the trust domain contains XML special characters".to_owned(),
            });
        }

        Ok(Self {
            image,
            trust_domain,
            // **Default off** (ADR-0114, determination 3). Whoever is the only
            // one nailed down can no longer move aside from an occupied core.
            pin_shards: false,
        })
    }

    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.trust_domain
    }

    #[must_use]
    pub fn pinned_shards(mut self, pinned: bool) -> Self {
        self.pin_shards = pinned;

        self
    }
}

#[must_use]
pub fn sidecar_name(workload: &str) -> String {
    format!("{workload}{SUFFIX}")
}

#[must_use]
pub fn members(workloads: &[WorkloadType]) -> Vec<&str> {
    workloads
        .iter()
        .filter(|workload| workload.mesh().is_some())
        .map(WorkloadExt::name)
        .collect()
}

#[must_use]
pub fn delegations(workloads: &[WorkloadType], spec: &SidecarSpec) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();

    for target in workloads {
        if target.mesh().is_none() {
            continue;
        }
        let name = target.name();
        let derived = sidecar_name(name);

        if let Some(candidate) = workloads
            .iter()
            .find(|candidate| candidate.name() == derived)
            && is_derived_sidecar(candidate, name, spec)
        {
            out.insert(derived, name.to_owned());
        }
    }

    out
}

pub fn expand(
    workloads: &[WorkloadType],
    spec: &SidecarSpec,
) -> Result<Vec<WorkloadType>, MeshError> {
    let mut out: Vec<WorkloadType> = Vec::with_capacity(workloads.len());

    for workload in workloads {
        out.push(workload.clone());

        let Some(mesh) = workload.mesh() else {
            continue;
        };

        // **The same rule as at ingest** (ADR-0084, determination 4). The
        // difference is a parameter: with `spec` an entry that is demonstrably
        // our derived sidecar does not count as a collision.
        if let Some(derived) = name_of_sidecar(workload, workloads, Some(spec))? {
            out.push(build(workload, &derived, mesh.port(), mesh.udp(), spec)?);
        }
    }

    Ok(out)
}

pub fn validate_names(workloads: &[WorkloadType]) -> Result<(), MeshError> {
    for workload in workloads {
        if workload.mesh().is_none() {
            continue;
        }
        name_of_sidecar(workload, workloads, None)?;
    }
    Ok(())
}

fn name_of_sidecar(
    workload: &WorkloadType,
    workloads: &[WorkloadType],
    spec: Option<&SidecarSpec>,
) -> Result<Option<String>, MeshError> {
    let name = workload.name();
    let derived = sidecar_name(name);

    if derived.len() > MAX_NAME {
        return Err(MeshError::NameTooLong {
            workload: name.to_owned(),
            derived,
        });
    }

    if let Some(existing) = workloads
        .iter()
        .find(|candidate| candidate.name() == derived)
    {
        if spec.is_some_and(|spec| is_derived_sidecar(existing, name, spec)) {
            return Ok(None);
        }
        return Err(MeshError::NameTaken {
            workload: name.to_owned(),
            derived,
        });
    }

    Ok(Some(derived))
}

fn is_derived_sidecar(candidate: &WorkloadType, workload: &str, spec: &SidecarSpec) -> bool {
    if candidate.image().reference() != spec.image() {
        return false;
    }

    let kinds: Vec<DependencyKind> = candidate
        .dependencies()
        .iter()
        .filter(|dependency| dependency.target() == workload)
        .map(|dependency| dependency.kind())
        .collect();

    kinds.contains(&DependencyKind::After) && kinds.contains(&DependencyKind::BindsTo)
}

fn build(
    workload: &WorkloadType,
    derived: &str,
    upstream_port: u16,
    mesh_udp: Option<u16>,
    spec: &SidecarSpec,
) -> Result<WorkloadType, MeshError> {
    use std::fmt::Write as _;

    let name = workload.name();
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <workloads xmlns=\"urn:tardigrade:workload:v1\">\n",
    );

    // `kind="service"`: a sidecar runs as long as its workload runs and is
    // never a one-off run. The class stays the default (`replicated`) — a proxy
    // has no single-writer constraint, even if its workload has one: it holds
    // no state.
    let _ = writeln!(xml, "  <workload name=\"{derived}\" kind=\"service\">");
    let _ = writeln!(xml, "    <image reference=\"{}\"/>", spec.image());

    // The derived unit is self-contained: it carries what it proxies for,
    // where it passes through to and where it reads its settings from. Without
    // that the sidecar process would have to look up its own definition — and
    // would thereby hang on a source that can be gone in a partition
    // (ADR-0019).
    //
    // **Here it stood that both thereby land in the Raft log and in the audit
    // trail (ADR-0020). That was false** and is withdrawn with ADR-0059: the
    // unit arises on the **node** and is written nowhere. What an auditor finds
    // in the log is `<mesh port="…"/>` in the definition; from that it is fully
    // reconstructible, but it is a computation and not an entry.
    // **From the constants, not as a literal** (see [`SIDECAR_INBOUND`]): the
    // agent lays the same three numbers into the rule set as the redirect
    // target, and a second source would let them run apart.
    let inbound = format!("0.0.0.0:{SIDECAR_INBOUND}");
    let outbound = format!("0.0.0.0:{SIDECAR_OUTBOUND}");
    let egress = format!("0.0.0.0:{SIDECAR_EGRESS}");

    xml.push_str("    <command>\n");
    for arg in [
        // **The program first**: `<command>` replaces the entrypoint and cmd
        // (schema, ADR-0003), so the line carries its own argv[0].
        PROGRAM_IN_CONTAINER,
        "--workload",
        name,
        "--upstream-port",
        &upstream_port.to_string(),
        // The three paths are **container-side** and therefore constants
        // (ADR-0059, determination 5). The agent mounts what lies behind them.
        "--socket",
        SOCKET_IN_CONTAINER,
        "--policy",
        EDGES_IN_CONTAINER,
        "--egress",
        EGRESS_IN_CONTAINER,
        "--active-role",
        ROLE_IN_CONTAINER,
        // The three ports the redirect means too (ADR-0012).
        //
        // The **outgoing** mesh port did not stand here at first: which peer
        // was meant no longer stands there behind a redirect. ADR-0060 decided
        // that — it comes from the kernel (`SO_ORIGINAL_DST`), the same source
        // as with egress and with an express difference: here the address is a
        // routing statement, not a permission.
        "--listen",
        &inbound,
        "--mesh-listen",
        &outbound,
        "--egress-listen",
        &egress,
        // **The node's trust domain**, not the sidecar's default. It searches
        // for its anchor with it (`bundle_for_trust_domain`); without this line
        // it took `cluster.local` and ended in every cluster with a different
        // domain with "no anchor for cluster.local".
        "--trust-domain",
        spec.trust_domain(),
    ] {
        let _ = writeln!(xml, "      <arg>{arg}</arg>");
    }

    // **UDP in the mesh** (ADR-0142, determinations 3 and 8) — only if this
    // workload has declared `<mesh udp="…">`. Without the declaration the
    // sidecar does not get the setting and opens no listener; ADR-0074 then
    // applies unchanged.
    //
    // **The path, not the port**: which local port the sidecar takes for which
    // peer stands in the file the agent writes from the slice (ADR-0040,
    // ADR-0073). Its own UDP port, by contrast, stands here — it is a
    // declaration of the workload and not a mapping.
    if let Some(udp) = mesh_udp {
        let _ = writeln!(xml, "      <arg>--mesh-udp</arg>");
        let _ = writeln!(xml, "      <arg>{MESH_UDP_IN_CONTAINER}</arg>");
        // **The listening port is the constant, not the declaration.** The
        // first build had `<mesh udp>` here, and that was wrong: then the
        // sending sidecar would have to know its peer's port, and that stands
        // in a definition this node does not have (ADR-0040).
        let _ = writeln!(xml, "      <arg>--mesh-udp-listen</arg>");
        let _ = writeln!(xml, "      <arg>0.0.0.0:{SIDECAR_MESH_UDP}</arg>");
        // And the number from the declaration is the **workload's** port — the
        // sidecar passes through to there, as with TCP.
        let _ = writeln!(xml, "      <arg>--mesh-udp-upstream</arg>");
        let _ = writeln!(xml, "      <arg>{udp}</arg>");
    }

    // **Who is affected stands at the sidecar and not in the file** (ADR-0066,
    // determination 2). Were the affectedness to stand in the file, a missing
    // file would mean "nobody is affected" — and a read error would lift the
    // active role for everyone. This way it means "no active role", and that is
    // the safe direction.
    if workload.class() == tg_defs::WorkloadClass::SingleWriter {
        xml.push_str("      <arg>--single-writer</arg>\n");
    }
    // **A property of the node, not of the workload** (ADR-0114,
    // determination 3). It therefore stands at the `SidecarSpec` like the image
    // and the trust domain, and not in the declaration.
    if spec.pin_shards {
        xml.push_str("      <arg>--pin-shards</arg>\n");
    }
    xml.push_str("    </command>\n");

    // The placement is taken over, **but it provides no co-location** — here
    // it once stood that the sidecar must thereby land on the same node as its
    // workload. Measured, that is false: the planner works per workload
    // (`placement`: `occupied` and `taken` are keyed by name), and `api` and
    // `api-proxy` are two of them. Inheriting the same constraints does not
    // mean getting the same node.
    //
    // Since ADR-0059 co-location arises from the **node** deriving — out of its
    // own slice. The placement is taken over nevertheless: it belongs to the
    // unit, and a document that keeps its provenance quiet would be harder to
    // read.
    if let Some(placement) = workload.placement() {
        let _ = writeln!(
            xml,
            "    <placement replicas=\"{}\" spread=\"{}\">",
            placement.replicas(),
            placement.spread()
        );
        for domain in placement.domains() {
            let _ = writeln!(
                xml,
                "      <domain level=\"{}\" value=\"{}\"/>",
                domain.level, domain.value
            );
        }
        if let Some(pin) = placement.pin() {
            let _ = writeln!(xml, "      <pin node=\"{pin}\"/>");
        }
        xml.push_str("    </placement>\n");
    }

    // The coupling from ADR-0009, in this order in the document. Both edges
    // point at the workload, none back.
    xml.push_str("    <dependencies>\n");
    let _ = writeln!(xml, "      <after ref=\"{name}\"/>");
    let _ = writeln!(xml, "      <bindsTo ref=\"{name}\"/>");
    xml.push_str("    </dependencies>\n");
    xml.push_str("  </workload>\n</workloads>\n");

    let set = from_str(&xml).map_err(|err| MeshError::Malformed {
        detail: err.to_string(),
    })?;

    set.workloads()
        .first()
        .cloned()
        .ok_or_else(|| MeshError::Malformed {
            detail: "the produced document contains no workload".to_owned(),
        })
}
