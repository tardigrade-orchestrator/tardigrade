//! The seam to the node network (ADR-0012).
//!
//! `tg-runtime` starts containers, `tg-net` builds networks -- and neither of
//! the two hangs on the other. What a container needs is a single path: the
//! network namespace it is put into (ADR-0003). Who produces it is not visible
//! from here, and that is the intention -- the address assignment (ADR-0039),
//! the veth pair and the rule set (ADR-0038) belong to the agent, not to the
//! runtime path.
//!
//! # Without an attachment it stays as it was
//!
//! If there is none, the spec sets **no** path, and the runtime then lays out
//! a fresh, empty network namespace. That is no network, but no hole either:
//! the container sees only its `lo`. A fallback to the host's network would be
//! the dangerous variant and expressly does not happen -- a workload without
//! an address is inconvenient, one in the node's network is a security
//! finding.

use std::path::PathBuf;

pub use tg_defs::Probe;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub netns: PathBuf,
    pub resolv_conf: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Mesh {
    pub spec: tg_model::SidecarSpec,
    pub mounts: Vec<crate::bundle::VolumeMount>,
    pub overhead: std::path::PathBuf,
}

pub trait Devices: Send + Sync {
    fn assign(
        &self,
        workload: &tg_defs::generated::WorkloadType,
        instance: u32,
    ) -> Result<Option<crate::cdi::Edits>, String>;

    fn release(&self, container: &str);

    fn held(&self) -> Vec<String>;
}

pub trait Sockets: Send + Sync {
    fn ensure(&self, container: &str) -> Result<std::path::PathBuf, String>;

    fn held(&self) -> Vec<String>;

    fn release(&self, container: &str);
}

pub trait Secrets: Send + Sync {
    fn ensure(&self, container: &str, workload: &str) -> Result<Option<PathBuf>, String>;

    fn held(&self) -> Vec<String>;

    fn release(&self, container: &str);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Extras<'a> {
    pub network: Option<&'a Attachment>,
    pub run_as: Option<u32>,
    pub no_seccomp: bool,
    pub userns: Option<crate::userns::Mapping>,
    pub sidecar_memory: Option<u64>,
    pub generation: u64,
    pub devices: Option<&'a crate::cdi::Edits>,
}

pub trait Wiring: Send + Sync {
    fn attach(&self, workload: &str, instance: u32) -> Result<Attachment, String>;

    fn leased(&self) -> Vec<String>;

    fn release(&self, container: &str);

    fn enforce(&self, netns: &str, workload: &str);

    fn ensure_baseline(&self, netns: &str);

    fn probe(&self, container: &str, probe: Probe<'_>) -> Result<(), String>;
}

pub trait Credentials: Send + Sync {
    fn for_registry(&self, registry: &str, workload: &str) -> Option<RegistryLogin>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryLogin {
    Basic {
        user: String,
        password: String,
    },
    Bearer {
        token: String,
    },
}

impl RegistryLogin {
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("basic ") {
            let (user, password) = rest.split_once(':')?;
            if user.is_empty() {
                return None;
            }
            return Some(Self::Basic {
                user: user.to_owned(),
                password: password.to_owned(),
            });
        }
        if let Some(token) = line.strip_prefix("bearer ") {
            let token = token.trim();
            if token.is_empty() {
                return None;
            }
            return Some(Self::Bearer {
                token: token.to_owned(),
            });
        }
        None
    }
}
