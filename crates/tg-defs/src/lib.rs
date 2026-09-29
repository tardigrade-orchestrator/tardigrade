//! Definition types generated from XSD, and the loader for them.
//!
//! The contract between XML definition and code:
//!
//! - `schema/workload.xsd` is the source of truth.
//! - `cargo xtask codegen` produces [`generated`] from it; the file is checked
//!   in and is checked against the XSD by `cargo xtask ci`.
//! - [`from_str`] / [`from_path`] read XML. The schema's facets (`xs:pattern`,
//!   `minLength`/`maxLength`, `minInclusive`/`maxInclusive`, `xs:enumeration`)
//!   and required fields are **enforced** in the process, not merely
//!   documented.
//!
//! Above the generated types lies a thin access layer ([`WorkloadSet`] and
//! neighbours). It contains no logic but keeps downstream crates away from the
//! codegen's internals. If the XSD changes so that the mapping no longer fits,
//! the compiler breaks here — a deliberate coupling meant to catch schema
//! drift immediately instead of letting it pass unnoticed.
//!
//! This crate validates **structurally** only. Referential integrity (does a
//! dependency point at an existing workload?) and acyclicity are graph
//! properties that require seeing all workloads together, and are handled by
//! a separate crate (`tg-model`) that builds the dependency graph.

#![forbid(unsafe_code)]
// **No panic-capable call on the production path**: a panic should cost only
// its own task, not bring down the whole node -- and that is a state an
// operator would only see reflected in a metric, not as a crash. `not(test)`,
// because the unit tests in `src` need them; the guard lies in
// `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

pub mod generated;

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use xsd_parser_types::quick_xml::{DeserializeSync as _, SerializeSync as _, SliceReader};

pub use crate::generated::{KindType as Kind, PullPolicyType as PullPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum WorkloadClass {
    #[default]
    Replicated,
    SingleWriter,
}

impl WorkloadClass {
    #[must_use]
    pub fn is_single_writer(self) -> bool {
        matches!(self, Self::SingleWriter)
    }
}

impl From<Option<generated::WorkloadClassType>> for WorkloadClass {
    fn from(declared: Option<generated::WorkloadClassType>) -> Self {
        match declared {
            Some(generated::WorkloadClassType::SingleWriter) => Self::SingleWriter,
            Some(generated::WorkloadClassType::Replicated) | None => Self::Replicated,
        }
    }
}

#[derive(Debug)]
pub enum LoadError {
    Io {
        path: PathBuf,
        source: io::Error,
    },
    Invalid {
        origin: String,
        detail: String,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "definition {} not readable: {source}", path.display())
            }
            Self::Invalid { origin, detail } => {
                write!(f, "definition {origin} is invalid: {detail}")
            }
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Invalid { .. } => None,
        }
    }
}

pub fn from_str(xml: &str) -> Result<WorkloadSet, LoadError> {
    parse(xml, "<input>")
}

pub fn from_path(path: impl AsRef<Path>) -> Result<WorkloadSet, LoadError> {
    let path = path.as_ref();
    let xml = fs::read_to_string(path).map_err(|source| LoadError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    parse(&xml, &path.display().to_string())
}

const NAMESPACE_V1: &[u8] = b"urn:tardigrade:workload:v1";

const ROOT_LOCAL_NAME: &[u8] = b"workloads";

fn parse(xml: &str, origin: &str) -> Result<WorkloadSet, LoadError> {
    let invalid = |detail: String| LoadError::Invalid {
        origin: origin.to_owned(),
        detail,
    };

    check_root(xml).map_err(&invalid)?;

    let mut reader = SliceReader::new(xml);

    generated::Workloads::deserialize(&mut reader)
        .map(WorkloadSet)
        .map_err(|source| invalid(source.to_string()))
}

fn check_root(xml: &str) -> Result<(), String> {
    use quick_xml::NsReader;
    use quick_xml::events::Event;
    use quick_xml::name::ResolveResult;

    let mut reader = NsReader::from_str(xml);

    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|err| format!("XML not readable: {err}"))?;

        let (start, start_kind) = match event {
            Event::Start(start) => (start, RootTag::Open),
            Event::Empty(start) => (start, RootTag::Closed),
            Event::Eof => return Err("document contains no root element".to_owned()),
            _ => continue,
        };

        let local = start.local_name();
        if local.as_ref() != ROOT_LOCAL_NAME {
            return Err(format!(
                "root element is <{}>, expected is <workloads>",
                String::from_utf8_lossy(local.as_ref())
            ));
        }

        match resolved {
            ResolveResult::Bound(ns) if ns.as_ref() == NAMESPACE_V1 => {}
            ResolveResult::Bound(ns) => {
                return Err(format!(
                    "root element lies in namespace '{}', expected is '{}'",
                    String::from_utf8_lossy(ns.as_ref()),
                    String::from_utf8_lossy(NAMESPACE_V1)
                ));
            }
            ResolveResult::Unbound => {
                return Err(format!(
                    "root element has no namespace, expected is '{}'",
                    String::from_utf8_lossy(NAMESPACE_V1)
                ));
            }
            ResolveResult::Unknown(prefix) => {
                return Err(format!(
                    "prefix '{}' of the root element is not declared",
                    String::from_utf8_lossy(&prefix)
                ));
            }
        }

        // An empty root element (`<workloads/>`) has no end still to come — the
        // schema rejects it anyway (`minOccurs` at the workload), but the
        // trailing check below would otherwise hang on the first event.
        let depth = usize::from(matches!(start_kind, RootTag::Open));
        return check_after_root(&mut reader, depth);
    }
}

enum RootTag {
    Open,
    Closed,
}

fn check_after_root(
    reader: &mut quick_xml::NsReader<&[u8]>,
    mut depth: usize,
) -> Result<(), String> {
    use quick_xml::events::Event;

    loop {
        let event = reader
            .read_event()
            .map_err(|err| format!("XML not readable: {err}"))?;

        if depth > 0 {
            match event {
                Event::Start(_) => depth += 1,
                Event::End(_) => depth -= 1,
                Event::Eof => return Ok(()),
                _ => {}
            }
            continue;
        }

        match event {
            Event::Eof => return Ok(()),
            // `Misc*` per XML 1.0.
            Event::Comment(_) | Event::PI(_) => {}
            Event::Text(text) if text.iter().all(u8::is_ascii_whitespace) => {}
            Event::Start(start) | Event::Empty(start) => {
                return Err(format!(
                    "another element <{}> stands after the root element — a \
                     document with two roots is not XML. Two definitions belong \
                     in two invocations, not concatenated",
                    String::from_utf8_lossy(start.local_name().as_ref())
                ));
            }
            other => {
                return Err(format!(
                    "further content stands after the root element ({}) — \
                     permitted are only comments, processing instructions and \
                     whitespace",
                    match other {
                        Event::Text(_) => "text",
                        Event::CData(_) => "CDATA",
                        Event::Decl(_) => "an XML declaration",
                        Event::DocType(_) => "a document type declaration",
                        _ => "unknown",
                    }
                ));
            }
        }
    }
}

pub fn workload_to_xml(workload: &generated::WorkloadType) -> Result<String, LoadError> {
    let set = generated::WorkloadSetType {
        content: generated::WorkloadSetTypeContent {
            workload: vec![workload.clone()],
        },
    };

    let mut buffer = Vec::new();
    let mut writer = quick_xml::Writer::new(&mut buffer);
    set.serialize("tg:workloads", &mut writer)
        .map_err(|err| LoadError::Invalid {
            origin: workload.name().to_owned(),
            detail: format!("not serializable: {err}"),
        })?;

    let body = String::from_utf8(buffer).map_err(|err| LoadError::Invalid {
        origin: workload.name().to_owned(),
        detail: format!("serialization is not UTF-8: {err}"),
    })?;

    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{body}\n"
    ))
}

#[derive(Debug, Clone, PartialEq)]
pub struct WorkloadSet(generated::Workloads);

impl WorkloadSet {
    #[must_use]
    pub fn workloads(&self) -> &[generated::WorkloadType] {
        &self.0.content.workload
    }
}

pub trait WorkloadExt {
    fn name(&self) -> &str;
    fn kind(&self) -> Kind;
    fn class(&self) -> WorkloadClass;
    fn image(&self) -> &generated::ImageType;
    fn command(&self) -> Vec<&str>;
    fn resources(&self) -> Option<&generated::ResourcesType>;
    fn placement(&self) -> Option<&generated::PlacementType>;
    fn mesh(&self) -> Option<&generated::MeshType>;
    fn readiness(&self) -> Option<Probe<'_>>;
    fn volumes(&self) -> &[generated::VolumeType];
    fn devices(&self) -> &[generated::DeviceType];
    fn dependencies(&self) -> Vec<Dependency<'_>>;
}

impl WorkloadExt for generated::WorkloadType {
    fn name(&self) -> &str {
        &self.name.0
    }

    fn kind(&self) -> Kind {
        self.kind.clone()
    }

    fn class(&self) -> WorkloadClass {
        self.class.clone().into()
    }

    fn image(&self) -> &generated::ImageType {
        &self.content.image
    }

    fn command(&self) -> Vec<&str> {
        self.content.command.as_ref().map_or_else(Vec::new, |cmd| {
            cmd.content.arg.iter().map(|arg| arg.0.as_str()).collect()
        })
    }

    fn resources(&self) -> Option<&generated::ResourcesType> {
        self.content.resources.as_ref()
    }

    fn placement(&self) -> Option<&generated::PlacementType> {
        self.content.placement.as_ref()
    }

    fn mesh(&self) -> Option<&generated::MeshType> {
        self.content.mesh.as_ref()
    }

    fn readiness(&self) -> Option<Probe<'_>> {
        let declared = self.content.readiness.as_ref()?;
        // `try_into` and no `as`: the facet allows 1..=65535, but the codegen
        // carries `u32`. An `as` would truncate a value that cannot exist — and
        // would truncate it silently, should the facet one day disappear after
        // all.
        let port = u16::try_from(declared.port.0).ok()?;
        Some(Probe {
            port,
            path: declared.path.as_ref().map(|path| path.0.as_str()),
        })
    }

    fn volumes(&self) -> &[generated::VolumeType] {
        self.content
            .volumes
            .as_ref()
            .map_or(&[], |volumes| volumes.content.volume.as_slice())
    }

    fn devices(&self) -> &[generated::DeviceType] {
        self.content
            .devices
            .as_ref()
            .map_or(&[], |devices| devices.content.device.as_slice())
    }

    fn dependencies(&self) -> Vec<Dependency<'_>> {
        self.content
            .dependencies
            .as_ref()
            .map(|deps| {
                deps.content
                    .iter()
                    .map(Dependency::from_generated)
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub trait MeshExt {
    fn port(&self) -> u16;

    fn udp(&self) -> Option<u16>;
}

impl MeshExt for generated::MeshType {
    fn port(&self) -> u16 {
        // The facet in the XSD bounds to 1..=65535; the codegen carries it as
        // u32. The value range is thereby already enforced on reading, and this
        // conversion cannot fail.
        u16::try_from(self.port.0).unwrap_or(u16::MAX)
    }

    fn udp(&self) -> Option<u16> {
        // The same facet, the same reason.
        self.udp
            .as_ref()
            .map(|port| u16::try_from(port.0).unwrap_or(u16::MAX))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VolumeMode {
    ReadWrite,
    ReadOnly,
}

impl std::fmt::Display for VolumeMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ReadWrite => "readWrite",
            Self::ReadOnly => "readOnly",
        })
    }
}

pub trait VolumeExt {
    fn name(&self) -> &str;
    fn path(&self) -> &str;
    fn mode(&self) -> VolumeMode;
    fn source(&self) -> Option<&str>;
    fn size(&self) -> Option<u64>;
}

impl VolumeExt for generated::VolumeType {
    fn name(&self) -> &str {
        &self.name.0
    }

    fn path(&self) -> &str {
        &self.path.0
    }

    fn mode(&self) -> VolumeMode {
        match self.mode {
            generated::VolumeModeType::ReadWrite => VolumeMode::ReadWrite,
            generated::VolumeModeType::ReadOnly => VolumeMode::ReadOnly,
        }
    }

    fn source(&self) -> Option<&str> {
        self.source.as_ref().map(|reference| reference.0.as_str())
    }

    fn size(&self) -> Option<u64> {
        self.size.as_ref().map(|bytes| bytes.0)
    }
}

pub trait ImageExt {
    fn reference(&self) -> &str;
    fn pull_policy(&self) -> Option<PullPolicy>;
}

impl ImageExt for generated::ImageType {
    fn reference(&self) -> &str {
        &self.reference.0
    }

    fn pull_policy(&self) -> Option<PullPolicy> {
        self.pull_policy.clone()
    }
}

pub trait ResourcesExt {
    fn millicores(&self) -> Option<u32>;
    fn memory_bytes(&self) -> Option<u64>;
}

impl ResourcesExt for generated::ResourcesType {
    fn millicores(&self) -> Option<u32> {
        self.content.cpu.as_ref().map(|cpu| cpu.millicores.0)
    }

    fn memory_bytes(&self) -> Option<u64> {
        self.content.memory.as_ref().map(|mem| mem.bytes.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyKind {
    After,
    Before,
    Requires,
    Wants,
    BindsTo,
    Conflicts,
}

impl DependencyKind {
    #[must_use]
    pub fn is_ordering(self) -> bool {
        matches!(self, Self::After | Self::Before)
    }

    #[must_use]
    pub fn is_requirement(self) -> bool {
        !self.is_ordering()
    }

    #[must_use]
    pub fn as_element(self) -> &'static str {
        match self {
            Self::After => "<after>",
            Self::Before => "<before>",
            Self::Requires => "<requires>",
            Self::Wants => "<wants>",
            Self::BindsTo => "<bindsTo>",
            Self::Conflicts => "<conflicts>",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe<'a> {
    pub port: u16,
    pub path: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dependency<'a> {
    kind: DependencyKind,
    target: &'a str,
}

impl<'a> Dependency<'a> {
    fn from_generated(content: &'a generated::DependenciesTypeContent) -> Self {
        use generated::DependenciesTypeContent as C;

        let (kind, target) = match content {
            C::After(r) => (DependencyKind::After, r),
            C::Before(r) => (DependencyKind::Before, r),
            C::Requires(r) => (DependencyKind::Requires, r),
            C::Wants(r) => (DependencyKind::Wants, r),
            C::BindsTo(r) => (DependencyKind::BindsTo, r),
            C::Conflicts(r) => (DependencyKind::Conflicts, r),
        };

        Self {
            kind,
            target: &target.ref_.0,
        }
    }

    #[must_use]
    pub fn kind(self) -> DependencyKind {
        self.kind
    }

    #[must_use]
    pub fn target(self) -> &'a str {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DomainLevel {
    Site,
    Hall,
    Rack,
}

impl DomainLevel {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Site => "site",
            Self::Hall => "hall",
            Self::Rack => "rack",
        }
    }
}

impl From<generated::DomainLevelType> for DomainLevel {
    fn from(level: generated::DomainLevelType) -> Self {
        match level {
            generated::DomainLevelType::Site => Self::Site,
            generated::DomainLevelType::Hall => Self::Hall,
            generated::DomainLevelType::Rack => Self::Rack,
        }
    }
}

impl fmt::Display for DomainLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainConstraint {
    pub level: DomainLevel,
    pub value: String,
}

pub trait PlacementExt {
    fn replicas(&self) -> u32;
    fn spread(&self) -> DomainLevel;
    fn domains(&self) -> Vec<DomainConstraint>;
    fn pin(&self) -> Option<&str>;
}

impl PlacementExt for generated::PlacementType {
    fn replicas(&self) -> u32 {
        self.replicas.as_ref().map_or(1, |value| value.0)
    }

    fn spread(&self) -> DomainLevel {
        self.spread
            .clone()
            .map_or(DomainLevel::Rack, DomainLevel::from)
    }

    fn domains(&self) -> Vec<DomainConstraint> {
        self.content
            .domain
            .iter()
            .map(|constraint| DomainConstraint {
                level: constraint.level.clone().into(),
                value: constraint.value.0.clone(),
            })
            .collect()
    }

    fn pin(&self) -> Option<&str> {
        self.content.pin.as_ref().map(|pin| pin.node.0.as_str())
    }
}
