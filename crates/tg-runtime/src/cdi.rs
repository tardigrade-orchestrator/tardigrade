//! Devices from a CDI spec.
//!
//! # What this module is
//!
//! The reading of a node's **Container Device Interface** specifications and
//! the mapping of what of them can take effect in this tree onto OCI fields.
//! It decides nothing about placement; it says which devices there are and
//! what their container gets.
//!
//! # The trust boundary
//!
//! A CDI spec is a **file that determines which device nodes a container
//! gets**, and it is read as root. That is why everything here is strict that
//! can be strict:
//!
//! - **`deny_unknown_fields` on every type.** A field we do not know aborts
//!   the file -- and is at the same time the generation check: a CDI that
//!   adds something does not keep it quiet.
//! - **Four sections are refused** instead of passed over: `hooks` (a program
//!   that root executes), `netDevices`, `intelRdt`, `additionalGids`.
//! - **Paths must lie under `/dev`** and must not contain a `..`. Without
//!   that a spec would lay a device node over a file of the rootfs.
//!
//! # What expressly does **not** arise here
//!
//! `linux.resources.devices` -- the cgroup device rules. In cgroup v2 the
//! controller is eBPF-based and thereby ruled out by this project's "no
//! eBPF" constraint; `bundle.rs` aborts if a spec carries them. What CDI
//! describes as `permissions` therefore becomes the **file mode**, and the
//! barrier is the **presence** of the node -- it carries, because a
//! container has no `CAP_MKNOD` (guard in `bundle.rs`).
//!
//! # JSON, not YAML
//!
//! No YAML parser lies in the tree, and this file is not the place at which
//! one takes one in. The vendor tools can do JSON
//! (`nvidia-ctk cdi generate --format=json`); a file we cannot read is
//! **reported** and not passed over.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use oci_spec::runtime::{LinuxDevice, LinuxDeviceBuilder, LinuxDeviceType, Mount, MountBuilder};
use serde::Deserialize;

pub const RESOURCE_PREFIX: &str = tg_model::Resources::DEVICE_PREFIX;

pub const DEFAULT_DIRS: [&str; 2] = ["/etc/cdi", "/var/run/cdi"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub path: PathBuf,
    pub reason: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.path.display(), self.reason)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub path: PathBuf,
    pub host_path: PathBuf,
    pub kind: LinuxDeviceType,
    pub major: i64,
    pub minor: i64,
    pub file_mode: u32,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}

impl Node {
    fn to_oci(&self) -> Result<LinuxDevice, String> {
        LinuxDeviceBuilder::default()
            .path(self.path.clone())
            .typ(self.kind)
            .major(self.major)
            .minor(self.minor)
            .file_mode(self.file_mode)
            .uid(self.uid.unwrap_or(0))
            .gid(self.gid.unwrap_or(0))
            .build()
            .map_err(|err| format!("device entry {}: {err}", self.path.display()))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Edits {
    pub nodes: Vec<Node>,
    pub mounts: Vec<(PathBuf, PathBuf, Vec<String>)>,
    pub env: Vec<String>,
}

impl Edits {
    fn absorb(&mut self, other: Self) {
        self.nodes.extend(other.nodes);
        self.mounts.extend(other.mounts);
        self.env.extend(other.env);
    }

    pub fn oci_devices(&self) -> Result<Vec<LinuxDevice>, String> {
        self.nodes.iter().map(Node::to_oci).collect()
    }

    pub fn oci_mounts(&self) -> Result<Vec<Mount>, String> {
        self.mounts
            .iter()
            .map(|(host, container, options)| {
                let mut options = options.clone();
                if !options.iter().any(|o| o == "bind" || o == "rbind") {
                    options.push("bind".to_owned());
                }
                MountBuilder::default()
                    .source(host.clone())
                    .destination(container.clone())
                    .typ("bind")
                    .options(options)
                    .build()
                    .map_err(|err| format!("mount {}: {err}", container.display()))
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub kind: String,
    pub name: String,
    pub edits: Edits,
}

impl Device {
    #[must_use]
    pub fn qualified(&self) -> String {
        format!("{}={}", self.kind, self.name)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Catalogue {
    devices: BTreeMap<String, Device>,
}

impl Catalogue {
    #[must_use]
    pub fn read(dirs: &[PathBuf]) -> (Self, Vec<Finding>) {
        let mut catalogue = Self::default();
        let mut findings = Vec::new();

        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(dir) else {
                // No directory, no finding: the normal case.
                continue;
            };

            // **Sorted**, so that two nodes with the same content read the
            // same and a duplicate name always objects to the same file.
            let mut paths: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.is_file())
                .collect();
            paths.sort();

            for path in paths {
                match Self::read_file(&path) {
                    Ok(devices) => {
                        for device in devices {
                            let key = device.qualified();
                            // **One name, one device** (the rule from 10c).
                            // Two files that describe the same device are an
                            // ambiguity -- and which applies would otherwise
                            // hang on who was read first.
                            if catalogue.devices.contains_key(&key) {
                                findings.push(Finding {
                                    path: path.clone(),
                                    reason: format!(
                                        "{key} is already described by another \
                                         spec -- which applies would be a \
                                         question of the reading order"
                                    ),
                                });
                                continue;
                            }
                            catalogue.devices.insert(key, device);
                        }
                    }
                    Err(reason) => findings.push(Finding { path, reason }),
                }
            }
        }

        (catalogue, findings)
    }

    fn read_file(path: &Path) -> Result<Vec<Device>, String> {
        let text = std::fs::read_to_string(path).map_err(|err| format!("not readable: {err}"))?;

        // The YAML case gets a sentence of its own: it otherwise looks like a
        // syntax error, and the operator searches in the file instead of at
        // the tool (determination 4).
        if path.extension().is_some_and(|e| e == "yaml" || e == "yml") {
            return Err("YAML is not read (ADR-0143 determination 4) -- the \
                 vendor tool can do JSON, such as `nvidia-ctk cdi generate \
                 --format=json`"
                .to_owned());
        }

        let spec: SpecFile =
            serde_json::from_str(&text).map_err(|err| format!("no valid CDI JSON: {err}"))?;
        spec.into_devices()
    }

    #[must_use]
    pub fn inventory(&self) -> BTreeMap<String, u64> {
        let mut counts: BTreeMap<String, u64> = BTreeMap::new();
        for device in self.devices.values() {
            *counts
                .entry(format!("{RESOURCE_PREFIX}{}", device.kind))
                .or_default() += 1;
        }
        counts
    }

    #[must_use]
    pub fn kinds(&self) -> Vec<&str> {
        let mut kinds: Vec<&str> = self
            .devices
            .values()
            .map(|device| device.kind.as_str())
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        kinds
    }

    #[must_use]
    pub fn names_of(&self, kind: &str) -> Vec<&str> {
        self.devices
            .values()
            .filter(|device| device.kind == kind)
            .map(|device| device.name.as_str())
            .collect()
    }

    #[must_use]
    pub fn get(&self, qualified: &str) -> Option<&Device> {
        self.devices.get(qualified)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

// ===================== The file format =====================
//
// Every type carries `deny_unknown_fields`. The four refused sections stand
// expressly as fields in it instead of being caught by the unknown-field
// error: that way the message names the section and the reason, and not
// merely "unknown field" (ADR-0143 determinations 1 and 3).

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SpecFile {
    cdi_version: String,
    kind: String,
    #[serde(default)]
    annotations: Option<BTreeMap<String, serde_json::Value>>,
    devices: Vec<DeviceEntry>,
    #[serde(default)]
    container_edits: Option<ContainerEdits>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeviceEntry {
    name: String,
    #[serde(default)]
    annotations: Option<BTreeMap<String, serde_json::Value>>,
    container_edits: ContainerEdits,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ContainerEdits {
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    device_nodes: Vec<DeviceNode>,
    #[serde(default)]
    mounts: Vec<MountEntry>,
    // The four that are refused. `serde_json::Value`, because their content
    // does not interest us -- only their presence.
    #[serde(default)]
    hooks: Vec<serde_json::Value>,
    #[serde(default)]
    net_devices: Vec<serde_json::Value>,
    #[serde(default)]
    intel_rdt: Option<serde_json::Value>,
    #[serde(default)]
    additional_gids: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct DeviceNode {
    path: String,
    #[serde(default)]
    host_path: Option<String>,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    major: Option<i64>,
    #[serde(default)]
    minor: Option<i64>,
    #[serde(default)]
    file_mode: Option<i64>,
    #[serde(default)]
    permissions: Option<String>,
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    gid: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct MountEntry {
    host_path: String,
    container_path: String,
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    options: Vec<String>,
}

impl SpecFile {
    fn into_devices(self) -> Result<Vec<Device>, String> {
        // **Accepted and not read** (determination 1): in CDI annotations do
        // not act on the container at all. Refusing them would be strictness
        // without a statement, reading them would give nothing to do.
        drop(self.annotations);
        check_version(&self.cdi_version)?;
        check_kind(&self.kind)?;

        let global = match self.container_edits {
            Some(edits) => edits.into_edits("containerEdits")?,
            None => Edits::default(),
        };

        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut devices = Vec::with_capacity(self.devices.len());
        for entry in self.devices {
            drop(entry.annotations); // as above
            check_device_name(&entry.name)?;
            if !seen.insert(entry.name.clone()) {
                return Err(format!(
                    "the device `{}` stands twice in the same spec",
                    entry.name
                ));
            }

            let mut edits = global.clone();
            edits.absorb(
                entry
                    .container_edits
                    .into_edits(&format!("devices[{}]", entry.name))?,
            );

            if edits.nodes.is_empty() {
                return Err(format!(
                    "the device `{}` describes not a single device node -- \
                     there would be nothing to give",
                    entry.name
                ));
            }

            devices.push(Device {
                kind: self.kind.clone(),
                name: entry.name,
                edits,
            });
        }

        if devices.is_empty() {
            return Err("the spec names no device".to_owned());
        }
        Ok(devices)
    }
}

impl ContainerEdits {
    fn into_edits(self, where_: &str) -> Result<Edits, String> {
        // **Refused instead of passed over** (determinations 1 and 3). Every
        // case names itself, so that an operator knows what to cut.
        if !self.hooks.is_empty() {
            return Err(format!(
                "{where_} carries {} hook(s). A hook is a program the runtime \
                 executes as root, and it is not executed here (ADR-0143 \
                 determination 3). `nvidia-ctk`'s spec carries them -- cut \
                 them, and set the library paths via `env`",
                self.hooks.len()
            ));
        }
        if !self.net_devices.is_empty() {
            return Err(format!(
                "{where_} carries `netDevices`. Pushing an interface into the \
                 namespace would reach into ADR-0012 and ADR-0093"
            ));
        }
        if self.intel_rdt.is_some() {
            return Err(format!(
                "{where_} carries `intelRdt`. That is resctrl, that is \
                 isolation, and this tree does not enforce it"
            ));
        }
        if !self.additional_gids.is_empty() {
            return Err(format!(
                "{where_} carries `additionalGids`. That would change the \
                 process's identity (ADR-0017)"
            ));
        }

        for variable in &self.env {
            if !variable.contains('=') {
                return Err(format!(
                    "{where_}: `{variable}` is no assignment `NAME=VALUE`"
                ));
            }
        }

        let nodes = self
            .device_nodes
            .into_iter()
            .map(|node| node.into_node(where_))
            .collect::<Result<Vec<_>, _>>()?;

        let mounts = self
            .mounts
            .into_iter()
            .map(|mount| mount.into_mount(where_))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Edits {
            nodes,
            mounts,
            env: self.env,
        })
    }
}

impl DeviceNode {
    fn into_node(self, where_: &str) -> Result<Node, String> {
        let path = check_device_path(where_, &self.path)?;
        let host_path = match &self.host_path {
            Some(host) => check_device_path(where_, host)?,
            None => path.clone(),
        };

        // **The host node must exist.** If it is missing, the runtime would
        // otherwise fail only at creation -- and for the workload, not for
        // whoever laid the spec down.
        if !host_path.exists() {
            return Err(format!(
                "{where_}: {} does not exist on this host",
                host_path.display()
            ));
        }

        let kind = match self.kind.as_deref() {
            None | Some("c") => LinuxDeviceType::C,
            Some("b") => LinuxDeviceType::B,
            Some("u") => LinuxDeviceType::U,
            Some(other) => {
                return Err(format!(
                    "{where_}: device type `{other}` -- permitted are `c`, \
                     `b` and `u`; a FIFO or a socket is no device"
                ));
            }
        };

        let (Some(major), Some(minor)) = (self.major, self.minor) else {
            return Err(format!(
                "{where_}: {} names no major/minor number -- without them \
                 the node cannot be created",
                path.display()
            ));
        };
        if major < 0 || minor < 0 {
            return Err(format!(
                "{where_}: {} names a negative device number ({major}:{minor})",
                path.display()
            ));
        }

        let file_mode = file_mode_for(where_, &path, self.file_mode, self.permissions.as_deref())?;

        Ok(Node {
            path,
            host_path,
            kind,
            major,
            minor,
            file_mode,
            uid: self.uid,
            gid: self.gid,
        })
    }
}

impl MountEntry {
    fn into_mount(self, where_: &str) -> Result<(PathBuf, PathBuf, Vec<String>), String> {
        // **A mount's type is not taken over.** CDI permits it; here every
        // mount is a bind mount (ADR-0143 determination 1), and a `tmpfs` out
        // of a device file would be something other than what the spec
        // purports to describe.
        if let Some(kind) = &self.kind
            && kind != "bind"
            && kind != "none"
        {
            return Err(format!(
                "{where_}: mount of type `{kind}` -- here every mount of a \
                 device is a bind mount"
            ));
        }

        let host = check_absolute(where_, &self.host_path)?;
        let container = check_absolute(where_, &self.container_path)?;
        if !host.exists() {
            return Err(format!(
                "{where_}: {} does not exist on this host",
                host.display()
            ));
        }

        Ok((host, container, self.options))
    }
}

// ===================== The checks =====================

fn check_version(version: &str) -> Result<(), String> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(format!("`cdiVersion` is `{version}` and not `X.Y.Z`"));
    }
    Ok(())
}

fn check_kind(kind: &str) -> Result<(), String> {
    let Some((vendor, class)) = kind.split_once('/') else {
        return Err(format!("`kind` is `{kind}` and not `vendor.tld/class`"));
    };
    if !vendor.contains('.') {
        return Err(format!(
            "`kind` is `{kind}`; the vendor part `{vendor}` carries no dot \
             and is thereby no domain name"
        ));
    }
    if kind.split('/').count() != 2 {
        return Err(format!("`kind` is `{kind}` and carries more than one `/`"));
    }
    for (label, segment) in [("vendor", vendor), ("class", class)] {
        if segment.is_empty() {
            return Err(format!("`kind` is `{kind}`; the {label} part is empty"));
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
        {
            return Err(format!(
                "`kind` is `{kind}`; the {label} part carries a character \
                 that has no business in a resource name"
            ));
        }
    }
    Ok(())
}

fn check_device_name(name: &str) -> Result<(), String> {
    let bytes = name.as_bytes();
    let ends_alnum = |b: Option<&u8>| b.is_some_and(u8::is_ascii_alphanumeric);
    if !ends_alnum(bytes.first()) || !ends_alnum(bytes.last()) {
        return Err(format!(
            "the device name `{name}` does not begin or end alphanumerically"
        ));
    }
    if !bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_' || *b == b'.')
    {
        return Err(format!(
            "the device name `{name}` carries a forbidden character"
        ));
    }
    Ok(())
}

fn check_absolute(where_: &str, raw: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(raw);
    if !path.is_absolute() {
        return Err(format!("{where_}: `{raw}` is no absolute path"));
    }
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!("{where_}: `{raw}` carries a `..`"));
    }
    Ok(path)
}

fn check_device_path(where_: &str, raw: &str) -> Result<PathBuf, String> {
    let path = check_absolute(where_, raw)?;
    if !path.starts_with("/dev/") {
        return Err(format!(
            "{where_}: the device node `{raw}` does not lie under `/dev/` \
             -- there it would cover a file of the rootfs"
        ));
    }
    Ok(path)
}

fn file_mode_for(
    where_: &str,
    path: &Path,
    file_mode: Option<i64>,
    permissions: Option<&str>,
) -> Result<u32, String> {
    let from_permissions = match permissions {
        None => None,
        Some(text) => {
            let mut mode = 0u32;
            let mut seen = BTreeSet::new();
            for character in text.chars() {
                if !seen.insert(character) {
                    return Err(format!(
                        "{where_}: `permissions` is `{text}` and names `{character}` twice"
                    ));
                }
                match character {
                    'r' => mode |= 0o444,
                    'w' => mode |= 0o222,
                    // **`m` falls away without consequence**: it is the
                    // cgroup permission to `mknod`, and the capability is
                    // missing anyway.
                    'm' => {}
                    other => {
                        return Err(format!(
                            "{where_}: `permissions` is `{text}`; `{other}` \
                             is neither `r`, `w` nor `m`"
                        ));
                    }
                }
            }
            if mode == 0 {
                return Err(format!(
                    "{where_}: `permissions` is `{text}` and permits neither \
                     reading nor writing -- the node would be useless"
                ));
            }
            Some(mode)
        }
    };

    let declared = match file_mode {
        None => None,
        Some(mode) => Some(
            u32::try_from(mode)
                .map_err(|_| format!("{where_}: `fileMode` is {mode} and thereby no file mode"))?,
        ),
    };

    match (declared, from_permissions) {
        (Some(declared), Some(derived)) if declared & 0o666 != derived => Err(format!(
            "{where_}: {} names `fileMode` {declared:#o} and `permissions` \
             from which {derived:#o} follows. Which applies is no question of \
             interpretation here (ADR-0143 determination 2)",
            path.display()
        )),
        (Some(declared), _) => Ok(declared),
        // Without both, the specification's default applies: `rwm`.
        (None, None) => Ok(0o666),
        (None, Some(derived)) => Ok(derived),
    }
}
