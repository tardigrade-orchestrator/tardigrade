//! The mapping `tg-defs` -> OCI bundle (`config.json` + rootfs).
//!
//! ADR-0003: the agent produces `config.json` from the definition generated
//! from the XSD. ADR-0008 names exactly this path as a use of the same
//! structures.

use std::fs;
use std::path::{Path, PathBuf};

use oci_spec::runtime::{
    LinuxBuilder, LinuxCpuBuilder, LinuxMemoryBuilder, LinuxNamespaceBuilder, LinuxNamespaceType,
    LinuxResourcesBuilder, MountBuilder, ProcessBuilder, RootBuilder, Spec, SpecBuilder,
    UserBuilder, get_default_namespaces,
};
use tg_defs::{ResourcesExt as _, WorkloadExt as _, generated::WorkloadType};
use tg_syscall::mount::{OverlayMount, is_overlay_mounted, mount_overlay};

use crate::content::Digest256;
use crate::error::RuntimeError;
use crate::network::Extras;
use crate::resolved::ResolvedImage;

const MILLICORES_PER_CORE: u64 = 1000;

const CPU_PERIOD_US: u64 = 100_000;

#[derive(Debug, Clone)]
pub struct Bundle {
    dir: PathBuf,
    rootfs: PathBuf,
    mount: OverlayMount,
}

impl Bundle {
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    #[must_use]
    pub fn rootfs(&self) -> &Path {
        &self.rootfs
    }

    #[must_use]
    pub fn mount(&self) -> &OverlayMount {
        &self.mount
    }
}

const OWNER: &str = ".owner";

fn claim(dir: &Path, container_id: &str) -> Result<(), RuntimeError> {
    let marker = dir.join(OWNER);

    // A bundle without a marker stems from the time before: it belongs to
    // whoever claims it now. Otherwise an upgrade could no longer rebuild a
    // single container.
    if let Ok(owner) = fs::read_to_string(&marker) {
        let owner = owner.trim();
        if !owner.is_empty() && owner != container_id {
            return Err(RuntimeError::BundleTaken {
                owner: owner.to_owned(),
                wanted: container_id.to_owned(),
            });
        }
    }

    fs::write(&marker, container_id)
        .map_err(|source| RuntimeError::io("the bundle owner", &marker, source))
}

const SPEC: &str = ".spec";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Current,
    Stale,
}

const GENERATION: &str = ".generation";

#[must_use]
pub fn built_generation(root: &Path, workload: &WorkloadType) -> u64 {
    let marker = root.join(workload.name()).join(GENERATION);
    fs::read_to_string(marker)
        .ok()
        .and_then(|text| text.trim().parse().ok())
        .unwrap_or(0)
}

#[must_use]
pub fn spec_digest(workload: &WorkloadType) -> Option<String> {
    match tg_defs::workload_to_xml(workload) {
        Ok(canonical) => Some(Digest256::of(canonical.as_bytes()).to_string()),
        Err(err) => {
            tracing::warn!(
                workload = %workload.name(),
                error = %err,
                "the declaration is not canonicalizable -- no statement about its generation"
            );
            None
        }
    }
}

#[must_use]
pub fn freshness(root: &Path, workload: &WorkloadType) -> Freshness {
    let marker = root.join(workload.name()).join(SPEC);
    let Ok(stored) = fs::read_to_string(&marker) else {
        return Freshness::Current;
    };
    let stored = stored.trim();
    if stored.is_empty() {
        return Freshness::Current;
    }

    match spec_digest(workload) {
        Some(current) if current == stored => Freshness::Current,
        Some(_) => Freshness::Stale,
        None => Freshness::Current,
    }
}

pub fn ensure_root(root: &Path) -> Result<(), RuntimeError> {
    fs::create_dir_all(root).map_err(|source| RuntimeError::io("the bundle root", root, source))?;

    crate::content::seal(root, "closing the bundle root")
}

pub fn build(
    root: &Path,
    workload: &WorkloadType,
    container_id: &str,
    layer_dirs: &[PathBuf],
    image: &ResolvedImage,
    volumes: &[VolumeMount],
    extras: Extras<'_>,
) -> Result<Bundle, RuntimeError> {
    ensure_root(root)?;

    // **Read before everything else** (ADR-0120): the marker `.spec` is
    // overwritten further down, and afterwards every declaration would look
    // unchanged.
    let changed = freshness(root, workload) == Freshness::Stale;

    let dir = root.join(workload.name());
    let rootfs = dir.join("rootfs");
    let upper = dir.join("upper");
    let work = dir.join("work");

    // **A changed declaration remounts** (ADR-0120, determination 1).
    //
    // Measured, this call took the **existing** mount, and that carries the
    // old `lowerdir`: a changed image thereby reached the `config.json` and
    // **not** the file system. The assurance from ADR-0070 and ADR-0071 --
    // "it takes effect at the next start" -- did not apply to anything that
    // sits in the image.
    //
    // **And the `upper` goes along** (determination 2): a writable layer of
    // image A over image B lays itself over exactly the files somebody once
    // touched -- the new generation would be invisible there. Half an upgrade
    // is worse than none, because it looks like one.
    //
    // **The precondition is a guard, not a sentence** (ADR-0122).
    //
    // Here stood: "This is safe here, because `build` runs only from `start`
    // and `start` only after `apply` has ended the container
    // (determination 4)." The sentence held for every arm except one --
    // `Unknown` fell together with `Absent`, and then the path led here while
    // the container was running. Measured: `Ok`, rootfs swapped, `upper`
    // deleted, container carries on, and only the subsequent `create`
    // reported something that sounds like a harmless remnant.
    //
    // The precondition is now carried by the exhaustive `match` in
    // `apply::reconcile_one`: **`start` is reached only when this pass knows
    // that no container of this identifier is running.** Whoever adds a state
    // to the enumeration type comes past there.
    if changed && tg_syscall::mount::is_overlay_mounted(&rootfs) {
        tg_syscall::mount::unmount_overlay(&rootfs)?;
        for path in [&upper, &work] {
            fs::remove_dir_all(path).map_err(|source| {
                RuntimeError::io("discarding the ephemeral volume", path, source)
            })?;
        }
        tracing::info!(
            workload = %workload.name(),
            "the declaration changed -- rootfs remounted, ephemeral volume discarded"
        );
    }

    for path in [&rootfs, &upper, &work] {
        fs::create_dir_all(path)
            .map_err(|source| RuntimeError::io("the bundle directory", path, source))?;
    }

    claim(&dir, container_id)?;

    // **The `upper` is the ephemeral volume** (phase 2, ADR-0027), and under
    // a user namespace it belongs to the host `root` -- the container could
    // not write into its own rootfs (ADR-0091, measurement 1).
    //
    // They are **fresh, empty** directories: the `chown` costs two calls, not
    // a tree. `rootfs` stays out of it -- it is the mount point, and what a
    // container sees there is determined by the overlay.
    if let Some(mapping) = extras.userns {
        for path in [&upper, &work] {
            crate::userns::shift_tree(path, mapping)
                .map_err(|source| RuntimeError::io("mapping the bundle", path, source))?;
        }
    }

    // **The digest of the declaration this bundle arises from** (ADR-0070).
    // It is the only place at which it can later be seen what the running
    // container actually is -- the `config.json` beside it says so only
    // indirectly, and a comparison over it would be a comparison with the
    // result instead of with the intention.
    if let Some(digest) = spec_digest(workload) {
        let marker = dir.join(SPEC);
        fs::write(&marker, &digest)
            .map_err(|source| RuntimeError::io("the bundle digest", &marker, source))?;
    }

    // **And the generation it is built in** (ADR-0071). It stands beside the
    // digest and not in it: the digest says *what* runs (ADR-0070), the
    // generation *when it was last decreed*. Two numbers, two questions.
    let marker = dir.join(GENERATION);
    fs::write(&marker, extras.generation.to_string())
        .map_err(|source| RuntimeError::io("the bundle generation", &marker, source))?;

    // overlayfs expects lowerdir topmost-first, OCI delivers lowest-first.
    let mut lower: Vec<PathBuf> = layer_dirs.to_vec();
    lower.reverse();

    // After an agent restart the rootfs is often still mounted (ADR-0019: it
    // survives the agent). A second mount would cover the first.
    let mount = if is_overlay_mounted(&rootfs) {
        OverlayMount::already_mounted(&rootfs)
    } else {
        mount_overlay(&lower, &upper, &work, &rootfs)?
    };

    // The `resolv.conf` goes into the rootfs **before** the spec: if it
    // fails, no `config.json` has arisen yet that points at a network in
    // which nobody resolves names.
    if let Some(content) = extras
        .network
        .and_then(|network| network.resolv_conf.as_deref())
    {
        write_resolv_conf(&rootfs, content)?;
    }

    let spec = spec_for(
        workload,
        container_id,
        &image.entrypoint,
        &image.env,
        volumes,
        extras,
    )?;
    let config = dir.join("config.json");
    spec.save(&config).map_err(|err| RuntimeError::Unmappable {
        workload: workload.name().to_owned(),
        reason: format!("the config.json is not writable: {err}"),
    })?;

    Ok(Bundle { dir, rootfs, mount })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeMount {
    pub source: PathBuf,
    pub destination: String,
    pub readonly: bool,
}

impl VolumeMount {
    #[must_use]
    pub fn options(&self) -> Vec<String> {
        let mut options = vec!["rbind".to_owned(), "rprivate".to_owned()];
        options.push(if self.readonly { "ro" } else { "rw" }.to_owned());
        options
    }
}

fn isolation(
    mut linux: LinuxBuilder,
    extras: &Extras<'_>,
    workload: &str,
) -> Result<LinuxBuilder, RuntimeError> {
    let unmappable = |reason: String| RuntimeError::Unmappable {
        workload: workload.to_owned(),
        reason,
    };

    if extras.network.is_some() || extras.userns.is_some() {
        // **Only what belongs replaced is replaced**, the remaining
        // namespaces stay as the builder brings them -- PID, IPC, UTS and
        // mount. A hand-written list would be a second source for a
        // container's isolation, and that does not stand out at startup.
        let mut namespaces = get_default_namespaces();
        if let Some(attachment) = extras.network {
            for namespace in &mut namespaces {
                if namespace.typ() == LinuxNamespaceType::Network {
                    namespace.set_path(Some(attachment.netns.clone()));
                }
            }
        }
        if extras.userns.is_some() {
            // **Without a path**: the namespace arises with the container.
            // A path would mean entering an existing one -- and that is
            // exactly what youki cannot do with a netns (ADR-0091,
            // measurement 5).
            namespaces.push(
                LinuxNamespaceBuilder::default()
                    .typ(LinuxNamespaceType::User)
                    .build()
                    .map_err(|err| unmappable(format!("the user namespace: {err}")))?,
            );
        }
        linux = linux.namespaces(namespaces);
    }

    if let Some(mapping) = extras.userns {
        // **The mapping** (ADR-0091, determination 1). It stands beside the
        // namespaces and not in them: the OCI spec keeps them separate.
        let ids = |kind: &str| -> Result<Vec<oci_spec::runtime::LinuxIdMapping>, RuntimeError> {
            Ok(vec![
                oci_spec::runtime::LinuxIdMappingBuilder::default()
                    .container_id(0_u32)
                    .host_id(mapping.base())
                    .size(crate::userns::SIZE)
                    .build()
                    .map_err(|err| unmappable(format!("the {kind} mapping: {err}")))?,
            ])
        };
        linux = linux.uid_mappings(ids("uid")?).gid_mappings(ids("gid")?);
    }

    Ok(linux)
}

pub fn spec_for(
    workload: &WorkloadType,
    container_id: &str,
    entrypoint: &[String],
    env: &[String],
    volumes: &[VolumeMount],
    extras: Extras<'_>,
) -> Result<Spec, RuntimeError> {
    let unmappable = |reason: String| RuntimeError::Unmappable {
        workload: workload.name().to_owned(),
        reason,
    };

    // The definition beats the image: if <command> stands in the XML, it
    // applies, otherwise entrypoint/cmd from the image (ADR-0003).
    let from_definition: Vec<String> = workload
        .command()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let args = if from_definition.is_empty() {
        entrypoint.to_vec()
    } else {
        from_definition
    };

    if args.is_empty() {
        return Err(unmappable(
            "neither <command> in the definition nor entrypoint/cmd in the \
             image; without a start command no container can be started"
                .to_owned(),
        ));
    }

    // **The device's environment comes after the image's** (ADR-0143): a
    // CDI `env` describes where its libraries lie, and whoever put it in
    // front would let an `ENV` in the image overwrite it.
    let mut environment = env.to_vec();
    if let Some(edits) = extras.devices {
        environment.extend(edits.env.iter().cloned());
    }

    let mut process = ProcessBuilder::default()
        .args(args)
        .env(environment)
        .cwd("/")
        .terminal(false);
    if let Some(uid) = extras.run_as {
        // **Only for sidecars** (ADR-0060): the exception in the rule set
        // hangs on `meta skuid`, and without an identifier of its own it
        // would free the workload too -- both otherwise run as 0. What an
        // ordinary image wants as its user stays its own business.
        let user = UserBuilder::default()
            .uid(uid)
            .gid(uid)
            .build()
            .map_err(|err| unmappable(format!("the user section: {err}")))?;
        process = process.user(user);
    }
    let process = process
        .build()
        .map_err(|err| unmappable(format!("the process section: {err}")))?;

    let root = RootBuilder::default()
        .path("rootfs")
        .readonly(false)
        .build()
        .map_err(|err| unmappable(format!("the root section: {err}")))?;

    let mut linux = LinuxBuilder::default().cgroups_path(cgroups_path(container_id));
    if let Some(resources) = linux_resources(workload, extras.sidecar_memory)? {
        linux = linux.resources(resources);
    }
    linux = isolation(linux, &extras, workload.name())?;
    if let Some(edits) = extras.devices {
        // **Only `linux.devices`, no cgroup rule** (ADR-0143
        // determination 2). What CDI describes as `permissions` sits in the
        // node's file mode; the controller for it would be eBPF
        // (`reject_unenforceable` below, ADR-0090).
        let devices = edits.oci_devices().map_err(unmappable)?;
        if !devices.is_empty() {
            linux = linux.devices(devices);
        }
    }
    if extras.no_seccomp {
        // **Expressly and audited** (ADR-0017): the agent reports the
        // setting at startup. Here it merely stands that it takes effect.
    } else {
        // **Every container gets the profile** (ADR-0090, determination 5)
        // -- the derived sidecar too (ADR-0059); it calls none of it.
        //
        // It is a **denylist**: what does not stand on it runs. It can
        // thereby break no workload it does not know -- the rationale stands
        // in `crate::seccomp`.
        linux = linux.seccomp(crate::seccomp::profile().map_err(unmappable)?);
    }
    let linux = linux
        .build()
        .map_err(|err| unmappable(format!("the linux section: {err}")))?;

    let mut spec = SpecBuilder::default()
        .version("1.0.2-dev")
        .root(root)
        .process(process)
        .hostname(workload.name())
        .linux(linux)
        .build()
        .map_err(|err| unmappable(format!("the spec: {err}")))?;

    let device_mounts = match extras.devices {
        Some(edits) => edits.oci_mounts().map_err(unmappable)?,
        None => Vec::new(),
    };

    if !volumes.is_empty() || !device_mounts.is_empty() {
        // **Supplement, not replace.** `SpecBuilder` brings the OCI
        // standard mounts along -- /proc, /dev, /sys and the rest.
        // Overwriting them would yield a container without /proc, and that
        // does not stand out at startup but at the first program that looks
        // for itself.
        let mut all = spec.mounts().clone().unwrap_or_default();

        for volume in volumes {
            let mount = MountBuilder::default()
                .destination(&volume.destination)
                .typ("bind")
                .source(&volume.source)
                .options(volume.options())
                .build()
                .map_err(|err| unmappable(format!("the mount '{}': {err}", volume.destination)))?;
            all.push(mount);
        }
        all.extend(device_mounts);

        spec.set_mounts(Some(all));
    }

    reject_unenforceable(workload.name(), &spec)?;

    Ok(spec)
}

fn reject_unenforceable(workload: &str, spec: &Spec) -> Result<(), RuntimeError> {
    let devices = spec
        .linux()
        .as_ref()
        .and_then(|linux| linux.resources().as_ref())
        .and_then(|resources| resources.devices().as_ref());

    let Some(devices) = devices else {
        return Ok(());
    };
    if devices.is_empty() {
        return Ok(());
    }

    Err(RuntimeError::Unenforceable {
        workload: workload.to_owned(),
        detail: format!(
            "the spec contains {} device cgroup rule(s), but the cgroup v2 \
             device controller is eBPF-based and out per CLAUDE.md \
             invariant 1. The runtime would ignore them quietly. Solve device \
             isolation via device-node presence and userns (ADR-0017, \
             ADR-0028)",
            devices.len()
        ),
    })
}

#[must_use]
pub fn sidecar_limit(path: &Path) -> Option<u64> {
    let text = fs::read_to_string(path).ok()?;

    text.lines()
        .filter_map(|line| line.split_once('='))
        .find(|(name, _)| name.trim() == tg_model::Resources::MEMORY_BYTES)
        .and_then(|(_, amount)| amount.trim().parse::<u64>().ok())
        .filter(|bytes| *bytes > 0)
}

fn linux_resources(
    workload: &WorkloadType,
    sidecar_memory: Option<u64>,
) -> Result<Option<oci_spec::runtime::LinuxResources>, RuntimeError> {
    let unmappable = |reason: String| RuntimeError::Unmappable {
        workload: workload.name().to_owned(),
        reason,
    };

    // **The derived sidecar** (ADR-0086). It has no declaration, so no
    // `<resources>` either -- and without this arm it would get no limit.
    // Expressly **only** memory: see `Extras::sidecar_memory`.
    if let Some(bytes) = sidecar_memory {
        let memory = LinuxMemoryBuilder::default()
            .limit(
                i64::try_from(bytes)
                    .map_err(|_| unmappable(format!("{bytes} bytes overflow an i64")))?,
            )
            .build()
            .map_err(|err| unmappable(format!("the sidecar's memory limit: {err}")))?;
        return Ok(Some(
            LinuxResourcesBuilder::default()
                .memory(memory)
                .build()
                .map_err(|err| unmappable(format!("the sidecar's limits: {err}")))?,
        ));
    }

    let Some(resources) = workload.resources() else {
        return Ok(None);
    };

    let mut builder = LinuxResourcesBuilder::default();

    if let Some(millicores) = resources.millicores() {
        // Quota = period x (millicores / 1000). Computed in integers, so
        // that 500 millicores become exactly 50 000 us and not 49 999.
        let quota = CPU_PERIOD_US
            .checked_mul(u64::from(millicores))
            .map(|product| product / MILLICORES_PER_CORE)
            .ok_or_else(|| unmappable(format!("{millicores} millicores overflow the CFS quota")))?;

        let cpu = LinuxCpuBuilder::default()
            .period(CPU_PERIOD_US)
            .quota(
                i64::try_from(quota)
                    .map_err(|_| unmappable("the CFS quota is too large".to_owned()))?,
            )
            .build()
            .map_err(|err| unmappable(format!("the CPU limit: {err}")))?;
        builder = builder.cpu(cpu);
    }

    if let Some(bytes) = resources.memory_bytes() {
        let limit = i64::try_from(bytes)
            .map_err(|_| unmappable(format!("{bytes} bytes overflow an i64")))?;
        let memory = LinuxMemoryBuilder::default()
            .limit(limit)
            .build()
            .map_err(|err| unmappable(format!("the memory limit: {err}")))?;
        builder = builder.memory(memory);
    }

    builder
        .build()
        .map(Some)
        .map_err(|err| unmappable(format!("the resources: {err}")))
}

#[must_use]
pub fn container_id(workload_name: &str, instance: u32) -> String {
    if instance == 0 {
        format!("{PREFIX}{workload_name}")
    } else {
        format!("{PREFIX}{workload_name}-{instance}")
    }
}

pub use tg_model::names::CONTAINER_PREFIX as PREFIX;

pub fn release(root: &Path, workload: &str) -> Result<(), RuntimeError> {
    let dir = root.join(workload);
    if !dir.is_dir() {
        return Ok(());
    }

    let rootfs = dir.join("rootfs");
    if tg_syscall::mount::is_overlay_mounted(&rootfs) {
        tg_syscall::mount::unmount_overlay(&rootfs)?;
    }

    fs::remove_dir_all(&dir).map_err(|source| RuntimeError::io("removing the bundle", &dir, source))
}

const CGROUP_PARENT: &str = "tardigrade";

fn write_resolv_conf(rootfs: &Path, content: &str) -> Result<(), RuntimeError> {
    let dir = rootfs.join("etc");
    fs::create_dir_all(&dir)
        .map_err(|source| RuntimeError::io("etc in the rootfs", &dir, source))?;

    let path = dir.join("resolv.conf");
    fs::write(&path, content).map_err(|source| RuntimeError::io("resolv.conf", &path, source))
}

#[must_use]
pub fn cgroups_path(container_id: &str) -> String {
    format!("/{CGROUP_PARENT}/{container_id}")
}

#[must_use]
pub fn bundles_root(data_dir: &Path) -> PathBuf {
    data_dir.join("bundles")
}

#[must_use]
pub fn layer_dirs(store: &crate::content::ContentStore, digests: &[Digest256]) -> Vec<PathBuf> {
    digests
        .iter()
        .map(|digest| store.layer_path(digest))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workload(xml: &str) -> tg_defs::WorkloadSet {
        tg_defs::from_str(xml).expect("the fixture must parse")
    }

    const MINIMAL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1"/>
  </workload>
</workloads>"#;

    const WITH_RESOURCES: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1"/>
    <resources>
      <cpu millicores="500"/>
      <memory bytes="536870912"/>
    </resources>
  </workload>
</workloads>"#;

    #[test]
    fn container_id_is_derived_from_the_workload_name() {
        assert_eq!(container_id("api", 0), "tg-api");
        // Instance 0 keeps the old name: an agent after the upgrade must
        // find the running container again, otherwise it starts a second one,
        // and both write into the same volume (ADR-0027).
        assert_eq!(container_id("api", 1), "tg-api-1");
        assert_eq!(container_id("api", 7), "tg-api-7");
    }

    #[test]
    fn a_bundle_belongs_to_one_container() {
        let dir = tempfile::tempdir().expect("tempdir");

        // **Without a marker**: the path after an upgrade.
        claim(dir.path(), "tg-api").expect("a bundle without a marker belongs to the claimant");

        // **The same one again**: the path after a restart.
        claim(dir.path(), "tg-api").expect("the same container may again");

        // **A foreign one**: the assurance.
        let err = claim(dir.path(), "tg-api-1").expect_err("the bundle is taken");
        let text = err.to_string();
        assert!(
            text.contains("tg-api") && text.contains("tg-api-1"),
            "the message must name both identifiers: {text}"
        );

        // **And the marker stands unchanged.** A refused claim that
        // nevertheless rewrote the owner would be the worst version: the first
        // container would carry on, and the next `claim` would give the
        // `upper` to the second.
        assert_eq!(
            std::fs::read_to_string(dir.path().join(OWNER)).expect("the marker"),
            "tg-api"
        );
    }

    #[test]
    fn the_cgroup_path_carries_the_container_id() {
        let set = workload(MINIMAL);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        assert_eq!(
            spec.linux()
                .as_ref()
                .and_then(|linux| linux.cgroups_path().clone())
                .as_deref()
                .and_then(std::path::Path::to_str),
            Some("/tardigrade/tg-api")
        );
    }

    #[test]
    fn the_container_enters_the_prepared_network_namespace() {
        let set = workload(MINIMAL);
        let attachment = crate::network::Attachment {
            netns: PathBuf::from("/run/netns/tg-api"),
            resolv_conf: None,
        };

        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras {
                devices: None,
                network: Some(&attachment),
                run_as: None,
                generation: 0,
                ..Extras::default()
            },
        )
        .expect("the spec");

        let namespaces = spec
            .linux()
            .as_ref()
            .and_then(|linux| linux.namespaces().clone())
            .expect("the namespaces");

        let network = namespaces
            .iter()
            .find(|namespace| namespace.typ() == LinuxNamespaceType::Network)
            .expect("no network namespace in the spec");
        assert_eq!(
            network.path().as_deref(),
            Some(Path::new("/run/netns/tg-api"))
        );

        // **The remaining namespaces stay fresh.** A path on PID, IPC, UTS
        // or mount would mean that the container inherits another's isolation
        // -- and that does not stand out at startup.
        for namespace in namespaces
            .iter()
            .filter(|namespace| namespace.typ() != LinuxNamespaceType::Network)
        {
            assert_eq!(
                namespace.path(),
                &None,
                "{:?} must carry no path",
                namespace.typ()
            );
        }
    }

    #[test]
    fn without_an_attachment_the_container_gets_a_fresh_empty_namespace() {
        let set = workload(MINIMAL);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        let namespaces = spec
            .linux()
            .as_ref()
            .and_then(|linux| linux.namespaces().clone())
            .expect("the namespaces");

        let network = namespaces
            .iter()
            .find(|namespace| namespace.typ() == LinuxNamespaceType::Network)
            .expect("without a network namespace the container would lie in the node's network");
        assert_eq!(network.path(), &None);
    }

    #[test]
    fn a_container_gets_every_namespace_the_isolation_rests_on() {
        let set = workload(MINIMAL);
        let attachment = crate::network::Attachment {
            netns: PathBuf::from("/run/netns/tg-api"),
            resolv_conf: None,
        };
        let expected = [
            LinuxNamespaceType::Pid,
            LinuxNamespaceType::Network,
            LinuxNamespaceType::Ipc,
            LinuxNamespaceType::Uts,
            LinuxNamespaceType::Mount,
            LinuxNamespaceType::Cgroup,
        ];
        let mut want: Vec<String> = expected.iter().map(|typ| format!("{typ:?}")).collect();
        want.sort();

        for network in [Some(&attachment), None] {
            let attached = network.is_some();
            let spec = spec_for(
                &set.workloads()[0],
                "tg-api",
                &["/bin/sh".into()],
                &[],
                &[],
                Extras {
                    network,
                    run_as: None,
                    generation: 0,
                    ..Extras::default()
                },
            )
            .expect("the spec");

            let mut found: Vec<String> = spec
                .linux()
                .as_ref()
                .and_then(|linux| linux.namespaces().clone())
                .expect("the namespaces")
                .iter()
                .map(|namespace| format!("{:?}", namespace.typ()))
                .collect();
            found.sort();

            assert_eq!(
                found, want,
                "attached={attached}: the spec's namespaces are not those the \
                 isolation rests on"
            );
        }
    }

    #[test]
    fn only_the_memory_entry_becomes_a_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("sidecar-overhead");

        std::fs::write(&path, "cpu-millicores=50\nmemory-bytes=67108864\n").expect("the file");
        assert_eq!(sidecar_limit(&path), Some(67_108_864));

        // Only the CPU: booked, but not enforced (ADR-0086).
        std::fs::write(&path, "cpu-millicores=50\n").expect("the file");
        assert_eq!(sidecar_limit(&path), None);

        for broken in [
            "",
            "memory-bytes=0\n",
            "memory-bytes=\n",
            "memory-bytes\n",
            "\u{0}",
        ] {
            std::fs::write(&path, broken).expect("the file");
            assert_eq!(
                sidecar_limit(&path),
                None,
                "'{}' yielded a limit",
                broken.escape_debug()
            );
        }

        assert_eq!(
            sidecar_limit(&dir.path().join("does-not-exist")),
            None,
            "a missing file means no surcharge, not a guessed limit"
        );
    }

    #[test]
    fn the_profile_is_in_the_spec() {
        let set = workload(MINIMAL);
        let build = |extras| {
            spec_for(
                &set.workloads()[0],
                "tg-api",
                &["/bin/sh".into()],
                &[],
                &[],
                extras,
            )
            .expect("the spec")
        };

        let spec = build(Extras::default());
        let seccomp = spec
            .linux()
            .as_ref()
            .expect("the linux section")
            .seccomp()
            .as_ref()
            .expect("the default carries a profile")
            .clone();
        assert_eq!(
            seccomp.default_action(),
            oci_spec::runtime::LinuxSeccompAction::ScmpActAllow,
            "a denylist has ALLOW as its default (ADR-0090)"
        );
        let names: Vec<&str> = seccomp
            .syscalls()
            .as_ref()
            .expect("the entries")
            .iter()
            .flat_map(|entry| entry.names().iter().map(String::as_str))
            .collect();
        assert!(
            names.contains(&"bpf"),
            "invariant 1 belongs in every spec: {names:?}"
        );

        // And the way out (ADR-0090, determination 5).
        let relaxed = build(Extras {
            no_seccomp: true,
            ..Extras::default()
        });
        assert!(
            relaxed
                .linux()
                .as_ref()
                .expect("the linux section")
                .seccomp()
                .is_none(),
            "with --no-seccomp no profile belongs in the spec"
        );
    }

    #[test]
    fn a_sidecar_gets_a_memory_limit_and_no_cpu_quota() {
        let set = workload(MINIMAL);
        let build = |extras| {
            spec_for(
                &set.workloads()[0],
                "tg-api-proxy",
                &["/usr/local/bin/tg-proxy".into()],
                &[],
                &[],
                extras,
            )
            .expect("the spec")
        };

        let limited = build(Extras {
            sidecar_memory: Some(64 << 20),
            ..Extras::default()
        });
        let resources = limited
            .linux()
            .as_ref()
            .expect("the linux section")
            .resources()
            .clone()
            .expect("a sidecar with a surcharge has limits");
        assert_eq!(
            resources
                .memory()
                .as_ref()
                .and_then(oci_spec::runtime::LinuxMemory::limit),
            Some(64 << 20),
            "without a memory limit an OOM kill takes all the node's workloads with it"
        );
        assert!(
            resources.cpu().is_none(),
            "a CFS quota on a proxy is exactly the throttling from ADR-0022: {:?}",
            resources.cpu()
        );

        // And the counter-direction. What is asked for are the **limits**
        // and not `resources()`: the `LinuxBuilder` lays a `devices: []` there
        // anyway, so `resources().is_none()` would never be true -- measured,
        // not assumed.
        let plain = build(Extras::default());
        let resources = plain
            .linux()
            .as_ref()
            .expect("the linux section")
            .resources()
            .clone()
            .expect("the builder lays something here anyway");
        assert!(
            resources.memory().is_none() && resources.cpu().is_none(),
            "without a surcharge no limit belongs in the spec: {resources:?}"
        );
    }

    #[test]
    fn the_mapping_is_in_the_spec() {
        let set = workload(MINIMAL);
        let build = |extras| {
            spec_for(
                &set.workloads()[0],
                "tg-api",
                &["/bin/sh".into()],
                &[],
                &[],
                extras,
            )
            .expect("the spec")
        };

        let base = 100_000;
        let mapped = build(Extras {
            userns: Some(crate::userns::Mapping::new(base).expect("the range")),
            ..Extras::default()
        });
        let linux = mapped.linux().as_ref().expect("the linux section").clone();

        let kinds: Vec<_> = linux
            .namespaces()
            .as_ref()
            .expect("the namespaces")
            .iter()
            .map(oci_spec::runtime::LinuxNamespace::typ)
            .collect();
        assert!(
            kinds.contains(&oci_spec::runtime::LinuxNamespaceType::User),
            "without the namespace in the set the mapping is without effect: {kinds:?}"
        );

        for (label, mappings) in [
            ("uid", linux.uid_mappings().as_ref()),
            ("gid", linux.gid_mappings().as_ref()),
        ] {
            let entries = mappings.unwrap_or_else(|| panic!("{label}Mappings are missing"));
            assert_eq!(entries.len(), 1, "one fixed mapping per node");
            let entry = &entries[0];
            assert_eq!(entry.container_id(), 0, "{label}: 0 in the container");
            assert_eq!(entry.host_id(), base, "{label}: onto the range");
            assert_eq!(
                entry.size(),
                crate::userns::SIZE,
                "{label}: the whole range"
            );
        }

        // And the counter-direction: without the setting everything stays as
        // it was.
        let plain = build(Extras::default());
        let linux = plain.linux().as_ref().expect("the linux section");
        assert!(
            linux.uid_mappings().is_none() && linux.gid_mappings().is_none(),
            "without --userns-base no mapping belongs in the spec"
        );
        let kinds: Vec<_> = linux
            .namespaces()
            .as_ref()
            .expect("the namespaces")
            .iter()
            .map(oci_spec::runtime::LinuxNamespace::typ)
            .collect();
        assert!(
            !kinds.contains(&oci_spec::runtime::LinuxNamespaceType::User),
            "without a mapping a user namespace would be a container without an identifier: {kinds:?}"
        );
    }

    #[test]
    fn the_hardening_the_oci_default_brings_stays() {
        let set = workload(MINIMAL);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        let process = spec.process().as_ref().expect("the process section");
        assert_eq!(
            process.no_new_privileges(),
            Some(true),
            "without no-new-privs a setuid binary in the image carries rights again (ADR-0017)"
        );

        let capabilities = process
            .capabilities()
            .as_ref()
            .expect("without a capability set the process keeps them all");
        let bounding = capabilities
            .bounding()
            .as_ref()
            .expect("without a bounding set nothing is bounded");
        assert!(
            bounding.len() < 10,
            "the capability set is no longer the narrow default: {} entries",
            bounding.len()
        );

        let linux = spec.linux().as_ref().expect("the linux section");
        assert!(
            linux.masked_paths().as_ref().is_some_and(|p| !p.is_empty()),
            "without masked paths the container reads /proc/kcore and the kernel pointers"
        );
        assert!(
            linux
                .readonly_paths()
                .as_ref()
                .is_some_and(|p| !p.is_empty()),
            "without read-only paths the container writes into /proc/sys"
        );
    }

    #[test]
    fn the_resolver_reaches_a_rootfs_without_an_etc() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).expect("rootfs");

        write_resolv_conf(&rootfs, "nameserver 10.42.1.1\n").expect("write");

        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc").join("resolv.conf")).expect("read"),
            "nameserver 10.42.1.1\n"
        );
    }

    #[test]
    fn an_existing_resolv_conf_is_replaced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let rootfs = dir.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("etc")).expect("etc");
        std::fs::write(
            rootfs.join("etc").join("resolv.conf"),
            "nameserver 8.8.8.8\n",
        )
        .expect("write");

        write_resolv_conf(&rootfs, "nameserver 10.42.1.1\n").expect("write");

        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc").join("resolv.conf")).expect("read"),
            "nameserver 10.42.1.1\n"
        );
    }

    #[test]
    fn a_second_instance_gets_its_own_cgroup() {
        let set = workload(MINIMAL);
        let spec = spec_for(
            &set.workloads()[0],
            &container_id("api", 1),
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        assert_eq!(
            spec.linux()
                .as_ref()
                .and_then(|linux| linux.cgroups_path().clone())
                .as_deref()
                .and_then(std::path::Path::to_str),
            Some("/tardigrade/tg-api-1")
        );
    }

    #[test]
    fn a_container_cannot_make_itself_a_device_node() {
        let set = workload(MINIMAL);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-probe",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        let capabilities = spec
            .process()
            .as_ref()
            .and_then(|process| process.capabilities().clone())
            .expect("without a capability set the process keeps them all");

        for set_name in [
            capabilities.bounding(),
            capabilities.effective(),
            capabilities.permitted(),
        ] {
            let Some(set_name) = set_name else { continue };
            assert!(
                !set_name.contains(&oci_spec::runtime::Capability::Mknod),
                "CAP_MKNOD is back -- then the device barrier from ADR-0143 \
                 determination 2 no longer carries, for a container lays the \
                 missing node out itself"
            );
        }
    }

    #[test]
    fn spec_carries_entrypoint_and_hostname() {
        let set = workload(MINIMAL);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        assert_eq!(spec.hostname().as_deref(), Some("api"));
        assert_eq!(
            spec.process().as_ref().and_then(|p| p.args().as_ref()),
            Some(&vec!["/bin/sh".to_owned()])
        );
    }

    #[test]
    fn empty_entrypoint_is_rejected_with_a_named_reason() {
        let set = workload(MINIMAL);
        let err = spec_for(
            &set.workloads()[0],
            "tg-api",
            &[],
            &[],
            &[],
            Extras::default(),
        )
        .unwrap_err();

        match err {
            RuntimeError::Unmappable { workload, reason } => {
                assert_eq!(workload, "api");
                assert!(
                    reason.contains("entrypoint"),
                    "the reason is unclear: {reason}"
                );
            }
            other => panic!("the wrong error: {other}"),
        }
    }

    #[test]
    fn millicores_map_to_exact_cfs_quota() {
        let set = workload(WITH_RESOURCES);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        let cpu = spec
            .linux()
            .as_ref()
            .and_then(|l| l.resources().as_ref())
            .and_then(|r| r.cpu().as_ref())
            .expect("the CPU limit is set");

        assert_eq!(cpu.period(), Some(100_000));
        assert_eq!(cpu.quota(), Some(50_000));
    }

    #[test]
    fn memory_bytes_map_to_the_cgroup_limit() {
        let set = workload(WITH_RESOURCES);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        let memory = spec
            .linux()
            .as_ref()
            .and_then(|l| l.resources().as_ref())
            .and_then(|r| r.memory().as_ref())
            .expect("the memory limit is set");

        assert_eq!(memory.limit(), Some(536_870_912));
    }

    #[test]
    fn device_cgroup_rules_are_rejected_instead_of_silently_ignored() {
        use oci_spec::runtime::LinuxDeviceCgroupBuilder;

        let set = workload(MINIMAL);
        let mut spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        let rule = LinuxDeviceCgroupBuilder::default()
            .allow(true)
            .typ(oci_spec::runtime::LinuxDeviceType::C)
            .major(195_i64)
            .minor(0_i64)
            .access("rwm")
            .build()
            .expect("the rule");

        let mut resources = spec.linux().as_ref().and_then(|l| l.resources().clone());
        let mut res = resources.take().unwrap_or_default();
        res.set_devices(Some(vec![rule]));
        let mut linux = spec.linux().clone().unwrap_or_default();
        linux.set_resources(Some(res));
        spec.set_linux(Some(linux));

        let err = reject_unenforceable("api", &spec).expect_err("must abort");

        match err {
            RuntimeError::Unenforceable { workload, detail } => {
                assert_eq!(workload, "api");
                assert!(detail.contains("eBPF"), "the reason is unclear: {detail}");
            }
            other => panic!("the wrong error: {other}"),
        }
    }

    #[test]
    fn spec_without_device_rules_passes_the_guard() {
        let set = workload(WITH_RESOURCES);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        assert!(reject_unenforceable("api", &spec).is_ok());
    }

    #[test]
    fn workload_without_resources_gets_no_cgroup_limits() {
        let set = workload(MINIMAL);
        let spec = spec_for(
            &set.workloads()[0],
            "tg-api",
            &["/bin/sh".into()],
            &[],
            &[],
            Extras::default(),
        )
        .expect("the spec");

        // `Linux::default()` delivers an empty resource block, not `None` --
        // the effect is therefore checked: no limit set.
        let resources = spec.linux().as_ref().and_then(|l| l.resources().as_ref());
        let cpu = resources.and_then(|r| r.cpu().as_ref());
        let memory = resources.and_then(|r| r.memory().as_ref());

        assert!(
            cpu.is_none(),
            "without <resources> no CPU limit must be set"
        );
        assert!(
            memory.is_none(),
            "without <resources> no memory limit must be set"
        );
    }

    #[test]
    fn the_digest_follows_the_declaration() {
        let one = workload(MINIMAL);
        let other = workload(WITH_RESOURCES);

        let first = spec_digest(&one.workloads()[0]).expect("canonicalizable");
        assert_eq!(
            first,
            spec_digest(&workload(MINIMAL).workloads()[0]).expect("canonicalizable"),
            "the same declaration, the same digest -- otherwise every instance would be permanently stale"
        );
        assert_ne!(
            first,
            spec_digest(&other.workloads()[0]).expect("canonicalizable"),
            "another declaration, another digest"
        );
    }

    #[test]
    fn a_pending_resize_makes_the_instance_stale() {
        let declaration = |size: &str| {
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.test/api:1"/>
    <volumes>
      <volume name="daten" mode="readWrite" path="/var/daten" size="{size}"/>
    </volumes>
  </workload>
</workloads>"#
            )
        };

        let small = workload(&declaration("8388608"));
        let large = workload(&declaration("67108864"));

        assert_ne!(
            spec_digest(&small.workloads()[0]).expect("canonicalizable"),
            spec_digest(&large.workloads()[0]).expect("canonicalizable"),
            "a changed volume size must make the instance stale -- otherwise \
             a pending growth is invisible (ADR-0063)"
        );
    }

    #[test]
    fn a_bundle_without_a_marker_counts_as_current() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set = workload(MINIMAL);
        let one = &set.workloads()[0];

        std::fs::create_dir_all(dir.path().join(one.name())).expect("the directory");
        assert_eq!(freshness(dir.path(), one), Freshness::Current);

        // The same situation with a marker from another declaration.
        let other = workload(WITH_RESOURCES);
        std::fs::write(
            dir.path().join(one.name()).join(SPEC),
            spec_digest(&other.workloads()[0]).expect("canonicalizable"),
        )
        .expect("the marker");
        assert_eq!(freshness(dir.path(), one), Freshness::Stale);

        // And with its own, current again.
        std::fs::write(
            dir.path().join(one.name()).join(SPEC),
            spec_digest(one).expect("canonicalizable"),
        )
        .expect("the marker");
        assert_eq!(freshness(dir.path(), one), Freshness::Current);
    }
}
