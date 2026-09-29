//! The way from a definition to a running container.
//!
//! This layer is deliberately **local and without a control plane** (ADR-0019): it
//! reads the desired state from the disk, asks the runtime for the actual state and
//! reconciles the difference. A network access happens only at the image pull, and
//! that too only when the layer does not already lie in the content store.
//!
//! Phase 2 makes **one** pass out of that. The loop, the drift detection and the
//! autonomy rules come in phase 4 (ADR-0010).

use tg_defs::{ImageExt as _, WorkloadExt as _, generated::WorkloadType};

use crate::content::ContentStore;
use crate::error::RuntimeError;
use crate::oci::{ContainerStatus, OciRuntime};
use crate::reconcile::Context;
use crate::volume::Sizing;
use crate::{NodePaths, acquire, bundle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    AlreadyRunning,
    Stale,
    Started,
    Replaced,
    Restarted,
    Unclear(&'static str),
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AlreadyRunning => "runs already",
            Self::Stale => "runs already, but from an older declaration (ADR-0070)",
            Self::Started => "started",
            Self::Replaced => "replaced and started",
            Self::Restarted => "was not running, started anew",
            Self::Unclear(reason) => return write!(f, "the state is unknown: {reason}"),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Target<'a> {
    pub workload: &'a WorkloadType,
    pub instance: u32,
    pub principal: Option<&'a str>,
    pub generation: u64,
    pub has_sidecar: bool,
}

pub async fn reconcile_one(
    paths: &NodePaths,
    runtime: &OciRuntime,
    target: &Target<'_>,
    context: &Context<'_>,
) -> Result<Outcome, RuntimeError> {
    let Target {
        workload,
        instance,
        generation,
        ..
    } = *target;
    let id = bundle::container_id(workload.name(), instance);

    // **Per pass, not per start** (ADR-0088). `provision` below runs only when a
    // container is really started; a gauge nobody sets afterwards expires after 15
    // minutes -- and with it the alarm that reports a size that has no effect
    // (ADR-0063).
    crate::volume::report_declared(paths.data_dir(), workload, instance);

    // **A failed call is no information, no failure** (ADR-0122, determination 2).
    // Here a `?` stood: a runtime that once does not answer thereby landed in `failed`
    // -- and per ADR-0061 a `failed` drags every dependant along.
    let status = match runtime.status(&id).await {
        Ok(status) => status,
        Err(err) => {
            tracing::warn!(%id, error = %err, "the state is not queryable");
            return Ok(Outcome::Unclear("the state is not queryable"));
        }
    };

    match status {
        // Fail-static: it runs, so hands off -- even when the declaration has changed
        // (ADR-0070, determination 1). It is said all the same: the difference between
        // the two outcomes is the whole information.
        //
        // **Unless an operator decreed it** (ADR-0071): then the container is replaced
        // -- ended and started anew from the current declaration. The comparison is
        // the generation its bundle was built with.
        ContainerStatus::Running
            if generation <= bundle::built_generation(&paths.bundles_dir(), workload) =>
        {
            return Ok(match bundle::freshness(&paths.bundles_dir(), workload) {
                bundle::Freshness::Current => Outcome::AlreadyRunning,
                bundle::Freshness::Stale => Outcome::Stale,
            });
        }
        // A remnant from an earlier run -- or a running container whose restart is
        // decreed (ADR-0071). Clear it away so that `create` bites.
        //
        // **A running container is ended beforehand**, and that with the grace period
        // from ADR-0058: `delete --force` otherwise sends it a `SIGKILL`, and an
        // orderly restart is no emergency brake.
        status @ (ContainerStatus::Running
        | ContainerStatus::Stopped
        | ContainerStatus::Created
        | ContainerStatus::Paused) => {
            // `stop` is `SIGTERM`, a deadline, then removal -- the same as what the
            // clearer does (ADR-0058). A `delete --force` alone would send `SIGKILL`,
            // and a decreed restart is no emergency brake.
            if status == ContainerStatus::Running {
                crate::reconcile::stop(runtime, &id).await?;
            } else {
                runtime.delete(&id, true).await?;
            }
            let outcome = start(paths, runtime, target, &id, context).await?;
            return Ok(match outcome {
                // **Was it running, or was it not?** That is the difference between a
                // decree and an error: a running container is replaced only by an
                // operator (ADR-0071), an ended one this pass starts because it is
                // ended. Counted together a restart loop would not be distinguishable
                // from a rolling update.
                Outcome::Started if status == ContainerStatus::Running => Outcome::Replaced,
                Outcome::Started => Outcome::Restarted,
                other => other,
            });
        }
        // **`Unknown` is not `Absent`** (ADR-0122, determination 1). The exhaustive
        // `match` *is* the assurance: whoever adds a state to the enumeration comes
        // past here and can no longer choose the unsafe direction by accident.
        //
        // With that the precondition ADR-0120 invokes holds as a property instead of
        // as a comment: **`start` is reached only when this pass knows that no
        // container of this identifier is running.**
        ContainerStatus::Unknown(reason) => return Ok(Outcome::Unclear(reason)),
        ContainerStatus::Absent => {}
    }

    start(paths, runtime, target, &id, context).await
}
fn devices_for(
    workload: &WorkloadType,
    instance: u32,
    id: &str,
    principal: Option<&str>,
    context: &Context<'_>,
) -> Result<Option<crate::cdi::Edits>, RuntimeError> {
    match (principal, context.devices) {
        (None, Some(devices)) => {
            devices
                .assign(workload, instance)
                .map_err(|detail| RuntimeError::Network {
                    instance: id.to_owned(),
                    detail,
                })
        }
        _ => Ok(None),
    }
}

async fn start(
    paths: &NodePaths,
    runtime: &OciRuntime,
    target: &Target<'_>,
    id: &str,
    context: &Context<'_>,
) -> Result<Outcome, RuntimeError> {
    let Target {
        workload,
        instance,
        principal,
        generation,
        ..
    } = *target;
    // **The store gets the mapping** (ADR-0091): a layer unpacked without it belongs
    // to `nobody` in the container and is not changeable.
    let store = ContentStore::open(paths.content_dir())?.mapped(context.userns);
    // **The login is asked for at every pull**, not remembered at the start
    // (ADR-0096, determination 7): a withdrawn `AllowSecret` thereby takes effect at
    // the next pull -- level-triggered like everything else (ADR-0010).
    let login = registry_login(context, workload.image().reference(), workload.name());
    let (resolved, source) = acquire::acquire(
        &store,
        workload.image().reference(),
        workload.image().pull_policy(),
        login.clone(),
    )
    .await?;
    let _ = source;

    let layer_dirs = bundle::layer_dirs(&store, &resolved.layers);
    let mut volumes = volume_mounts(
        paths,
        &store,
        workload,
        instance,
        context.userns,
        context.volume_keys,
        login,
    )
    .await?;

    // **A sidecar gets three mounts more** (ADR-0059, determination 5): the workload
    // API socket, the edges and the egress permissions. They stand at fixed paths in
    // the container; where they lie on the node is known by the agent.
    if principal.is_some()
        && let Some(mesh) = context.mesh
    {
        volumes.extend(mesh.mounts.iter().cloned());
    }

    // **And every container gets its own socket** (ADR-0081).
    //
    // Unconditionally, for workload and sidecar: the socket **is** the attestation,
    // whoever reached it is in this container. That is why there is no `else` branch
    // any more -- with one socket per node it was necessary so that two mounts did not
    // point at the same target; now it is a different one per container.
    //
    // The sidecar thereby gets **its** socket and over it its own SVID plus the
    // delegated one of its workload (ADR-0036) -- the same mapping as before, only
    // fastened to the socket instead of to the cgroup.
    //
    // **Before the bundle**, because it is mounted: a bind mount of a source that does
    // not exist fails. The same order as at the network.
    //
    // If it fails, **the container does not start**: a workload without a way to its
    // identity starts up as if nothing were amiss and stands out only at the first
    // connection (ADR-0007).
    if let Some(sockets) = context.workload_api {
        let socket = sockets.ensure(id).map_err(|detail| RuntimeError::Volume {
            volume: format!("workload-api/{id}"),
            detail,
        })?;
        // Writable, because using it means writing into it; the permissions have
        // never authorized there (ADR-0060, ADR-0081 determination 2), and what
        // separates is the mount.
        volumes.push(bundle::VolumeMount {
            source: socket,
            destination: tg_model::mesh::SOCKET_IN_CONTAINER.to_owned(),
            readonly: false,
        });
    }

    // The secrets (ADR-0098). **Only the workload container**, not its sidecar: that
    // one enters its workload's namespace (ADR-0059), but its rootfs is one of its own
    // -- and least privilege gives the deciding vote.
    //
    // **Before the bundle**, for the same reason as the socket: a bind mount of a
    // source that does not exist fails.
    //
    // If it fails, **the container does not start**: a workload that starts up without
    // its password looks as if it were running and stands out only at the first access
    // (ADR-0098, determination 7).
    if let Some(secrets) = context.secrets
        && principal.is_none()
    {
        let held = secrets
            .ensure(id, workload.name())
            .map_err(|detail| RuntimeError::Volume {
                volume: format!("secrets/{id}"),
                detail,
            })?;
        // `None` means: this workload may read no secret -- then no mount arises. An
        // empty directory would be the same for the container and one mount more in
        // the spec.
        if let Some(dir) = held {
            volumes.push(bundle::VolumeMount {
                source: dir,
                destination: tg_model::mesh::SECRETS_IN_CONTAINER.to_owned(),
                // Read-only: what the container writes nobody reads, and the kernel
                // enforces it instead of a check of ours.
                readonly: true,
            });
        }
    }

    // **The network comes before the bundle**, for the spec carries the namespace's
    // path (ADR-0012). If it fails, the container is **not** started: a workload that
    // starts up without its address looks as if it were running and stands out only to
    // whoever wants to address it.
    //
    // **A sidecar enters its workload's namespace**, not one of its own (ADR-0059,
    // determination 3): one instance, one address, two processes. Only so is the
    // upstream reachable over loopback.
    let network_of = principal.unwrap_or_else(|| workload.name());
    let attachment =
        match context.network {
            Some(wiring) => Some(wiring.attach(network_of, instance).map_err(|detail| {
                RuntimeError::Network {
                    instance: id.to_owned(),
                    detail,
                }
            })?),
            None => None,
        };

    let device_edits = devices_for(workload, instance, id, principal, context)?;

    let built = bundle::build(
        &paths.bundles_dir(),
        workload,
        id,
        &layer_dirs,
        &resolved,
        &volumes,
        crate::network::Extras {
            network: attachment.as_ref(),
            // A sidecar gets its own identifier -- otherwise the exception in the
            // rule set would free the workload too (ADR-0060).
            run_as: principal.map(|_| tg_model::mesh::SIDECAR_UID),
            no_seccomp: context.no_seccomp,
            userns: context.userns,
            // **Read per pass**, not at the start (ADR-0086): the surcharge comes in
            // the slice, so after the start. Only for a sidecar -- a declared workload
            // has `<resources>`.
            sidecar_memory: principal
                .and(context.mesh)
                .and_then(|mesh| bundle::sidecar_limit(&mesh.overhead)),
            generation,
            devices: device_edits.as_ref(),
        },
    )?;

    runtime.create(id, built.dir()).await?;
    runtime.start(id).await?;

    // **Only now the redirect** (ADR-0060, determination 3): it must not lie there
    // before somebody is there who listens. Only at the sidecar, for only it is that
    // somebody -- and it applies in the namespace of its workload, which it shares
    // (ADR-0059).
    if let (Some(principal), Some(wiring)) = (principal, context.network) {
        wiring.enforce(&bundle::container_id(principal, instance), principal);
    }

    Ok(Outcome::Started)
}

fn registry_login(
    context: &Context<'_>,
    reference: &str,
    workload: &str,
) -> Option<crate::network::RegistryLogin> {
    let credentials = context.credentials?;
    credentials.for_registry(&tg_model::egress::registry_of(reference), workload)
}

async fn volume_mounts(
    paths: &NodePaths,
    store: &ContentStore,
    workload: &WorkloadType,
    instance: u32,
    userns: Option<crate::userns::Mapping>,
    volume_keys: Option<&crate::volume::Derive>,
    login: Option<crate::network::RegistryLogin>,
) -> Result<Vec<bundle::VolumeMount>, RuntimeError> {
    use tg_defs::{VolumeExt as _, VolumeMode};

    let declared = tg_defs::WorkloadExt::volumes(workload);
    if declared.is_empty() {
        return Ok(Vec::new());
    }

    let local = crate::volume::VolumeStore::open(paths.data_dir())
        .map_err(|err| RuntimeError::Volume {
            volume: "<storage>".to_owned(),
            detail: err.to_string(),
        })?
        .mapped(userns)
        .keyed(volume_keys.cloned());

    let mut mounts = Vec::with_capacity(declared.len());
    for volume in declared {
        let fail = |detail: String| RuntimeError::Volume {
            volume: volume.name().to_owned(),
            detail,
        };

        let source = match volume.mode() {
            VolumeMode::ReadWrite => {
                let name =
                    tg_model::storage::volume_of(volume.name(), VolumeMode::ReadWrite, instance);
                let bytes = volume.size().ok_or_else(|| {
                    // Cannot occur: the ingest check refuses a writable volume without
                    // a size (phase 10a). An `unwrap` would be wrong all the same --
                    // a privileged process runs here.
                    fail("no size declared".to_owned())
                })?;

                // **Before** the mount, and that is the whole point in time (ADR-0063):
                // `resize` demands an unmounted volume, and here it is surely one. A
                // running container is not halted for it -- a number in a definition
                // must trigger no restart (ADR-0010).
                let (_, sizing) = local
                    .provision(&name, bytes)
                    .map_err(|err| fail(err.to_string()))?;
                match &sizing {
                    Sizing::Created | Sizing::Unchanged => {}
                    // Reported, not concealed: a size that has no effect must not look
                    // like one that does. And not aborted: the workload ran with it
                    // before (ADR-0019).
                    Sizing::Grown { .. } => tracing::info!(volume = %name, %sizing, "the volume"),
                    Sizing::ShrinkRefused { .. } | Sizing::GrowthFailed { .. } => {
                        tracing::warn!(volume = %name, %sizing, "the volume");
                    }
                }
                local.mount(&name).map_err(|err| fail(err.to_string()))?
            }
            VolumeMode::ReadOnly => {
                let reference = volume
                    .source()
                    .ok_or_else(|| fail("no source declared".to_owned()))?;
                crate::volume::materialize_shared(store, reference, login.clone())
                    .await
                    .map_err(|err| fail(err.to_string()))?
            }
        };

        mounts.push(bundle::VolumeMount {
            source,
            destination: volume.path().to_owned(),
            readonly: volume.mode() == VolumeMode::ReadOnly,
        });
    }

    Ok(mounts)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeRuntime {
        dir: tempfile::TempDir,
        log: std::path::PathBuf,
    }

    impl FakeRuntime {
        fn new(body: &str) -> Self {
            use std::os::unix::fs::PermissionsExt as _;

            let dir = tempfile::tempdir().expect("tempdir");
            let bin = dir.path().join("tg-fake-runtime");
            let log = dir.path().join("calls");
            std::fs::write(
                &bin,
                format!("#!/bin/sh\necho \"$@\" >> '{}'\n{body}\n", log.display()),
            )
            .expect("the script");
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
                .expect("executable");

            Self { dir, log }
        }

        fn runtime(&self) -> OciRuntime {
            let bin = self.dir.path().join("tg-fake-runtime");
            OciRuntime::discover(
                &[bin.to_str().expect("the path")],
                self.dir.path().join("root"),
            )
            .expect("the fake runtime")
        }

        fn calls(&self) -> String {
            std::fs::read_to_string(&self.log).unwrap_or_default()
        }
    }

    const DEF: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="unclear" kind="service">
    <image reference="registry.invalid/api:1"/>
  </workload>
</workloads>"#;

    fn context() -> Context<'static> {
        Context {
            devices: None,
            volume_keys: None,
            no_seccomp: false,
            userns: None,
            now: &|| 0,
            fence_margin: 0,
            wake: None,
            keep_snapshots: 3,
            quorum: tg_model::Quorum::Available,
            network: None,
            mesh: None,
            workload_api: None,
            secrets: None,
            credentials: None,
            empty: &|| crate::reconcile::EmptyMeans::NothingWanted,
        }
    }

    async fn outcome_of(fake: &FakeRuntime) -> Result<Outcome, RuntimeError> {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = NodePaths::new(dir.path());
        let set = tg_defs::from_str(DEF).expect("the definition");
        let workload = &set.workloads()[0];

        reconcile_one(
            &paths,
            &fake.runtime(),
            &Target {
                workload,
                instance: 0,
                principal: None,
                generation: 0,
                has_sidecar: false,
            },
            &context(),
        )
        .await
    }

    #[tokio::test]
    async fn an_unreadable_state_touches_nothing() {
        let fake = FakeRuntime::new(
            "for arg in \"$@\"; do\n             if [ \"$arg\" = state ]; then printf '%s' '{\"id\":\"x\",\"status\":\"zombie\"}'; fi\n             done\nexit 0",
        );

        let outcome = outcome_of(&fake).await.expect("not knowing is no failure");

        assert!(
            matches!(outcome, Outcome::Unclear(_)),
            "an unknown state must not be treated like `Absent`, was: {outcome}"
        );

        let calls = fake.calls();
        for forbidden in ["create", "start", "delete", "kill"] {
            assert!(
                !calls.contains(forbidden),
                "the runtime was called with `{forbidden}` -- at an unknown state \
                 nothing is touched (ADR-0122): {calls:?}"
            );
        }
        assert!(calls.contains("state"), "it was very much asked: {calls:?}");
    }

    #[tokio::test]
    async fn a_runtime_that_does_not_answer_is_not_a_failure() {
        let fake = FakeRuntime::new("echo 'the service does not answer' >&2\nexit 1");

        let outcome = outcome_of(&fake)
            .await
            .expect("a failed call is no information, no failure");

        assert_eq!(
            outcome,
            Outcome::Unclear("the state is not queryable"),
            "a runtime that does not answer must not drag the dependants along (ADR-0061)"
        );
    }

    #[tokio::test]
    async fn an_absent_container_is_still_started() {
        let fake = FakeRuntime::new(
            "for arg in \"$@\"; do\n             if [ \"$arg\" = state ]; then echo 'container does not exist' >&2; exit 1; fi\n             done\nexit 0",
        );

        let outcome = outcome_of(&fake).await;
        assert!(
            !matches!(outcome, Ok(Outcome::Unclear(_))),
            "`Absent` is no not-knowing -- there a start happens, was: {outcome:?}"
        );
    }
}
