//! The secrets arrive in the container (ADR-0098).
//!
//! # What is checked here
//!
//! Not the delivery -- that lies in `tg_agent::secrets` and has its witnesses
//! there at a real tmpfs. Here it is about the **wiring**: that the path the
//! seam delivers lands as a mount in the spec and the container reads it.
//!
//! In addition the assurance ADR-0016 has always made and nobody has checked:
//! **never in the environment**. Measured, `env` in the spec comes solely from
//! the image -- the container writes its own dump, and the secret does not
//! stand in it.
//!
//! The container **witnesses it itself** -- it reads its directory and writes
//! what it found. Looking from outside would be weaker: then the test would
//! check the state it produced itself.
//!
//! # The sidecar gets none
//!
//! Determination 4, and it is half this test's statement: a provided seam that
//! delivers a directory for **every** call would pass the first half too --
//! the sidecar would then get its workload's secrets without anybody having
//! decided it.
//!
//! `#[ignore]`: demands `CAP_SYS_ADMIN` (overlayfs) and an OCI runtime. Run
//! with `cargo xtask storage`.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

mod support;
use support::{Fixture, await_line, build_layer};

use tg_runtime::content::{ContentStore, Digest256};
use tg_runtime::network::Secrets;
use tg_runtime::oci::{DEFAULT_RUNTIMES, OciRuntime};
use tg_runtime::reconcile::{Context, EmptyMeans};
use tg_runtime::resolved::ResolvedImage;
use tg_runtime::state::DesiredState;

/// A workload that reads its secrets directory and writes down what it sees.
///
/// **`read` and a glob instead of `cat` and `ls`**: the layer from
/// `build_layer` brings `sh` and `sleep` along and nothing else, and extending
/// it concerns the neighbouring tests. The shell can do both itself, and the
/// witness file becomes sharper for it -- `read` reads the **content**, the
/// glob names the **file**.
///
/// **`export -p` stands first, and the order is the whole statement**:
/// `read p` puts the plaintext into a shell variable, and after it the dump
/// showed it -- a false hit of its own assertion. The environment is dumped
/// **before** the container touches the secret.
const DOCUMENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="NAME" kind="service">
    <image reference="registry.invalid/probe:1"/>
    <command>
      <arg>/bin/sh</arg>
      <arg>-c</arg>
      <arg>export -p &gt; /tmp/environ; read p &lt; /run/tardigrade/secrets/db-password; echo "$p" &gt; /tmp/seen; echo /run/tardigrade/secrets/* &gt;&gt; /tmp/seen; sleep 600</arg>
    </command>
  </workload>
</workloads>"#;

/// A provided seam: it lays down an ordinary directory.
///
/// **No tmpfs**, and that is deliberate: what `mount(tmpfs)` does is
/// substantiated in `tg_agent::secrets` at real mounts. Here the object is the
/// spec, and a directory suffices for that -- the test thereby needs one
/// privilege less.
#[derive(Debug)]
struct Handed {
    root: PathBuf,
    /// Who the seam was asked about -- half the assurance.
    asked: Mutex<Vec<(String, String)>>,
}

impl Secrets for Handed {
    fn ensure(&self, container: &str, workload: &str) -> Result<Option<PathBuf>, String> {
        if let Ok(mut guard) = self.asked.lock() {
            guard.push((container.to_owned(), workload.to_owned()));
        }

        let dir = self.root.join(container);
        std::fs::create_dir_all(&dir).map_err(|err| err.to_string())?;
        std::fs::write(dir.join("db-password"), b"hunter2").map_err(|err| err.to_string())?;

        Ok(Some(dir))
    }

    fn held(&self) -> Vec<String> {
        Vec::new()
    }

    fn release(&self, _container: &str) {}
}

/// **A real container reads its secrets.**
#[tokio::test(flavor = "multi_thread")]
#[ignore = "demands CAP_SYS_ADMIN and an OCI runtime; via `cargo xtask storage`"]
async fn a_real_container_reads_its_secrets() {
    let dir = tempfile::tempdir().expect("tempdir");
    let name = "secrets-probe";
    let paths = tg_runtime::NodePaths::new(dir.path());
    let runtime =
        OciRuntime::discover(DEFAULT_RUNTIMES, paths.runtime_root()).expect("no OCI runtime");

    let document = DOCUMENT.replace("NAME", name);
    let id = tg_runtime::bundle::container_id(name, 0);
    // **`rootfs` set although the reconciler only builds the bundle later**:
    // the path is computable, and `Fixture::drop` unmounts exactly it. With
    // `None` the overlayfs would stay standing after a **red** run and hold
    // its temp directory fast -- measured: four of them after four
    // counter-checks, around 400 MiB each.
    let _fixture = Fixture {
        id: id.clone(),
        root: paths.runtime_root().clone(),
        rootfs: Some(paths.bundles_dir().join(name).join("rootfs")),
    };

    seed(dir.path(), &paths, &document);

    let handed = Handed {
        root: dir.path().join("provided"),
        asked: Mutex::new(Vec::new()),
    };
    let handed = Arc::new(handed);
    let context = Context {
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
        secrets: Some(handed.as_ref()),
        credentials: None,
        empty: &|| EmptyMeans::NothingWanted,
    };

    let report = tg_runtime::reconcile::once(&paths, &runtime, &context)
        .await
        .expect("the pass");
    assert!(report.failed.is_empty(), "{report:?}");

    // The container witnesses itself what it saw.
    let proof = paths
        .bundles_dir()
        .join(name)
        .join("rootfs")
        .join("tmp")
        .join("seen");
    let seen = await_line(&proof, "db-password").unwrap_or_else(|last| last);

    assert!(
        seen.contains("hunter2"),
        "the container must be able to read the plaintext: {seen:?}"
    );
    assert!(
        seen.contains("db-password"),
        "and list the directory: {seen:?}"
    );

    // **And never in the environment** (ADR-0016, ADR-0098 determination 1).
    // The reason stands in ADR-0098: `/proc/<pid>/environ`, core dumps,
    // process lists and every child inherit it. Measured, `env` in the spec
    // comes **solely** from the image (`bundle::spec_for` takes it as an
    // argument, and the only caller passes `image.env`) -- so the assurance
    // held, and nobody had checked it.
    //
    // The container witnesses it itself, and the first half carries: a dump
    // that is empty or never arose would not contain the plaintext either.
    // **The marker is `PATH`, not the secret's name** -- and that is a
    // finding: a wait function with **one** hard-written marker for both
    // callers stood here, and it was `db-password`. The environment dump
    // however **never** contains that by assurance (the assertion three lines
    // further forbids it), so this test waited out the full deadline on
    // **every** run: measured 20.28 s, and green.
    let environ = await_line(
        &paths
            .bundles_dir()
            .join(name)
            .join("rootfs")
            .join("tmp")
            .join("environ"),
        "PATH",
    )
    .unwrap_or_else(|last| last);
    assert!(
        environ.contains("PATH"),
        "the environment dump is unusable: {environ:?}"
    );
    assert!(
        !environ.contains("hunter2") && !environ.contains("db-password"),
        "a secret in the environment: {environ:?}"
    );

    // **Half the assurance** (determination 4): it was asked only for the
    // workload. Without it the test would not show that a sidecar gets none --
    // there is none here, but the reconciler nevertheless asks the question
    // only once, and with the workload's name.
    let asked = handed.asked.lock().expect("the lock").clone();
    assert_eq!(
        asked,
        vec![(id.clone(), name.to_owned())],
        "one ask per container, with the name of its workload"
    );

    let _ = runtime.kill(&id, "SIGKILL").await;
    let _ = runtime.delete(&id, true).await;
}

/// Lays down the layer, the resolution and the desired state.
///
/// The layer arises via `build_layer` (the same source as the neighbours) and
/// is packed from there into a tar: `once` resolves the image over the content
/// store, and building a bundle by hand would leave out exactly the path this
/// test checks.
fn seed(dir: &Path, paths: &tg_runtime::NodePaths, document: &str) {
    let layer = dir.join("layer");
    build_layer(&layer);
    // `/tmp` at 1777 as in every real image -- the container writes its
    // witness file there.
    std::fs::create_dir_all(layer.join("tmp")).expect("tmp");
    std::fs::create_dir_all(layer.join("run")).expect("run");

    let store = ContentStore::open(paths.content_dir()).expect("the store");
    let blob = tar_of(&layer);
    let digest = Digest256::of(&blob);
    store.verify_blob(&digest, &blob).expect("the blob");
    store
        .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &blob)
        .expect("unpack");

    ResolvedImage {
        reference: "registry.invalid/probe:1".to_owned(),
        layers: vec![digest],
        entrypoint: vec!["/bin/sh".to_owned()],
        env: vec!["PATH=/bin".to_owned()],
    }
    .save(&store)
    .expect("the record");

    let set = tg_defs::from_str(document).expect("the definition parses");
    let desired = DesiredState::open(paths.data_dir()).expect("the cache");
    desired.put(&set.workloads()[0]).expect("the desired state");
    desired
        .assign("secrets-probe", &[0])
        .expect("the assignment");
}

/// A tar over this tree.
fn tar_of(root: &Path) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    builder.follow_symlinks(false);
    builder.mode(tar::HeaderMode::Complete);
    builder.append_dir_all(".", root).expect("the tar");
    builder.into_inner().expect("the tar")
}
