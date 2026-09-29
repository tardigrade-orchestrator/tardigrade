//! What is common to the tests that run **real containers** with the real
//! `tg-proxy`.
//!
//! Two files do that: `sidecar_image.rs` (carries the image, and the identity chain)
//! and `mesh_container.rs` (two of them, and mTLS between them). Both need the same
//! image from `cargo xtask image`, the same seeding into the content store and the
//! same clearing away -- here it stands **once**.
//!
//! `#![allow(dead_code)]`: every test binary compiles this module for itself, and
//! none uses everything. Without the permission the price for a shared module would
//! be a warning per unused building block -- and `-D warnings` in the Definition of
//! Done turns that into an error.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use tg_runtime::content::{ContentStore, Digest256};
use tg_runtime::resolved::ResolvedImage;

/// Where `cargo xtask image` files the image.
pub(crate) const SHARED: &str = "target/xtask-image";

/// Under which reference.
pub(crate) const REFERENCE: &str = "tardigrade.local/tg-proxy:dev";

/// Where the wrapper script writes -- in the container.
pub(crate) const PROOF: &str = "/tmp/proof";

pub(crate) fn libraries(binary: &str) -> Vec<String> {
    let out = std::process::Command::new("ldd")
        .arg(binary)
        .output()
        .expect("ldd");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            line.split_whitespace()
                .find(|part| part.starts_with('/') && Path::new(part).is_file())
                .map(str::to_owned)
        })
        .collect()
}

pub(crate) fn append(tar: &mut tar::Builder<Vec<u8>>, source: &str, inside: &str) {
    let bytes = std::fs::read(source).expect("readable");
    let mut header = tar::Header::new_gnu();
    header.set_mode(0o755);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    tar.append_data(&mut header, inside, bytes.as_slice())
        .expect("file");
}

/// Waits until the witness file contains a **marker**.
///
/// # Why not for the first content
///
/// The predecessor returned as soon as the file contained anything -- and a container
/// writes **line by line**. Measured, a sidecar's first line was the warning "no
/// `--policy` given", and "the sidecar is ready" came later: under load the test read
/// the first line and failed at an assurance about the second, with the message "the
/// identity path does not carry". A race in the test rig that looks like an error in
/// the code -- and exactly the wrong trail.
///
/// What is waited for is therefore the **statement**, not the transient (the same
/// correction as at the slice witness in `tg-agent`). At expiry what stood there until
/// then comes back: without the intermediate state nobody knows how far it got.
pub(crate) fn await_line(path: &Path, needle: &str) -> Result<String, String> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let mut last = String::new();
    while std::time::Instant::now() < deadline {
        if let Ok(text) = std::fs::read_to_string(path) {
            if text.contains(needle) {
                return Ok(text);
            }
            last = text;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    Err(last)
}

/// Clears the container away, even when the test fails.
///
/// # Why the runtime has to be named
///
/// The first throw called `crun` -- hard, and that was **wrong**: `DEFAULT_RUNTIMES`
/// names youki first (ADR-0003, youki-first), and in this environment both lie in the
/// `PATH`. The container was therefore produced by youki and cleared away by crun,
/// and crun does not know the state of a foreign runtime -- the clearing away came to
/// nothing.
///
/// **Measured**, the consequence was not merely a container that stays standing:
/// `bundle::build` mounts the rootfs as overlayfs, and the reconciler does not unmount
/// it again (ADR-0058, open point) -- that is done by the runtime's `delete` at the
/// clearing away. If that stayed out, the mount held the `TempDir` fast,
/// `TempDir::drop` cannot remove it, and the next run laid another one beside it. The
/// whole privileged run left **two** mounts of about 400 MiB each behind, both from
/// this file.
///
/// # And why the unmounting nevertheless belongs to it
///
/// The obvious conclusion was that the right runtime takes it along. **That too is
/// measured and wrong**: with `youki delete` the same two mounts stayed lying. The
/// tests that leave nothing behind come past a reconciler `stop` in the run; here the
/// container ends by itself and is never stopped.
///
/// Those are thereby **two resources and not two mechanisms**: the container belongs
/// to the runtime, the mount to the kernel. Searched for instead of booked -- a list
/// would have to be kept by this test, and whoever forgets a path notices it only
/// when the disk is full. Deepest first, so that a mount under another goes first.
pub(crate) struct Cleanup {
    /// The container's identifier.
    id: String,
    /// The state directory the runtime got.
    root: PathBuf,
    /// The name of the runtime that laid it out.
    runtime: String,
    /// Under which directory unmounting happens.
    under: PathBuf,
}

impl Cleanup {
    /// Takes the container and everything mounted under `under`.
    ///
    /// **Named fields and a constructor**, not four positions: with four settings of
    /// the same kind -- two paths and two names -- nobody at the call site sees any
    /// more what belongs where.
    pub(crate) fn new(id: String, root: PathBuf, runtime: String, under: PathBuf) -> Self {
        Self {
            id,
            root,
            runtime,
            under,
        }
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for args in [vec!["kill", &self.id, "KILL"], vec!["delete", &self.id]] {
            let _ = std::process::Command::new(&self.runtime)
                .arg("--root")
                .arg(&self.root)
                .args(&args)
                .output();
        }

        let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
            return;
        };
        let prefix = self.under.display().to_string();
        let mut targets: Vec<&str> = mounts
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1))
            .filter(|target| target.starts_with(&prefix))
            .collect();
        targets.sort_unstable_by_key(|target| std::cmp::Reverse(target.len()));
        for target in targets {
            // `\040` is `/proc/mounts`'s encoding for a space.
            let target = target.replace("\\040", " ");
            let _ = tg_syscall::mount::unmount_at(Path::new(&target));
        }
    }
}

// ============================================================ The helpers

/// The real layer, taken over from `cargo xtask image`'s store.
///
/// **Byte for byte**, not rebuilt: the digest is checked at the filing (ADR-0003), so
/// a copying error would stand out and not slip through.
pub(crate) fn base_layer(store: &ContentStore) -> Digest256 {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("root")
        .to_path_buf();
    let shared = ContentStore::open(root.join(SHARED).join("content"))
        .expect("`cargo xtask image`'s store is missing -- does it run in the xtask?");
    let real = ResolvedImage::load(&shared, REFERENCE).unwrap_or_else(|| {
        panic!(
            "no record for {REFERENCE} in {} -- `cargo xtask image` lays it out",
            root.join(SHARED).display()
        )
    });
    let digest = real.layers.first().expect("the image has no layer").clone();

    // **Beside the store, not in it** (ADR-0126, determination 1): the store no
    // longer keeps blobs. `cargo xtask image` lays the tar beside it as a dev
    // artifact, and `verify_blob` holds it below against the digest from the record --
    // the byte-for-byte assurance thereby stays as it was.
    let tar = root.join(SHARED).join("layer.tar");
    let blob = std::fs::read(&tar).unwrap_or_else(|err| {
        panic!(
            "{} is missing ({err}) -- `cargo xtask image` lays it out",
            tar.display()
        )
    });
    store.verify_blob(&digest, &blob).expect("blob");
    store
        .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &blob)
        .expect("unpack");

    digest
}

/// A layer **above it** with `/bin/sh` and the wrapper script.
///
/// Two reasons for the second layer instead of an extended image:
///
/// - A container without a shell cannot steer its output into a file, and the output
///   **is** the statement here.
/// - The real image stays minimal: it contains no shell, and it shall not
///   (ADR-0017).
///
/// Incidentally that runs the **multi-layer** overlay path (ADR-0052), which is
/// otherwise checked only at staged layers.
pub(crate) fn probe_layer(store: &ContentStore, script: &str) -> Digest256 {
    let mut tar = tar::Builder::new(Vec::new());

    for dir in ["bin", "lib64", "usr", "usr/lib64"] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(0o755);
        header.set_size(0);
        header.set_cksum();
        tar.append_data(&mut header, format!("{dir}/"), std::io::empty())
            .expect("directory");
    }

    append(&mut tar, "/bin/sh", "bin/sh");
    for library in libraries("/bin/sh") {
        append(&mut tar, &library, library.trim_start_matches('/'));
    }

    let mut header = tar::Header::new_gnu();
    header.set_mode(0o755);
    header.set_size(script.len() as u64);
    header.set_cksum();
    tar.append_data(&mut header, "wrapper", script.as_bytes())
        .expect("script");

    let blob = tar.into_inner().expect("archive");
    let digest = Digest256::of(&blob);
    store.verify_blob(&digest, &blob).expect("blob");
    store
        .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &blob)
        .expect("unpack");

    digest
}

/// Files the record -- **lowest layer first** (ADR-0003).
pub(crate) fn seed(store: &ContentStore, reference: &str, layers: &[Digest256]) {
    ResolvedImage {
        reference: reference.to_owned(),
        layers: layers.to_vec(),
        entrypoint: vec!["/wrapper".to_owned()],
        env: vec!["PATH=/usr/local/bin:/bin".to_owned()],
    }
    .save(store)
    .expect("record");
}

/// The definition that starts the image.
///
/// `<command>` overrides entrypoint and cmd (schema, ADR-0003) -- the same place at
/// which the derived sidecar unit carries its `argv[0]` (ADR-0059).
pub(crate) fn definition(name: &str, reference: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="{name}" kind="service">
    <image reference="{reference}"/>
    <command>
      <arg>/wrapper</arg>
    </command>
  </workload>
</workloads>"#
    )
}
