//! Builds the sidecar image — without a registry, into the local content store.
//!
//! ADR-0059 makes the proxy image a **setting per node** (`--proxy-image`), i.e.
//! an artifact an operator provides. Only there was none: the plan carried "the
//! sidecar image still does not exist" as an open point. The consequence was
//! larger than the missing file: **the real `tg-proxy` had never run in a
//! container.**
//!
//! **Without a registry**, because ADR-0019 says a locally present image is
//! taken locally: the puller asks the content store first, and a record there is
//! as good as a pull.
//!
//! It lies in the `xtask` for the same reason as `cargo xtask identity`
//! (ADR-0023): a tool that builds images does not belong in the same program
//! that starts them.

use std::path::{Path, PathBuf};

use tg_model::mesh::{
    EDGES_IN_CONTAINER, EGRESS_IN_CONTAINER, PROGRAM_IN_CONTAINER, ROLE_IN_CONTAINER,
    SOCKET_IN_CONTAINER,
};
use tg_runtime::content::{ContentStore, Digest256};
use tg_runtime::resolved::ResolvedImage;

use crate::TaskError;

/// The reference under which the image is stored if none is named.
pub(crate) const DEFAULT_REFERENCE: &str = "tardigrade.local/tg-proxy:dev";

/// Where the layer's tar lies — beside the store, not in it (ADR-0126).
pub(crate) const LAYER_FIXTURE: &str = "layer.tar";

/// Builds the image and puts it into the content store under `data_dir`.
///
/// # Errors
///
/// [`TaskError`] if the binary is missing, `ldd` does not run or the store
/// refuses to store it.
pub(crate) fn run(root: &Path, data_dir: &Path, reference: &str) -> Result<(), TaskError> {
    let binary = root.join("target/debug/tg-proxy");
    if !binary.is_file() {
        return Err(TaskError::Image {
            detail: format!(
                "{} is missing — `cargo build -p tg-proxy`, then try again",
                binary.display()
            ),
        });
    }

    let layer = layer(&binary)?;
    let digest = Digest256::of(&layer);

    let store = ContentStore::open(data_dir.join("content")).map_err(|err| TaskError::Image {
        detail: format!("content store under {}: {err}", data_dir.display()),
    })?;
    store
        .verify_blob(&digest, &layer)
        .map_err(|err| TaskError::Image {
            detail: format!("verify blob: {err}"),
        })?;
    // **The tar lies beside the store, not in it** (ADR-0126, D1). Since then
    // the store keeps no blobs; the harnesses that take the layer over into a
    // **store of their own** need the bytes byte for byte, though — a rebuilt
    // layer would have a different digest.
    let tar = data_dir.join(LAYER_FIXTURE);
    std::fs::write(&tar, &layer).map_err(|err| TaskError::Image {
        detail: format!("{}: {err}", tar.display()),
    })?;
    store
        .unpack_layer(&digest, "application/vnd.oci.image.layer.v1.tar", &layer)
        .map_err(|err| TaskError::Image {
            detail: format!("unpack: {err}"),
        })?;

    ResolvedImage {
        reference: reference.to_owned(),
        layers: vec![digest.clone()],
        // The derived unit overrides both with `<command>` (ADR-0003, ADR-0059)
        // — the entrypoint here is the honest setting for the case that somebody
        // starts the image by hand.
        entrypoint: vec![PROGRAM_IN_CONTAINER.to_owned()],
        env: vec!["PATH=/usr/local/bin:/bin".to_owned()],
    }
    .save(&store)
    .map_err(|err| TaskError::Image {
        detail: format!("store record: {err}"),
    })?;

    eprintln!(
        "image: {reference} lies in {} ({} MiB, layer {})",
        data_dir.join("content").display(),
        layer.len() / 1024 / 1024,
        digest,
    );
    eprintln!("image: for a run `tg-agent --proxy-image {reference}`.");
    eprintln!(
        "image: a dev artifact — in operation the image comes from a build \
         pipeline (ADR-0059)."
    );

    Ok(())
}

/// The layer as an uncompressed tar.
///
/// **Uncompressed**, because the store is told the media type and can do both; a
/// `gzip` would save space on a developer's disk and cost the readability of the
/// product.
fn layer(binary: &Path) -> Result<Vec<u8>, TaskError> {
    let mut tar = tar::Builder::new(Vec::new());

    // The directories the program and the mounts need.
    //
    // `/tmp` at `1777`, as in every real image: since ADR-0060 the sidecar runs
    // under an **identifier of its own** (65532) and may write nowhere else. An
    // image that does not tolerate the identifier thereby stands out at the
    // start and not later.
    let mut dirs: Vec<String> = vec![
        "usr".to_owned(),
        "usr/local".to_owned(),
        "usr/local/bin".to_owned(),
        "usr/lib".to_owned(),
        "usr/lib64".to_owned(),
        "lib".to_owned(),
        "lib64".to_owned(),
        "proc".to_owned(),
        "dev".to_owned(),
        "sys".to_owned(),
        "tmp".to_owned(),
    ];
    // And the directories of the three mount points plus the socket — **computed
    // from the constants**, not copied: if a path moves, the directory moves
    // with it (ADR-0059).
    for path in [
        SOCKET_IN_CONTAINER,
        EDGES_IN_CONTAINER,
        EGRESS_IN_CONTAINER,
        ROLE_IN_CONTAINER,
    ] {
        let mut current = PathBuf::new();
        for part in Path::new(path)
            .parent()
            .unwrap_or(Path::new("/"))
            .components()
            .skip(1)
        {
            current.push(part);
            let name = current.display().to_string();
            if !dirs.contains(&name) {
                dirs.push(name);
            }
        }
    }
    dirs.sort();

    for dir in &dirs {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(if dir == "tmp" { 0o1777 } else { 0o755 });
        header.set_size(0);
        header.set_cksum();
        tar.append_data(&mut header, format!("{dir}/"), std::io::empty())
            .map_err(|err| TaskError::Image {
                detail: format!("directory {dir}: {err}"),
            })?;
    }

    // **Stripped**, and that is no cosmetics: the debug binary is 198 MiB,
    // stripped it is 20. An image is **copied and unpacked** — per run in the
    // harness —, and the symbols contribute nothing to that. Measured, the
    // unstripped way filled the disk, because every run left 400 MiB behind.
    //
    // If `strip` fails, the original is taken: a large image is better than
    // none.
    let stripped = strip(binary);
    append(
        &mut tar,
        stripped.as_deref().unwrap_or(binary),
        PROGRAM_IN_CONTAINER.trim_start_matches('/'),
    )?;

    // **The libraries come from `ldd`**, not from a list. A hand-maintained list
    // would be the construction this tree has measured several times as a source
    // of error — and it would stand out only in the container, as "not found".
    for library in libraries(binary)? {
        let inside = library.trim_start_matches('/').to_owned();
        append(&mut tar, Path::new(&library), &inside)?;
    }

    tar.into_inner().map_err(|err| TaskError::Image {
        detail: format!("archive: {err}"),
    })
}

/// A stripped copy of the binary, if `strip` can produce one.
///
/// The copy lies beside the original and is not cleared away: it is a product in
/// the `target/` tree like any other, and the next run overwrites it.
fn strip(binary: &Path) -> Option<PathBuf> {
    let copy = binary.with_extension("stripped");
    std::fs::copy(binary, &copy).ok()?;

    let out = std::process::Command::new("strip")
        .arg(&copy)
        .output()
        .ok()?;
    if !out.status.success() {
        eprintln!(
            "image: `strip` refused, the image carries the symbols along: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return None;
    }

    Some(copy)
}

/// Puts a file with its permissions into the archive.
fn append<W: std::io::Write>(
    tar: &mut tar::Builder<W>,
    from: &Path,
    to: &str,
) -> Result<(), TaskError> {
    let bytes = std::fs::read(from).map_err(|err| TaskError::Image {
        detail: format!("{}: {err}", from.display()),
    })?;

    let mut header = tar::Header::new_gnu();
    header.set_mode(0o755);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    tar.append_data(&mut header, to, bytes.as_slice())
        .map_err(|err| TaskError::Image {
            detail: format!("{to}: {err}"),
        })
}

/// A binary's dynamic libraries, absolute.
fn libraries(binary: &Path) -> Result<Vec<String>, TaskError> {
    let out = std::process::Command::new("ldd")
        .arg(binary)
        .output()
        .map_err(|err| TaskError::Image {
            detail: format!("ldd: {err}"),
        })?;

    let text = String::from_utf8_lossy(&out.stdout);
    let mut found = Vec::new();
    for line in text.lines() {
        // Two forms: "name => /path (address)" and "/path (address)" — the
        // second is the loader.
        let candidate = line
            .split_whitespace()
            .find(|part| part.starts_with('/') && !part.starts_with("/lib/ld"));
        if let Some(path) = candidate
            && Path::new(path).is_file()
            && !found.contains(&path.to_owned())
        {
            found.push(path.to_owned());
        }
    }

    if found.is_empty() {
        return Err(TaskError::Image {
            detail: format!("ldd names no library for {}", binary.display()),
        });
    }

    Ok(found)
}
