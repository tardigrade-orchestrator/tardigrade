//! The content-addressed store for image layers.
//!
//! ADR-0003: layers lie under `/var/lib/tardigrade/content`, addressed over their
//! sha256 digest. A layer that is there already is not loaded again -- that is the
//! dedup property a CAS brings along for free.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::RuntimeError;

const LAYERS: &str = "layers/sha256";

const LEGACY_BLOBS: &str = "blobs";

const MARKER: &str = ".complete";

pub const LAYER_FORMAT: &str = "tardigrade-layer 2\n";

#[derive(Debug, Clone)]
pub struct ContentStore {
    root: PathBuf,
    userns: Option<crate::userns::Mapping>,
}

impl ContentStore {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, RuntimeError> {
        let root = root.into();
        let path = root.join(LAYERS);
        fs::create_dir_all(&path)
            .map_err(|source| RuntimeError::io("laying out the store", &path, source))?;
        // **The bolt sits at the root** (ADR-0017): an unpacked layer keeps the
        // permissions from the tar, setuid included, and the files belong to `root`
        // because the agent runs privileged.
        seal(&root, "closing the store")?;

        Ok(Self { root, userns: None })
    }

    #[must_use]
    pub fn mapped(mut self, userns: Option<crate::userns::Mapping>) -> Self {
        self.userns = userns;
        self
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    #[must_use]
    pub fn layer_path(&self, digest: &Digest256) -> PathBuf {
        self.root.join(LAYERS).join(digest.hex())
    }

    #[must_use]
    pub fn has_layer(&self, digest: &Digest256) -> bool {
        let marker = self.layer_path(digest).join(MARKER);

        fs::read_to_string(marker).is_ok_and(|content| content == LAYER_FORMAT)
    }

    pub fn verify_blob(&self, expected: &Digest256, bytes: &[u8]) -> Result<(), RuntimeError> {
        let actual = Digest256::of(bytes);
        if actual == *expected {
            return Ok(());
        }

        Err(RuntimeError::DigestMismatch {
            expected: expected.to_string(),
            actual: actual.to_string(),
        })
    }

    pub fn unpack_layer(
        &self,
        digest: &Digest256,
        media_type: &str,
        blob: &[u8],
    ) -> Result<PathBuf, RuntimeError> {
        let dir = self.layer_path(digest);
        if self.has_layer(digest) {
            return Ok(dir);
        }

        // Discard the remains of an aborted run instead of building on them.
        if dir.exists() {
            fs::remove_dir_all(&dir)
                .map_err(|source| RuntimeError::io("clearing the layer remains", &dir, source))?;
        }
        fs::create_dir_all(&dir)
            .map_err(|source| RuntimeError::io("the layer directory", &dir, source))?;

        let decoded = decompress(media_type, blob)?;
        let mut archive = tar::Archive::new(decoded.as_slice());
        archive.set_preserve_permissions(true);
        archive.set_unpack_xattrs(true);
        archive
            .unpack(&dir)
            .map_err(|source| RuntimeError::io("unpacking the layer", &dir, source))?;

        // **First unpack, then translate** (ADR-0052). Two passes and not one:
        // `tar::Archive::unpack` brings permissions, xattrs, hardlinks and directories
        // along, and rebuilding that in a loop of our own would mean rewriting
        // unpacking semantics. The `.wh.` markers lie there briefly as files in the
        // process; that is without consequence, because `.complete` arises only
        // afterwards.
        apply_whiteouts(&dir)?;

        // **Shift before the marker falls** (ADR-0091, determination 2). The layer
        // stock is the rootfs's lowerdir, and an overlayfs cannot be idmapped
        // (ADR-0091, measurement 3) -- without this step every file from the image
        // belongs to `nobody` in the container and is not changeable.
        //
        // Before the marker, because an aborted run would otherwise leave a
        // half-shifted layer behind as finished.
        if let Some(mapping) = self.userns {
            crate::userns::shift_tree(&dir, mapping)
                .map_err(|source| RuntimeError::io("mapping the layer", &dir, source))?;
        }

        let marker = dir.join(MARKER);
        fs::write(&marker, LAYER_FORMAT)
            .map_err(|source| RuntimeError::io("the layer marker", &marker, source))?;

        Ok(dir)
    }
}

pub fn seal(dir: &Path, what: &'static str) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|source| RuntimeError::io(what, dir, source))
}

pub fn seal_soft(dir: &Path, what: &'static str) {
    if let Err(err) = seal(dir, what) {
        tracing::error!(path = %dir.display(), error = %err, "{what}");
    }
}

const WHITEOUT: &str = ".wh.";

const OPAQUE: &str = ".wh..wh..opq";

const MARKER_EXCERPT: usize = 64;

#[derive(Debug, PartialEq, Eq)]
enum Mark<'a> {
    Opaque,
    Whiteout(&'a str),
    Plain,
}

fn classify(name: &str) -> Result<Mark<'_>, RuntimeError> {
    if name == OPAQUE {
        return Ok(Mark::Opaque);
    }

    let Some(hidden) = name.strip_prefix(WHITEOUT) else {
        return Ok(Mark::Plain);
    };

    let refuse = |reason| {
        Err(RuntimeError::MalformedWhiteout {
            marker: name.chars().take(MARKER_EXCERPT).collect(),
            reason,
        })
    };

    // The order is the order of the damage: what breaks out first.
    if hidden == ".." {
        return refuse("points out of the layer");
    }
    if hidden.is_empty() || hidden == "." {
        return refuse("names no entry");
    }
    // Neither `/` nor NUL can come here out of `read_dir` -- both are impossible in a
    // Linux file name. The check stands all the same, because this function *is* the
    // boundary: if it one day reads tar headers instead of directory entries, paths in
    // them are very much possible. A backslash is expressly **not** refused: it is an
    // ordinary character, and forbidding it would mean refusing a permissible
    // whiteout.
    if hidden.contains('/') || hidden.contains('\0') {
        return refuse("is no single path component");
    }
    // `.wh..wh.` is reserved by the convention for its own purposes; apart from the
    // opacity above we support none of them. Laying out a character device with such a
    // name would be guessing.
    if hidden.starts_with(WHITEOUT) {
        return refuse("names a reserved marker");
    }

    Ok(Mark::Whiteout(hidden))
}

fn apply_whiteouts(dir: &Path) -> Result<(), RuntimeError> {
    // First collect, then act: deleting and laying out during the reading is a
    // behaviour that looks different per file system.
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(dir).map_err(|source| RuntimeError::io("reading the layer", dir, source))?
    {
        let entry = entry.map_err(|source| RuntimeError::io("a layer entry", dir, source))?;
        entries.push(entry.path());
    }

    for path in entries {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();

        match classify(&name)? {
            Mark::Opaque => {
                mark_opaque(dir)?;
                fs::remove_file(&path).map_err(|source| {
                    RuntimeError::io("clearing the opaque marker", &path, source)
                })?;
            }
            Mark::Whiteout(hidden) => {
                whiteout(dir, hidden)?;
                fs::remove_file(&path).map_err(|source| {
                    RuntimeError::io("clearing the whiteout marker", &path, source)
                })?;
            }
            Mark::Plain => {
                if path.is_dir() {
                    apply_whiteouts(&path)?;
                }
            }
        }
    }

    Ok(())
}

fn whiteout(dir: &Path, name: &str) -> Result<(), RuntimeError> {
    let target = dir.join(name);
    if target.symlink_metadata().is_ok() {
        let removed = if target.is_dir() {
            fs::remove_dir_all(&target)
        } else {
            fs::remove_file(&target)
        };
        removed.map_err(|source| RuntimeError::io("clearing the hidden entry", &target, source))?;
    }

    let handle = std::fs::File::open(dir)
        .map_err(|source| RuntimeError::io("opening the layer directory", dir, source))?;

    rustix::fs::mknodat(
        &handle,
        name,
        rustix::fs::FileType::CharacterDevice,
        rustix::fs::Mode::empty(),
        rustix::fs::makedev(0, 0),
    )
    .map_err(|source| {
        RuntimeError::io(
            "laying out the whiteout",
            &target,
            std::io::Error::from(source),
        )
    })
}

fn mark_opaque(dir: &Path) -> Result<(), RuntimeError> {
    rustix::fs::setxattr(
        dir,
        "trusted.overlay.opaque",
        b"y",
        rustix::fs::XattrFlags::empty(),
    )
    .map_err(|source| {
        RuntimeError::io(
            "making the directory opaque",
            dir,
            std::io::Error::from(source),
        )
    })
}

fn decompress(media_type: &str, blob: &[u8]) -> Result<Vec<u8>, RuntimeError> {
    let mut out = Vec::new();

    if media_type.ends_with("tar+gzip") || media_type.ends_with("tar.gzip") {
        flate2::read::GzDecoder::new(blob)
            .read_to_end(&mut out)
            .map_err(|source| RuntimeError::decompress("gzip", source))?;
    } else if media_type.ends_with("tar+zstd") {
        zstd::stream::copy_decode(blob, &mut out)
            .map_err(|source| RuntimeError::decompress("zstd", source))?;
    } else if media_type.ends_with("tar") {
        out.extend_from_slice(blob);
    } else {
        return Err(RuntimeError::UnknownMediaType {
            media_type: media_type.to_owned(),
        });
    }

    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest256(String);

impl Digest256 {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        Self(hex::encode(digest))
    }

    pub fn parse(value: &str) -> Result<Self, RuntimeError> {
        let hex_part = match value.split_once(':') {
            Some(("sha256", rest)) => rest,
            Some((algorithm, _)) => {
                return Err(RuntimeError::MalformedDigest {
                    value: value.to_owned(),
                    reason: format!("the algorithm '{algorithm}' is not supported, only sha256"),
                });
            }
            None => value,
        };

        if hex_part.len() != 64 || !hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RuntimeError::MalformedDigest {
                value: value.to_owned(),
                reason: "64 hex characters are expected".to_owned(),
            });
        }

        Ok(Self(hex_part.to_ascii_lowercase()))
    }

    #[must_use]
    pub fn hex(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Digest256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Reclaimed {
    pub layers: u64,
    pub records: u64,
    pub bytes: u64,
}

pub fn collect(store: &ContentStore, reachable: &[String]) -> Reclaimed {
    let mut freed = Reclaimed::default();

    // **The blob directory first and entirely** (determination 1): it has not been
    // written since ADR-0126 and is never read. On a node from the time before it
    // still lies there, and nobody else clears it away.
    let blobs = store.root().join(LEGACY_BLOBS);
    if blobs.is_dir() {
        freed.bytes += weight(&blobs);
        if fs::remove_dir_all(&blobs).is_ok() {
            tracing::info!(
                freed = freed.bytes,
                "the blob directory was cleared away (ADR-0126)"
            );
        } else {
            freed.bytes = 0;
        }
    }

    // The records: what the desired state names is kept.
    let wanted: std::collections::BTreeSet<PathBuf> = reachable
        .iter()
        .map(|reference| crate::resolved::record_path_of(store, reference))
        .collect();

    let mut keep: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    if let Ok(entries) = fs::read_dir(crate::resolved::manifests_dir(store)) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if wanted.contains(&path) {
                if let Some(record) = crate::resolved::ResolvedImage::read(&path) {
                    keep.extend(record.layers.iter().map(ToString::to_string));
                }
                continue;
            }
            let size = path.metadata().map(|meta| meta.len()).unwrap_or_default();
            if fs::remove_file(&path).is_ok() {
                freed.records += 1;
                freed.bytes += size;
            }
        }
    }

    // And the layers no remaining record names.
    if let Ok(entries) = fs::read_dir(store.root().join(LAYERS)) {
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !path.is_dir() || keep.contains(&format!("sha256:{name}")) {
                continue;
            }
            let size = weight(&path);
            if fs::remove_dir_all(&path).is_ok() {
                freed.layers += 1;
                freed.bytes += size;
            }
        }
    }

    freed
}

fn weight(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return path.metadata().map(|meta| meta.len()).unwrap_or_default();
    };

    entries
        .flatten()
        .map(|entry| {
            let path = entry.path();
            if path.is_dir() {
                weight(&path)
            } else {
                path.metadata().map(|meta| meta.len()).unwrap_or_default()
            }
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_of_known_input_matches_sha256() {
        // sha256("") is a known value -- catches swaps in the hex encoding.
        assert_eq!(
            Digest256::of(b"").hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn parse_accepts_prefixed_and_bare_hex() {
        let bare = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(Digest256::parse(bare).unwrap().hex(), bare);
        assert_eq!(
            Digest256::parse(&format!("sha256:{bare}")).unwrap().hex(),
            bare
        );
    }

    #[test]
    fn parse_rejects_other_algorithms() {
        let err = Digest256::parse("sha512:abc").unwrap_err();
        assert!(matches!(err, RuntimeError::MalformedDigest { .. }));
    }

    #[test]
    fn parse_rejects_wrong_length() {
        assert!(Digest256::parse("deadbeef").is_err());
    }

    #[test]
    fn verify_blob_rejects_content_that_does_not_match_the_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");
        let wrong = Digest256::of(b"something else");

        let err = store.verify_blob(&wrong, b"payload").unwrap_err();

        assert!(matches!(err, RuntimeError::DigestMismatch { .. }));
    }

    #[test]
    fn verify_blob_keeps_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");
        let digest = Digest256::of(b"payload");

        store.verify_blob(&digest, b"payload").expect("fits");
        store.verify_blob(&digest, b"payload").expect("and again");

        assert!(
            !dir.path().join("blobs").exists(),
            "the blob directory does not even arise any more"
        );
    }

    #[test]
    fn unknown_media_type_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");
        let digest = Digest256::of(b"x");

        let err = store
            .unpack_layer(
                &digest,
                "application/vnd.oci.image.layer.v1.tar+brotli",
                b"x",
            )
            .unwrap_err();

        assert!(matches!(err, RuntimeError::UnknownMediaType { .. }));
    }

    #[test]
    fn layer_without_marker_counts_as_incomplete() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");
        let digest = Digest256::of(b"layer");

        fs::create_dir_all(store.layer_path(&digest)).expect("half a layer directory");

        assert!(!store.has_layer(&digest));
    }
}

#[cfg(test)]
mod whiteout_tests {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::path::{Component, Path};

    use super::{Mark, classify};
    use crate::error::RuntimeError;

    #[test]
    fn a_name_that_merely_resembles_the_prefix_is_plain() {
        for plain in [
            "ordinary",
            ".hidden",
            ".wh",
            ".whisky",
            "wh.foo",
            ".w.h.foo",
            "foo.wh.bar",
        ] {
            assert_eq!(
                classify(plain).expect("must not be refused"),
                Mark::Plain,
                "{plain} is no marker"
            );
        }
    }

    #[test]
    fn the_convention_is_read_as_written() {
        assert_eq!(
            classify(".wh.secret").expect("valid"),
            Mark::Whiteout("secret")
        );
        assert_eq!(classify(".wh..wh..opq").expect("valid"), Mark::Opaque);
    }

    #[test]
    fn a_marker_that_points_out_of_the_layer_is_refused() {
        for hostile in [".wh...", ".wh.", ".wh..", ".wh../", ".wh../../etc"] {
            let err = classify(hostile).expect_err("must be refused");
            let RuntimeError::MalformedWhiteout { marker, reason } = err else {
                panic!("the wrong error kind for {hostile}: {err:?}");
            };
            assert_eq!(marker, hostile, "the message must name the name");
            assert!(!reason.is_empty(), "the message must name the reason");
        }
    }

    #[test]
    fn a_reserved_marker_other_than_opaque_is_refused() {
        for reserved in [".wh..wh.plnk", ".wh..wh.aufs", ".wh..wh..opqx"] {
            assert!(classify(reserved).is_err(), "{reserved} is reserved");
        }
    }

    #[test]
    fn a_long_hostile_marker_is_quoted_only_in_part() {
        let hostile = format!(".wh.{}", "x".repeat(10_000));
        // A long but *valid* name is no refusal -- for the abridgement one is needed
        // that is both.
        let broken = format!(".wh./{}", "x".repeat(10_000));

        assert!(classify(&hostile).is_ok(), "long alone is not wrong");

        let err = classify(&broken).expect_err("must be refused");
        let RuntimeError::MalformedWhiteout { marker, .. } = err else {
            panic!("the wrong error kind");
        };
        assert_eq!(marker.chars().count(), super::MARKER_EXCERPT);
    }

    // =========================================================== The fuzz run

    const DEFAULT_ITERATIONS: u32 = 20_000;

    fn iterations() -> u32 {
        std::env::var("TG_FUZZ_ITERATIONS")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(DEFAULT_ITERATIONS)
    }

    fn fresh_seed() -> u64 {
        RandomState::new().build_hasher().finish() | 1
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % bound as u64).expect("fits")
        }
    }

    const PARTS: &[&str] = &[
        ".wh.",
        ".wh..wh.",
        ".wh..wh..opq",
        ".",
        "..",
        "...",
        "/",
        "\\",
        "wh",
        "a",
        "secret",
        "\u{0}",
        "\u{e4}",
        "\u{1f600}",
        "",
    ];

    fn name(rng: &mut Rng) -> String {
        let parts = 1 + rng.below(4);
        let mut out = String::new();
        for _ in 0..parts {
            out.push_str(PARTS[rng.below(PARTS.len())]);
        }
        out
    }

    fn is_one_plain_component(value: &str) -> bool {
        let mut components = Path::new(value).components();
        let first = components.next();
        components.next().is_none() && matches!(first, Some(Component::Normal(_)))
    }

    #[test]
    fn a_whiteout_is_never_more_than_one_plain_component() {
        let seed = fresh_seed();
        let mut rng = Rng(seed);
        let rounds = iterations();

        let mut refused = 0_u32;
        let mut marks = 0_u32;
        let mut opaque = 0_u32;

        for round in 0..rounds {
            let entry = name(&mut rng);

            match classify(&entry) {
                Err(_) => refused += 1,
                Ok(Mark::Opaque) => opaque += 1,
                Ok(Mark::Plain) => {
                    // A name with the prefix must never pass as an ordinary file --
                    // that would be a deletion that does not take effect, so exactly
                    // the state ADR-0052 abolishes.
                    assert!(
                        !entry.starts_with(super::WHITEOUT),
                        "seed {seed}, round {round}: '{entry}' counted as ordinary"
                    );
                }
                Ok(Mark::Whiteout(hidden)) => {
                    marks += 1;
                    assert!(
                        is_one_plain_component(hidden),
                        "seed {seed}, round {round}: '{entry}' yielded '{hidden}'"
                    );
                }
            }
        }

        // Without these three the run would confirm itself.
        assert!(refused > 0, "seed {seed}: not a single refusal seen");
        assert!(marks > 0, "seed {seed}: not a single marker read");
        assert!(opaque > 0, "seed {seed}: no opaque directory");
    }
}

#[cfg(test)]
mod adr_0126 {
    use super::{ContentStore, Digest256, collect};
    use crate::resolved::ResolvedImage;

    fn layer(store: &ContentStore, content: &[u8]) -> Digest256 {
        let digest = Digest256::of(content);
        let dir = store.layer_path(&digest);
        std::fs::create_dir_all(&dir).expect("layer dir");
        std::fs::write(dir.join(super::MARKER), super::LAYER_FORMAT).expect("marker");
        std::fs::write(dir.join("payload"), content).expect("content");
        digest
    }

    fn record(store: &ContentStore, reference: &str, layers: Vec<Digest256>) {
        ResolvedImage {
            reference: reference.to_owned(),
            layers,
            entrypoint: vec!["/bin/sleep".to_owned()],
            env: Vec::new(),
        }
        .save(store)
        .expect("record");
    }

    #[test]
    fn what_the_desired_state_names_survives() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");

        let stays = layer(&store, b"wanted");
        let goes = layer(&store, b"forgotten");
        record(&store, "registry.invalid/api:2", vec![stays.clone()]);
        record(&store, "registry.invalid/api:1", vec![goes.clone()]);

        let freed = collect(&store, &["registry.invalid/api:2".to_owned()]);

        assert!(
            store.has_layer(&stays),
            "the reachable layer was removed -- that costs a pull nobody demanded"
        );
        assert!(
            !store.has_layer(&goes),
            "the unreachable layer stayed lying"
        );
        assert_eq!(freed.layers, 1);
        assert_eq!(freed.records, 1);
        assert!(freed.bytes > 0, "what was removed is counted (D6)");

        // And the record the desired state names still carries.
        assert!(
            ResolvedImage::load(&store, "registry.invalid/api:2").is_some(),
            "the remaining record must stay usable"
        );
        assert!(
            ResolvedImage::load(&store, "registry.invalid/api:1").is_none(),
            "and the removed one must not come back"
        );
    }

    #[test]
    fn a_shared_layer_belongs_to_whoever_still_needs_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");

        let shared = layer(&store, b"shared");
        record(&store, "registry.invalid/a:1", vec![shared.clone()]);
        record(&store, "registry.invalid/b:1", vec![shared.clone()]);

        collect(&store, &["registry.invalid/a:1".to_owned()]);

        assert!(
            store.has_layer(&shared),
            "a shared layer must not go with the unreachable record"
        );
    }

    #[test]
    fn the_old_blob_directory_is_swept() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");

        let old = dir.path().join("blobs").join("sha256");
        std::fs::create_dir_all(&old).expect("the old layout");
        std::fs::write(old.join("something"), vec![7_u8; 4096]).expect("blob");

        let freed = collect(&store, &[]);

        assert!(
            !dir.path().join("blobs").exists(),
            "the blob directory must disappear entirely"
        );
        assert!(freed.bytes >= 4096, "and it counts along: {freed:?}");
    }
}
