//! The workloads' user namespace (ADR-0091).
//!
//! # What it costs, and why it was measured
//!
//! Without further action everything the agent laid out as `root` is foreign to the
//! container -- measured at a real container:
//!
//! ```text
//! 65534 65534  /            the rootfs belongs to `nobody`
//! ROOT-DENIED               no writing into one's own rootfs
//! VOL-DENIED                no writing into one's own volume
//! ```
//!
//! The rootfs's `upper` **is** the ephemeral volume from phase 2; a container that
//! cannot write there is unusable for most images. That is why three places get the
//! mapped identifier: the layer stock at the unpacking, `upper`/`work` at the bundle
//! build and a volume's root at the mount (ADR-0091, determination 2).
//!
//! # One mapping per node
//!
//! Not per container: the layer stock is **shared** (ADR-0003, one store, one digest),
//! and chowned per range it would no longer be. What a mapping per container would
//! additionally protect -- container against container -- is closed anyway: every
//! instance has its own rootfs and its own volume (ADR-0027).

pub const SIZE: u32 = 65_536;

const _: () = assert!(
    tg_model::mesh::SIDECAR_UID < SIZE,
    "the sidecar's identifier lies outside the mapping -- the exception in the rule \
     set would then hit nobody (ADR-0060, ADR-0091)"
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    base: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappingError {
    TooLow {
        base: u32,
        minimum: u32,
    },
    Overflow {
        base: u32,
    },
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLow { base, minimum } => write!(
                out,
                "{base} lies too low: below {minimum} the mapping collides with the \
                 host's accounts"
            ),
            Self::Overflow { base } => {
                write!(out, "{base} + {SIZE} no longer fits into an identifier")
            }
        }
    }
}

impl std::error::Error for MappingError {}

impl Mapping {
    pub const MINIMUM: u32 = 65_536;

    pub const fn new(base: u32) -> Result<Self, MappingError> {
        if base < Self::MINIMUM {
            return Err(MappingError::TooLow {
                base,
                minimum: Self::MINIMUM,
            });
        }
        if base.checked_add(SIZE).is_none() {
            return Err(MappingError::Overflow { base });
        }
        Ok(Self { base })
    }

    #[must_use]
    pub const fn base(self) -> u32 {
        self.base
    }

    #[must_use]
    pub const fn host_uid(self, in_container: u32) -> Option<u32> {
        if in_container >= SIZE {
            return None;
        }
        Some(self.base + in_container)
    }
}

pub fn shift_tree(root: &std::path::Path, mapping: Mapping) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let meta = std::fs::symlink_metadata(&path)?;
        let shift = |id: u32| -> u32 {
            if id >= SIZE {
                // Outside the range does not exist in the container; leaving them
                // standing would be an identifier of the **host** in a tree a
                // container writes into.
                mapping.base()
            } else {
                mapping.base() + id
            }
        };
        std::os::unix::fs::lchown(&path, Some(shift(meta.uid())), Some(shift(meta.gid())))?;

        // Only real directories are entered -- a symlink to a directory would lead
        // out of the tree.
        if meta.is_dir() {
            for entry in std::fs::read_dir(&path)? {
                pending.push(entry?.path());
            }
        }
    }
    Ok(())
}

pub const CAPABLE_RUNTIMES: &[&str] = &["crun"];

#[must_use]
pub fn supported_by(runtime: &str) -> bool {
    CAPABLE_RUNTIMES.contains(&runtime)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_range_below_the_host_accounts_is_refused() {
        for base in [0, 1, 1000, 65_535] {
            assert!(
                matches!(Mapping::new(base), Err(MappingError::TooLow { .. })),
                "{base} must be refused"
            );
        }
        // The counter-check: the first permitted value carries. Without it a check
        // that refuses everything would be green likewise.
        assert!(Mapping::new(Mapping::MINIMUM).is_ok());
        assert!(Mapping::new(100_000).is_ok());
    }

    #[test]
    fn a_range_that_would_overflow_is_refused() {
        assert!(matches!(
            Mapping::new(u32::MAX - 1),
            Err(MappingError::Overflow { .. })
        ));
        // Exactly fitting still carries.
        assert!(Mapping::new(u32::MAX - SIZE).is_ok());
    }

    #[test]
    fn ownership_is_shifted_not_flattened() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let tree = dir.path().join("layer");
        std::fs::create_dir_all(tree.join("lower")).expect("the directory");
        std::fs::write(tree.join("lower").join("file"), b"x").expect("the file");
        // A file that belongs to somebody else in the layer.
        std::os::unix::fs::lchown(tree.join("lower").join("file"), Some(1000), Some(1000))
            .expect("chown");

        let mapping = Mapping::new(100_000).expect("valid");
        shift_tree(&tree, mapping).expect("shift");

        let root = std::fs::symlink_metadata(&tree).expect("stat");
        assert_eq!((root.uid(), root.gid()), (100_000, 100_000));
        let inner = std::fs::symlink_metadata(tree.join("lower").join("file")).expect("stat");
        assert_eq!(
            (inner.uid(), inner.gid()),
            (101_000, 101_000),
            "from 1000 must become base+1000, not base"
        );
    }

    #[test]
    fn a_symlink_does_not_lead_out_of_the_tree() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let tree = dir.path().join("layer");
        std::fs::create_dir_all(&tree).expect("the directory");
        let outside = dir.path().join("outside");
        std::fs::write(&outside, b"do not touch").expect("the file");
        std::os::unix::fs::symlink(&outside, tree.join("pointer")).expect("symlink");

        let before = std::fs::symlink_metadata(&outside).expect("stat").uid();
        shift_tree(&tree, Mapping::new(100_000).expect("valid")).expect("shift");
        let after = std::fs::symlink_metadata(&outside).expect("stat").uid();

        assert_eq!(before, after, "the symlink's target was touched");
        // The symlink itself very much so -- it belongs to the layer.
        assert_eq!(
            std::fs::symlink_metadata(tree.join("pointer"))
                .expect("stat")
                .uid(),
            100_000
        );
    }

    #[test]
    fn the_sidecar_uid_is_mapped() {
        let mapping = Mapping::new(100_000).expect("valid");
        assert_eq!(
            mapping.host_uid(tg_model::mesh::SIDECAR_UID),
            Some(100_000 + tg_model::mesh::SIDECAR_UID)
        );
        // And what is not representable in the container does not exist either.
        assert_eq!(mapping.host_uid(SIZE), None);
    }

    #[test]
    fn only_a_runtime_that_can_join_a_netns_carries_the_mapping() {
        assert!(
            supported_by("crun"),
            "crun can do it (ADR-0091, measurement 5)"
        );
        assert!(
            !supported_by("youki"),
            "youki enters the netns out of the user namespace and gets EPERM"
        );
        assert!(
            !supported_by("unknown"),
            "what nobody measured does not apply"
        );
    }
}
