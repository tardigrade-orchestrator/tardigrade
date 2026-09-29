//! Resolved image settings, so that a restart gets by without a registry.
//!
//! The agent must be able to restore its state **without an external source**.
//! The content store does hold the layers, but not the question of *which* layers in
//! which order belong to a reference and which command the image brings along -- that
//! stands in the manifest, and that lies in the registry.
//!
//! That is why a pull's result is written along here. Afterwards a container start is
//! purely locally possible: the layers from the CAS, the order and the start command
//! from this record.
//!
//! The format is line-based and without a foreign library, fitting the rest of the
//! crate. Line breaks and backslashes in values are escaped so that an env value
//! cannot tear the sentence structure apart.

use std::fs;
use std::path::{Path, PathBuf};

use crate::content::{ContentStore, Digest256};
use crate::error::RuntimeError;

const HEADER: &str = "# tardigrade resolved image v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedImage {
    pub reference: String,
    pub layers: Vec<Digest256>,
    pub entrypoint: Vec<String>,
    pub env: Vec<String>,
}

impl ResolvedImage {
    pub fn save(&self, store: &ContentStore) -> Result<(), RuntimeError> {
        let path = record_path(store, &self.reference);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|source| RuntimeError::io("the manifest directory", parent, source))?;
        }

        let mut out = String::from(HEADER);
        out.push('\n');
        push_line(&mut out, "ref", &self.reference);
        for layer in &self.layers {
            push_line(&mut out, "layer", &layer.to_string());
        }
        for arg in &self.entrypoint {
            push_line(&mut out, "arg", arg);
        }
        for env in &self.env {
            push_line(&mut out, "env", env);
        }

        let temp = path.with_extension("tmp");
        fs::write(&temp, &out)
            .map_err(|source| RuntimeError::io("writing the manifest", &temp, source))?;
        fs::rename(&temp, &path)
            .map_err(|source| RuntimeError::io("renaming the manifest", &path, source))?;

        Ok(())
    }

    #[must_use]
    pub fn load(store: &ContentStore, reference: &str) -> Option<Self> {
        let resolved = Self::read(&record_path(store, reference))?;

        // **A record without its layers is unusable**: a garbage collector that
        // removes too much must cost a pull and never an empty rootfs.
        if resolved.layers.is_empty() || !resolved.layers.iter().all(|d| store.has_layer(d)) {
            return None;
        }

        Some(resolved)
    }

    #[must_use]
    pub fn read(path: &Path) -> Option<Self> {
        let text = fs::read_to_string(path).ok()?;
        let mut lines = text.lines();

        if lines.next()? != HEADER {
            return None;
        }

        let mut resolved = Self {
            reference: String::new(),
            layers: Vec::new(),
            entrypoint: Vec::new(),
            env: Vec::new(),
        };

        for line in lines {
            let (key, value) = line.split_once(' ')?;
            let value = unescape(value);
            match key {
                "ref" => resolved.reference = value,
                "layer" => resolved.layers.push(Digest256::parse(&value).ok()?),
                "arg" => resolved.entrypoint.push(value),
                "env" => resolved.env.push(value),
                _ => return None,
            }
        }

        Some(resolved)
    }
}

#[must_use]
pub fn record_path_of(store: &ContentStore, reference: &str) -> PathBuf {
    record_path(store, reference)
}

fn record_path(store: &ContentStore, reference: &str) -> PathBuf {
    let key = Digest256::of(reference.as_bytes());
    store.root().join("manifests").join(key.hex())
}

fn push_line(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push(' ');
    out.push_str(&escape(value));
    out.push('\n');
}

fn escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\n', "\\n")
}

fn unescape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            // A backslash at the end of the line stays a backslash -- exactly like an
            // escaped backslash sequence.
            Some('\\') | None => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
        }
    }

    out
}

#[must_use]
pub fn manifests_dir(store: &ContentStore) -> PathBuf {
    store.root().join("manifests")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, ContentStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");
        (dir, store)
    }

    fn fake_layer(store: &ContentStore, content: &[u8]) -> Digest256 {
        let digest = Digest256::of(content);
        let dir = store.layer_path(&digest);
        fs::create_dir_all(&dir).expect("layer dir");
        fs::write(dir.join(".complete"), crate::content::LAYER_FORMAT).expect("marker");
        digest
    }

    #[test]
    fn record_survives_a_round_trip() {
        let (_dir, store) = store();
        let layer = fake_layer(&store, b"layer-a");

        let original = ResolvedImage {
            reference: "docker.io/library/busybox:1.36".to_owned(),
            layers: vec![layer],
            entrypoint: vec!["/bin/sleep".to_owned(), "3600".to_owned()],
            env: vec!["PATH=/usr/bin".to_owned()],
        };
        original.save(&store).expect("save");

        let loaded = ResolvedImage::load(&store, &original.reference).expect("load");
        assert_eq!(loaded, original);
    }

    #[test]
    fn values_with_newlines_and_backslashes_survive() {
        let (_dir, store) = store();
        let layer = fake_layer(&store, b"layer-a");

        let original = ResolvedImage {
            reference: "example.com/app:1".to_owned(),
            layers: vec![layer],
            entrypoint: vec!["/app".to_owned()],
            env: vec![
                "MULTILINE=one\ntwo".to_owned(),
                r"WINPATH=C:\temp".to_owned(),
            ],
        };
        original.save(&store).expect("save");

        let loaded = ResolvedImage::load(&store, &original.reference).expect("load");
        assert_eq!(loaded.env, original.env);
    }

    #[test]
    fn record_is_rejected_when_a_layer_is_missing() {
        let (_dir, store) = store();
        let present = fake_layer(&store, b"layer-a");
        let absent = Digest256::of(b"never-unpacked");

        ResolvedImage {
            reference: "example.com/app:1".to_owned(),
            layers: vec![present, absent],
            entrypoint: vec!["/app".to_owned()],
            env: Vec::new(),
        }
        .save(&store)
        .expect("save");

        assert!(ResolvedImage::load(&store, "example.com/app:1").is_none());
    }

    #[test]
    fn unknown_reference_loads_as_none() {
        let (_dir, store) = store();
        assert!(ResolvedImage::load(&store, "example.com/does-not-exist:1").is_none());
    }

    #[test]
    fn foreign_header_is_rejected() {
        let (_dir, store) = store();
        let path = record_path(&store, "example.com/app:1");
        fs::create_dir_all(path.parent().expect("parent")).expect("dir");
        fs::write(&path, "# some other format\nlayer sha256:00\n").expect("write");

        assert!(ResolvedImage::load(&store, "example.com/app:1").is_none());
    }

    #[test]
    fn different_references_do_not_collide() {
        let (_dir, store) = store();
        let layer = fake_layer(&store, b"layer-a");

        for reference in ["example.com/a:1", "example.com/b:1"] {
            ResolvedImage {
                reference: reference.to_owned(),
                layers: vec![layer.clone()],
                entrypoint: vec![reference.to_owned()],
                env: Vec::new(),
            }
            .save(&store)
            .expect("save");
        }

        let a = ResolvedImage::load(&store, "example.com/a:1").expect("a");
        let b = ResolvedImage::load(&store, "example.com/b:1").expect("b");
        assert_eq!(a.entrypoint, vec!["example.com/a:1"]);
        assert_eq!(b.entrypoint, vec!["example.com/b:1"]);
    }
}
