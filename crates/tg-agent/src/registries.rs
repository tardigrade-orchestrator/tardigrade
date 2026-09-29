//! What the node logs in to a registry with (ADR-0096).
//!
//! **In memory and not in a file**, unlike the edges and the egress permissions
//! beside it. The reason is not convenience: the data key lies in
//! `identity/secrets.key` on the same disk, and a ciphertext beside its key is
//! plaintext. The protection from ADR-0095 applies to the **log** (ADR-0020
//! keeps forever) and to the projection — a node's disk is the trust boundary
//! anyway, but a filing nobody asked for makes it worse.
//!
//! The other two need a file, because their consumer runs in a container. The
//! puller runs **in the agent** (ADR-0096, determination 4).
//!
//! The price is thereby fixed: after a restart the node pulls anonymously until
//! the first slice is there — and then fails at the registry with its own
//! message, not with one of ours.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tg_runtime::network::{Credentials, RegistryLogin};
use tg_store::session::NodeSlice;

#[derive(Clone)]
pub(crate) struct Registries {
    inner: Arc<Mutex<Known>>,
    key: PathBuf,
}

#[derive(Default)]
struct Known {
    registries: BTreeMap<String, String>,
    secrets: BTreeMap<(String, String), tg_identity::secrets::Sealed>,
}

impl Registries {
    pub(crate) fn new(key: &Path) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Known::default())),
            key: key.to_owned(),
        }
    }

    pub(crate) fn absorb(&self, slice: &NodeSlice) {
        let known = Known {
            // **Lower-cased** (ADR-0125, determination 1). Since this version
            // the state machine normalizes itself; here once more, so that an
            // entry from before that carries **at once** and not only after a
            // new `SetRegistryCredential`. Measured, a login otherwise failed
            // silently on a capital letter.
            registries: slice
                .registry_credentials
                .iter()
                .map(|(registry, secret)| (registry.to_ascii_lowercase(), secret.clone()))
                .collect(),
            secrets: slice
                .secrets
                .iter()
                .map(|(workload, name, value)| ((workload.clone(), name.clone()), value.clone()))
                .collect(),
        };
        if let Ok(mut guard) = self.inner.lock() {
            *guard = known;
        }
    }
}

impl Credentials for Registries {
    fn for_registry(&self, registry: &str, workload: &str) -> Option<RegistryLogin> {
        let sealed = {
            let guard = self.inner.lock().ok()?;
            let secret = guard.registries.get(registry)?;
            guard
                .secrets
                .get(&(workload.to_owned(), secret.clone()))?
                .clone()
        };

        // **Every failure means anonymous**, not an abort (ADR-0096,
        // determination 6): no key, a damaged value, a line without a leading
        // word. The pull then fails at the registry, and its `401` is the more
        // precise statement -- it says that the registry refused, instead of that
        // we could not read something.
        let key = match std::fs::read_to_string(&self.key)
            .map_err(|err| err.to_string())
            .and_then(|text| {
                tg_identity::secrets::DataKey::from_base64(text.trim())
                    .map_err(|err| err.to_string())
            }) {
            Ok(key) => key,
            Err(detail) => {
                tracing::warn!(
                    registry,
                    workload,
                    detail,
                    "no data key, pulling anonymously"
                );
                return None;
            }
        };

        let plaintext = match key.open(&sealed) {
            Ok(plaintext) => plaintext,
            Err(err) => {
                tracing::warn!(
                    registry,
                    workload,
                    detail = %err,
                    "registry credential cannot be opened, pulling anonymously"
                );
                return None;
            }
        };

        // The plaintext lives exactly here and falls at the end of this
        // function into `RegistryLogin` -- it reaches no file system
        // (determination 4).
        let Ok(line) = String::from_utf8(plaintext) else {
            tracing::warn!(registry, workload, "registry credential is no text");
            return None;
        };

        let login = RegistryLogin::parse(&line);
        if login.is_none() {
            tracing::warn!(
                registry,
                workload,
                "registry credential without 'basic ' or 'bearer ', pulling anonymously"
            );
        }
        login
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tg_identity::secrets::DataKey;

    fn slice(
        registries: &[(&str, &str)],
        secrets: &[(&str, &str, tg_identity::secrets::Sealed)],
    ) -> NodeSlice {
        NodeSlice {
            registry_credentials: registries
                .iter()
                .map(|(registry, secret)| ((*registry).to_owned(), (*secret).to_owned()))
                .collect(),
            secrets: secrets
                .iter()
                .map(|(workload, name, value)| {
                    ((*workload).to_owned(), (*name).to_owned(), value.clone())
                })
                .collect(),
            ..NodeSlice::default()
        }
    }

    fn key_at(dir: &Path) -> DataKey {
        let key = DataKey::generate().expect("key");
        std::fs::write(dir.join("secrets.key"), key.to_base64()).expect("file it");
        key
    }

    #[test]
    fn a_sealed_credential_becomes_a_login() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key_at(dir.path());
        let registries = Registries::new(&dir.path().join("secrets.key"));
        registries.absorb(&slice(
            &[("registry.test", "s3-key")],
            &[(
                "api",
                "s3-key",
                key.seal(b"basic robot:topsecret").expect("seal"),
            )],
        ));

        assert_eq!(
            registries.for_registry("registry.test", "api"),
            Some(RegistryLogin::Basic {
                user: "robot".to_owned(),
                password: "topsecret".to_owned(),
            })
        );
    }

    #[test]
    fn another_workload_gets_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key_at(dir.path());
        let registries = Registries::new(&dir.path().join("secrets.key"));
        registries.absorb(&slice(
            &[("registry.test", "s3-key")],
            &[(
                "api",
                "s3-key",
                key.seal(b"basic robot:topsecret").expect("seal"),
            )],
        ));

        assert_eq!(registries.for_registry("registry.test", "foreign"), None);
        // The counter-check: the entitled one gets it.
        assert!(registries.for_registry("registry.test", "api").is_some());
    }

    #[test]
    fn every_failure_means_anonymous() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key_at(dir.path());
        let path = dir.path().join("secrets.key");

        // (1) no mapping
        let registries = Registries::new(&path);
        registries.absorb(&slice(
            &[],
            &[("api", "s3-key", key.seal(b"basic a:b").expect("seal"))],
        ));
        assert_eq!(registries.for_registry("registry.test", "api"), None);

        // (2) a value from a foreign key
        let foreign = DataKey::generate().expect("key");
        let registries = Registries::new(&path);
        registries.absorb(&slice(
            &[("registry.test", "s3-key")],
            &[("api", "s3-key", foreign.seal(b"basic a:b").expect("seal"))],
        ));
        assert_eq!(registries.for_registry("registry.test", "api"), None);

        // (3) a line without a leading word
        let registries = Registries::new(&path);
        registries.absorb(&slice(
            &[("registry.test", "s3-key")],
            &[("api", "s3-key", key.seal(b"robot:topsecret").expect("seal"))],
        ));
        assert_eq!(registries.for_registry("registry.test", "api"), None);

        // (4) no data key
        let registries = Registries::new(&dir.path().join("does-not-exist"));
        registries.absorb(&slice(
            &[("registry.test", "s3-key")],
            &[("api", "s3-key", key.seal(b"basic a:b").expect("seal"))],
        ));
        assert_eq!(registries.for_registry("registry.test", "api"), None);
    }

    #[test]
    fn a_revoked_grant_disappears_with_the_next_slice() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = key_at(dir.path());
        let registries = Registries::new(&dir.path().join("secrets.key"));

        registries.absorb(&slice(
            &[("registry.test", "s3-key")],
            &[(
                "api",
                "s3-key",
                key.seal(b"basic robot:topsecret").expect("seal"),
            )],
        ));
        assert!(registries.for_registry("registry.test", "api").is_some());

        // The next slice no longer carries the permission.
        registries.absorb(&slice(&[("registry.test", "s3-key")], &[]));
        assert_eq!(registries.for_registry("registry.test", "api"), None);
    }

    #[test]
    fn the_plaintext_never_reaches_the_disk() {
        let source = include_str!("registries.rs");
        let prod = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(before, _)| before);
        // Without comment lines: the module head names `identity/secrets.key`
        // and the filing that does not exist.
        let prod: String = prod
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && !trimmed.starts_with("/*")
            })
            .collect::<Vec<_>>()
            .join("\n");

        for forbidden in ["fs::write", "File::create", "create_dir"] {
            assert!(
                !prod.contains(forbidden),
                "'{forbidden}' in the login path: the plaintext does not belong \
                 on the disk on which its key lies (ADR-0096, determination 4)"
            );
        }

        assert_eq!(
            prod.matches("std::fs::").count(),
            1,
            "exactly one file access -- the key is read; everything else is to \
             be decided anew"
        );
        assert!(
            prod.contains("read_to_string"),
            "the key is no longer read -- then this guard is moot"
        );
    }
}
