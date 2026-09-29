//! How a secret gets into a container (ADR-0098).
//!
//! A **tmpfs** per instance with secrets, filled by the agent and hung into the
//! spec as a bind mount — like the workload API socket (ADR-0081).
//!
//! # The mount is the authorization
//!
//! A container gets exactly the secrets for which `AllowSecret` names **its**
//! name, and the way there is filtered twice and structurally both times: the
//! slice carries only the secrets of this node's workloads (ADR-0095), and here
//! only its own are mounted per container. There is no call anybody could forge.
//!
//! # Why no service with mTLS
//!
//! ADR-0016 formulated a secrets service with SVID auth; ADR-0098 rejected it,
//! and the reason is structural: a workload that speaks mTLS needs a TLS library,
//! a client and a protocol. An unmodified image does not have that — and
//! precisely for that reason a sidecar stands between it and the network
//! (ADR-0007). An API reverses that decision.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tg_runtime::network::Secrets;
use tg_store::session::NodeSlice;

const TMPFS_BYTES: u64 = 1_048_576;

// **The relation to the size of a secret is assured.** The tmpfs carries all of
// an instance's secrets, and nothing bounds how many there are -- what is
// promised is therefore that sixteen full ones fit in. Whoever changes one of the
// two numbers has the conversation instead of letting a container fail on an
// `ENOSPC` (ADR-0098, determination 7).
// Measured against a real tmpfs: exactly sixteen secrets of 64 KiB fit, the
// seventeenth fails -- the overhead is zero, tmpfs books the data volume. The
// computation is thereby exact and not estimated; a witness beside it
// substantiates it on real bytes.
const _: () = assert!(
    TMPFS_BYTES >= 16 * tg_identity::secrets::MAX_SECRET_BYTES as u64,
    "the tmpfs per instance must carry sixteen secrets of full size \
     (ADR-0016, ADR-0098)"
);

const DIR: &str = "secrets";

#[derive(Clone)]
pub(crate) struct SecretStore {
    inner: Arc<Mutex<BTreeMap<(String, String), tg_identity::secrets::Sealed>>>,
    key: PathBuf,
    root: PathBuf,
    userns: Option<tg_runtime::userns::Mapping>,
}

impl SecretStore {
    pub(crate) fn new(
        data_dir: &Path,
        key: &Path,
        userns: Option<tg_runtime::userns::Mapping>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
            key: key.to_owned(),
            root: data_dir.join(DIR),
            userns,
        }
    }

    pub(crate) fn absorb(&self, slice: &NodeSlice) {
        let known = slice
            .secrets
            .iter()
            .map(|(workload, name, value)| ((workload.clone(), name.clone()), value.clone()))
            .collect();

        if let Ok(mut guard) = self.inner.lock() {
            *guard = known;
        }
    }

    fn sealed_for(&self, workload: &str) -> Vec<(String, tg_identity::secrets::Sealed)> {
        let Ok(guard) = self.inner.lock() else {
            return Vec::new();
        };

        guard
            .iter()
            .filter(|((owner, _), _)| owner == workload)
            .map(|((_, name), value)| (name.clone(), value.clone()))
            .collect()
    }

    fn dir_of(&self, container: &str) -> PathBuf {
        self.root.join(container)
    }
}

impl SecretStore {
    fn ring(&self) -> Result<tg_identity::secrets::KeyRing, String> {
        let read = |path: &Path| -> Result<tg_identity::secrets::DataKey, String> {
            std::fs::read_to_string(path)
                .map_err(|err| format!("{}: {err}", path.display()))
                .and_then(|text| {
                    tg_identity::secrets::DataKey::from_base64(text.trim())
                        .map_err(|err| format!("data key unusable: {err}"))
                })
        };

        let primary = read(&self.key)?;
        let previous_path = self
            .key
            .with_file_name(tg_identity::layout::SECRETS_KEY_PREVIOUS);
        let previous = if previous_path.exists() {
            match read(&previous_path) {
                Ok(key) => Some(key),
                Err(err) => {
                    tracing::warn!(%err, "the data key to be replaced is unreadable");
                    None
                }
            }
        } else {
            None
        };

        Ok(tg_identity::secrets::KeyRing::new(primary, previous))
    }
}

impl Secrets for SecretStore {
    fn ensure(&self, container: &str, workload: &str) -> Result<Option<PathBuf>, String> {
        let sealed = self.sealed_for(workload);
        if sealed.is_empty() {
            // No mount for a workload without secrets: an empty directory would
            // be the same for the container and one mount more in the spec
            // (ADR-0098, determination 1).
            return Ok(None);
        }

        let key = self.ring()?;

        let dir = self.dir_of(container);
        std::fs::create_dir_all(&dir).map_err(|err| format!("{}: {err}", dir.display()))?;

        // **Idempotent** (ADR-0010): a second mount over the same target would
        // stack the mounts, and at the third pass there would be three.
        let fresh = !tg_syscall::mount::is_tmpfs_mounted(&dir);
        if fresh {
            tg_syscall::mount::mount_tmpfs(&dir, TMPFS_BYTES)
                .map_err(|err| format!("tmpfs: {err}"))?;
        }
        // The mode comes from the mount options; the owner does not.
        chown(&dir, self.userns)?;

        let mut wanted = BTreeSet::new();
        for (name, value) in sealed {
            // **The name becomes the file name**, and it comes from the log --
            // that is, from an operator. A `../` would be a path escape, and as
            // root at that. It is checked here **even when** the state machine
            // already does: the log is kept forever (ADR-0020), and an old entry
            // does not carry the check.
            if !plausible(&name) {
                tracing::warn!(
                    container,
                    workload,
                    secret = name,
                    "the secret name is no single path component -- passed over"
                );
                continue;
            }

            let plaintext = key
                .open(&value)
                .map_err(|err| format!("secret '{name}' cannot be opened: {err}"))?;

            // **The reason is named, not the kernel error.** The client refuses
            // a secret that is too large -- it can arrive here from a log entry
            // predating this limit (the log is kept, ADR-0020) or from somebody
            // who wrote past the client (ADR-0044: whoever reaches the socket may
            // do anything). Without this line `write_secret` fails at some point
            // with `No space left on device` on a node with a free disk, and the
            // container does not start (ADR-0098, determination 7).
            //
            // **At some point**, and that is the precise statement: measured, a
            // single secret just over the limit still gets through -- it does fit
            // into a megabyte. What fails is the **seventeenth** (measured:
            // exactly sixteen of 64 KiB fit, the seventeenth does not) or a
            // single one over 1 MiB. The limit per secret is therefore not one at
            // which it breaks at once but the one that permits sixteen.
            //
            // **The whole delivery fails**, unlike with a hostile name beside it
            // -- and that is the same choice as with the missing key: a secret the
            // operator meant and that does not arrive costs the container
            // (ADR-0098, determination 7). Passed over, it would start up and not
            // find a file it expects -- an outage that looks like an error of the
            // workload. A hostile **name**, by contrast, is no secret anybody
            // meant.
            let limit = tg_identity::secrets::MAX_SECRET_BYTES;
            if plaintext.len() > limit {
                return Err(format!(
                    "secret '{name}' is {} bytes large, the tmpfs in the \
                     container carries {limit} per secret (ADR-0016)",
                    plaintext.len()
                ));
            }

            write_secret(&dir.join(&name), &plaintext, self.userns)?;
            wanted.insert(name);
        }

        // What the slice no longer names disappears -- a secret left lying would
        // be one the cluster has revoked (ADR-0098, determination 6).
        // **The delivery is reported** (ADR-0016, ADR-0098).
        //
        // ADR-0016 names among its consequences "every secret access is
        // identity-bound and audited", and ADR-0098 writes that "the agent
        // reports what it mounts" -- **measured it did not**. The log carries
        // `AllowSecret`, that is, *who may read*; that a particular container
        // really got the values stood nowhere.
        //
        // **Only at the first mount**, not per pass: the reconciliation is
        // level-triggered and would otherwise run every second. A rotation is in
        // the log anyway (`PutSecret`), and a revocation is reported by
        // `remove_stale` -- the two events an auditor asks about.
        //
        // **Names, never values.** The plaintext lies in the tmpfs and belongs
        // nowhere else -- least of all in a log line a collector fetches.
        if fresh {
            tracing::info!(
                container,
                workload,
                secrets = %wanted.iter().cloned().collect::<Vec<_>>().join(","),
                "secrets delivered"
            );
        }

        remove_stale(&dir, &wanted);

        Ok(Some(dir))
    }

    fn held(&self) -> Vec<String> {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return Vec::new();
        };

        entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .filter_map(|entry| entry.file_name().to_str().map(ToOwned::to_owned))
            .collect()
    }

    fn release(&self, container: &str) {
        let dir = self.dir_of(container);

        // **Unmount at once, not lazily.** What lies here is plaintext, and a
        // lazy mount holds it until the last reference falls -- the same choice
        // as when clearing away the volumes.
        if tg_syscall::mount::is_tmpfs_mounted(&dir)
            && let Err(err) = tg_syscall::mount::unmount_now(&dir)
        {
            tracing::warn!(container, error = %err, "the secrets tmpfs was not unmounted");
            return;
        }
        if let Err(err) = std::fs::remove_dir_all(&dir)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(container, error = %err, "the secrets directory was not removed");
        }
    }
}

fn plausible(name: &str) -> bool {
    tg_model::names::is_plausible_secret(name)
}

fn write_secret(
    path: &Path,
    plaintext: &[u8],
    userns: Option<tg_runtime::userns::Mapping>,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = path.with_extension("new");
    std::fs::write(&temp, plaintext).map_err(|err| format!("{}: {err}", temp.display()))?;
    std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o400))
        .map_err(|err| format!("{}: {err}", temp.display()))?;
    chown(&temp, userns)?;
    std::fs::rename(&temp, path).map_err(|err| format!("{}: {err}", path.display()))
}

fn chown(path: &Path, mapping: Option<tg_runtime::userns::Mapping>) -> Result<(), String> {
    let Some(mapping) = mapping else {
        return Ok(());
    };

    tg_runtime::userns::shift_tree(path, mapping)
        .map_err(|err| format!("{}: chown: {err}", path.display()))
}

fn remove_stale(dir: &Path, wanted: &BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        if wanted.contains(&name) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            // **The second event an auditor asks about** (ADR-0016): that a
            // value has disappeared again. Until here only the **failure** stood
            // in the log -- the success did not, and with that the revocation was
            // indistinguishable from a file that was never there.
            Ok(()) => tracing::info!(%name, "revoked secret removed"),
            Err(err) => tracing::warn!(
                path = %entry.path().display(),
                error = %err,
                "revoked secret not removed"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DIR, SecretStore, plausible};
    use std::path::Path;
    use tg_runtime::network::Secrets as _;

    struct Released<'a> {
        store: &'a SecretStore,
        container: &'a str,
    }

    impl Drop for Released<'_> {
        fn drop(&mut self) {
            self.store.release(self.container);
        }
    }

    fn store(dir: &Path, secrets: &[(&str, &str, &[u8])]) -> SecretStore {
        let key = tg_identity::secrets::DataKey::generate().expect("key");
        let identity = dir.join(tg_identity::layout::DIR);
        std::fs::create_dir_all(&identity).expect("directory");
        let key_path = identity.join(tg_identity::layout::SECRETS_KEY);
        std::fs::write(&key_path, key.to_base64()).expect("key");

        let store = SecretStore::new(dir, &key_path, None);
        let sealed = secrets
            .iter()
            .map(|(workload, name, value)| {
                (
                    ((*workload).to_owned(), (*name).to_owned()),
                    key.seal(value).expect("sealable"),
                )
            })
            .collect();
        *store.inner.lock().expect("lock") = sealed;

        store
    }

    #[test]
    #[ignore = "demands CAP_SYS_ADMIN for mount(tmpfs); over `cargo xtask storage`"]
    fn a_workload_gets_its_own_secrets_and_no_others() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(
            dir.path(),
            &[
                ("api", "db-password", b"hunter2"),
                ("api", "s3-key", b"AKIA..."),
                ("foreign", "topsecret", b"not for api"),
            ],
        );
        let _released = Released {
            store: &store,
            container: "tg-api",
        };

        let held = store
            .ensure("tg-api", "api")
            .expect("delivery")
            .expect("api has secrets");

        assert_eq!(
            std::fs::read(held.join("db-password")).expect("file"),
            b"hunter2",
            "the plaintext must lie in the directory"
        );
        assert!(held.join("s3-key").exists(), "both secrets of api");
        assert!(
            !held.join("topsecret").exists(),
            "the secret of a foreign workload must not arise -- the mount *is* \
             the authorization"
        );

        // It is a **tmpfs** and not a directory on the disk (ADR-0098,
        // determination 1): the plaintext shall lie nowhere at rest.
        assert!(
            tg_syscall::mount::is_tmpfs_mounted(&held),
            "the plaintext belongs in RAM, not on the disk"
        );

        // **The call is the subject here and not the clean-up.** `Released`
        // beside it is the guard for the red case; this line is the assurance
        // that `release` really unmounts -- and it once went along with the
        // mechanical removal of the five clean-up calls. `release` is idempotent,
        // so the two do not stand in each other's way.
        store.release("tg-api");

        assert!(
            !tg_syscall::mount::is_tmpfs_mounted(&held),
            "the tmpfs must disappear with the instance -- what stays lying is \
             plaintext"
        );
        assert!(!held.exists(), "and the directory with it");
    }

    #[test]
    fn a_workload_without_secrets_gets_no_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path(), &[("foreign", "topsecret", b"value")]);
        let _released = Released {
            store: &store,
            container: "tg-api",
        };

        assert!(
            store.ensure("tg-api", "api").expect("delivery").is_none(),
            "without a grant no directory arises"
        );
        assert!(
            !dir.path().join(DIR).join("tg-api").exists(),
            "and nothing on the disk either"
        );
    }

    #[test]
    #[ignore = "demands CAP_SYS_ADMIN for mount(tmpfs); over `cargo xtask storage`"]
    fn a_hostile_name_is_skipped_and_the_rest_arrives() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(
            dir.path(),
            &[("api", "../escape", b"evil"), ("api", "good", b"value")],
        );
        let _released = Released {
            store: &store,
            container: "tg-api",
        };

        let held = store
            .ensure("tg-api", "api")
            .expect("delivery")
            .expect("api has secrets");

        assert_eq!(
            std::fs::read(held.join("good")).expect("file"),
            b"value",
            "the good secret must arrive"
        );
        let escape = dir.path().join(DIR).join("escape");
        assert!(
            !escape.exists(),
            "'../escape' must write nothing outside: {}",
            escape.display()
        );
    }

    #[test]
    #[ignore = "demands CAP_SYS_ADMIN for mount(tmpfs); over `cargo xtask storage`"]
    fn a_rotation_reaches_a_running_container_and_a_revocation_takes_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = tg_identity::secrets::DataKey::generate().expect("key");
        let identity = dir.path().join(tg_identity::layout::DIR);
        std::fs::create_dir_all(&identity).expect("directory");
        let key_path = identity.join(tg_identity::layout::SECRETS_KEY);
        std::fs::write(&key_path, key.to_base64()).expect("key");

        let store = SecretStore::new(dir.path(), &key_path, None);
        let _released = Released {
            store: &store,
            container: "tg-api",
        };
        let put = |pairs: Vec<(&str, &[u8])>| {
            let sealed = pairs
                .into_iter()
                .map(|(name, value)| {
                    (
                        ("api".to_owned(), name.to_owned()),
                        key.seal(value).expect("sealable"),
                    )
                })
                .collect();
            *store.inner.lock().expect("lock") = sealed;
        };

        put(vec![("db-password", b"old"), ("gone", b"right away")]);
        let held = store
            .ensure("tg-api", "api")
            .expect("delivery")
            .expect("secrets");
        assert_eq!(
            std::fs::read(held.join("db-password")).expect("file"),
            b"old"
        );
        assert!(held.join("gone").exists());

        // A `PutSecret` and a `RevokeSecret` -- the same container, no restart.
        put(vec![("db-password", b"new")]);
        store.ensure("tg-api", "api").expect("delivery");

        assert_eq!(
            std::fs::read(held.join("db-password")).expect("file"),
            b"new",
            "a rotation must reach a running container"
        );
        assert!(
            !held.join("gone").exists(),
            "and a revocation takes its file away"
        );
    }

    #[test]
    #[ignore = "demands CAP_SYS_ADMIN for mount(tmpfs); over `cargo xtask storage`"]
    fn during_a_rotation_both_keys_reach_the_container() {
        let dir = tempfile::tempdir().expect("tempdir");
        let new = tg_identity::secrets::DataKey::generate().expect("key");
        let old = tg_identity::secrets::DataKey::generate().expect("key");

        let identity = dir.path().join(tg_identity::layout::DIR);
        std::fs::create_dir_all(&identity).expect("directory");
        let key_path = identity.join(tg_identity::layout::SECRETS_KEY);
        std::fs::write(&key_path, new.to_base64()).expect("key");
        std::fs::write(
            identity.join(tg_identity::layout::SECRETS_KEY_PREVIOUS),
            old.to_base64(),
        )
        .expect("the key to be replaced");

        let store = SecretStore::new(dir.path(), &key_path, None);
        let _released = Released {
            store: &store,
            container: "tg-api",
        };
        *store.inner.lock().expect("lock") = [
            (
                ("api".to_owned(), "already-rekeyed".to_owned()),
                new.seal(b"with the new one").expect("sealable"),
            ),
            (
                ("api".to_owned(), "not-yet".to_owned()),
                old.seal(b"with the old one").expect("sealable"),
            ),
        ]
        .into_iter()
        .collect();

        let held = store
            .ensure("tg-api", "api")
            .expect("delivery")
            .expect("secrets");

        assert_eq!(
            std::fs::read(held.join("already-rekeyed")).expect("file"),
            b"with the new one"
        );
        assert_eq!(
            std::fs::read(held.join("not-yet")).expect("file"),
            b"with the old one",
            "without the key to be replaced a container loses its secret in the \
             middle of the rotation"
        );
    }

    #[test]
    #[ignore = "demands CAP_SYS_ADMIN for mount(tmpfs); over `cargo xtask storage`"]
    fn without_the_previous_key_the_whole_delivery_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let new = tg_identity::secrets::DataKey::generate().expect("key");
        let old = tg_identity::secrets::DataKey::generate().expect("key");

        let identity = dir.path().join(tg_identity::layout::DIR);
        std::fs::create_dir_all(&identity).expect("directory");
        let key_path = identity.join(tg_identity::layout::SECRETS_KEY);
        std::fs::write(&key_path, new.to_base64()).expect("key");
        // **No** `secrets.key.previous` -- the rotation is complete.

        let store = SecretStore::new(dir.path(), &key_path, None);
        let _released = Released {
            store: &store,
            container: "tg-api",
        };
        *store.inner.lock().expect("lock") = [
            (
                ("api".to_owned(), "good".to_owned()),
                new.seal(b"value").expect("sealable"),
            ),
            (
                ("api".to_owned(), "unreadable".to_owned()),
                old.seal(b"from the old one").expect("sealable"),
            ),
        ]
        .into_iter()
        .collect();

        let err = store
            .ensure("tg-api", "api")
            .expect_err("without the key to be replaced the delivery must not succeed");

        assert!(
            err.contains("unreadable") && err.contains("cannot be opened"),
            "the reason must name the secret by name: {err}"
        );
    }

    #[test]
    #[ignore = "demands CAP_SYS_ADMIN for mount(tmpfs); over `cargo xtask storage`"]
    fn sixteen_secrets_of_full_size_fit() {
        let limit = tg_identity::secrets::MAX_SECRET_BYTES;
        let full = vec![b'z'; limit];
        let names: Vec<String> = (0..16).map(|i| format!("s{i}")).collect();
        let secrets: Vec<(&str, &str, &[u8])> = names
            .iter()
            .map(|name| ("api", name.as_str(), full.as_slice()))
            .collect();

        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path(), &secrets);
        let _released = Released {
            store: &store,
            container: "tg-api",
        };

        let mount = store
            .ensure("tg-api", "api")
            .expect("sixteen secrets of full size must fit")
            .expect("a mount point");
        for name in &names {
            assert_eq!(
                std::fs::read(mount.join(name)).expect("file").len(),
                limit,
                "'{name}' did not arrive in full"
            );
        }
    }

    #[test]
    #[ignore = "demands CAP_SYS_ADMIN for mount(tmpfs); over `cargo xtask storage`"]
    fn a_secret_over_the_limit_names_both_numbers() {
        let limit = tg_identity::secrets::MAX_SECRET_BYTES;

        let over = vec![b'x'; limit + 1];
        let dir = tempfile::tempdir().expect("tempdir");
        let too_big = store(dir.path(), &[("api", "huge", &over)]);
        let _released = Released {
            store: &too_big,
            container: "tg-api",
        };

        let err = too_big
            .ensure("tg-api", "api")
            .expect_err("a secret over the limit must not arrive");
        assert!(
            err.contains("huge")
                && err.contains(&(limit + 1).to_string())
                && err.contains(&limit.to_string()),
            "the message does not name name, size and limit: {err}"
        );

        // And the counter-direction: **at** the limit it gets through.
        let exact = vec![b'y'; limit];
        let dir2 = tempfile::tempdir().expect("tempdir");
        let fits = store(dir2.path(), &[("api", "just-about", &exact)]);
        let _released2 = Released {
            store: &fits,
            container: "tg-api",
        };
        let mount = fits
            .ensure("tg-api", "api")
            .expect("a secret at the limit must arrive")
            .expect("a mount point");
        assert_eq!(
            std::fs::read(mount.join("just-about")).expect("file"),
            exact
        );
    }

    #[test]
    fn a_name_that_is_not_a_single_path_component_is_refused() {
        for hostile in [
            "..",
            ".",
            "../etc/passwd",
            "a/b",
            "/absolute",
            "a/../b",
            "",
            "./x",
        ] {
            assert!(
                !plausible(hostile),
                "'{hostile}' must not become a file name -- it comes from the log"
            );
        }
    }

    #[test]
    fn an_ordinary_name_is_accepted() {
        for ordinary in ["db-password", "s3", "api-key-2", "a", "x.pem"] {
            assert!(plausible(ordinary), "'{ordinary}' must go through");
        }
    }

    #[test]
    fn the_form_is_the_one_a_workload_name_has() {
        assert!(!plausible("DB_PASSWORD"));
        assert!(!plausible("db_password"));
        assert!(!plausible("9lives"), "a digit begins no name");
        assert!(!plausible(&"a".repeat(64)), "63 characters are the limit");
        assert!(plausible(&"a".repeat(63)));
    }

    #[test]
    #[ignore = "demands CAP_SYS_ADMIN for mount(tmpfs); over `cargo xtask storage`"]
    fn the_delivery_is_reported_with_names_and_without_values() {
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt as _;

        #[derive(Clone, Default)]
        struct Collected(Arc<Mutex<Vec<String>>>);

        impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Collected {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _: tracing_subscriber::layer::Context<'_, S>,
            ) {
                struct Grab<'a>(&'a mut String);
                impl tracing::field::Visit for Grab<'_> {
                    fn record_debug(
                        &mut self,
                        field: &tracing::field::Field,
                        value: &dyn std::fmt::Debug,
                    ) {
                        use std::fmt::Write as _;
                        let _ = write!(self.0, " {}={value:?}", field.name());
                    }
                }
                let mut line = String::new();
                event.record(&mut Grab(&mut line));
                if let Ok(mut all) = self.0.lock() {
                    all.push(line);
                }
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let store = store(dir.path(), &[("api", "s3-key", b"top-secret-xyz")]);
        let _released = Released {
            store: &store,
            container: "tg-api",
        };

        let collected = Collected::default();
        let subscriber = tracing_subscriber::registry().with(collected.clone());
        tracing::subscriber::with_default(subscriber, || {
            store.ensure("tg-api", "api").expect("delivered");
            // **A second pass does not report again.** The reconciliation is
            // level-triggered and would otherwise run into the log every second.
            store.ensure("tg-api", "api").expect("delivered");
        });

        let lines = collected.0.lock().expect("messages").clone();
        let delivered: Vec<_> = lines
            .iter()
            .filter(|line| line.contains("secrets delivered"))
            .collect();

        assert_eq!(delivered.len(), 1, "reported exactly once: {lines:?}");
        assert!(
            delivered[0].contains("s3-key") && delivered[0].contains("tg-api"),
            "the message names container and names: {delivered:?}"
        );

        let all = lines.join(" | ");
        assert!(
            !all.contains("top-secret"),
            "the plaintext belongs in no log line: {all}"
        );
    }
}
