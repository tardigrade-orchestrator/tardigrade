//! Acquisition of an image per the definition's pull policy.
//!
//! This layer decides **whether** the registry is asked at all. That is what
//! lets an agent restart work without a network: if the image already lies
//! locally in full, it is taken locally.
//!
//! The policy comes from the definition schema (`pullPolicy`):
//!
//! | Value            | Behaviour                                         |
//! |------------------|---------------------------------------------------|
//! | `if-not-present` | local, otherwise pull -- **the default**          |
//! | `always`         | always pull; without a network an error           |
//! | `never`          | local only; if absent, an error instead of a pull |

use tg_defs::PullPolicy;

use crate::content::ContentStore;
use crate::error::RuntimeError;
use crate::image;
use crate::resolved::ResolvedImage;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Local,
    Registry,
}

pub async fn acquire(
    store: &ContentStore,
    reference: &str,
    policy: Option<PullPolicy>,
    login: Option<crate::network::RegistryLogin>,
) -> Result<(ResolvedImage, Source), RuntimeError> {
    let policy = policy.unwrap_or(PullPolicy::IfNotPresent);

    if matches!(policy, PullPolicy::IfNotPresent | PullPolicy::Never)
        && let Some(local) = ResolvedImage::load(store, reference)
    {
        return Ok((local, Source::Local));
    }

    if matches!(policy, PullPolicy::Never) {
        return Err(RuntimeError::Pull {
            reference: reference.to_owned(),
            detail: "pullPolicy=\"never\", but the image does not lie in \
                     full in the local content store"
                .to_owned(),
        });
    }

    let pulled = image::pull(store, reference, login).await?;
    let resolved = ResolvedImage {
        reference: reference.to_owned(),
        layers: pulled.layers,
        entrypoint: pulled.entrypoint,
        env: pulled.env,
    };

    // Only write now: a record may arise only once the layers really lie in
    // the store.
    resolved.save(store)?;

    Ok((resolved, Source::Registry))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::Digest256;

    fn store() -> (tempfile::TempDir, ContentStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = ContentStore::open(dir.path()).expect("store");
        (dir, store)
    }

    fn seed(store: &ContentStore, reference: &str) {
        let digest = Digest256::of(b"layer");
        let dir = store.layer_path(&digest);
        std::fs::create_dir_all(&dir).expect("layer dir");
        std::fs::write(dir.join(".complete"), crate::content::LAYER_FORMAT).expect("marker");

        ResolvedImage {
            reference: reference.to_owned(),
            layers: vec![digest],
            entrypoint: vec!["/bin/sleep".to_owned(), "3600".to_owned()],
            env: Vec::new(),
        }
        .save(store)
        .expect("save");
    }

    #[tokio::test]
    async fn cached_image_is_used_without_touching_the_registry() {
        let (_dir, store) = store();
        seed(&store, "example.invalid/app:1");

        let (resolved, source) = acquire(&store, "example.invalid/app:1", None, None)
            .await
            .expect("locally resolvable");

        assert_eq!(source, Source::Local);
        assert_eq!(resolved.entrypoint, vec!["/bin/sleep", "3600"]);
    }

    #[tokio::test]
    async fn never_uses_the_cache_when_present() {
        let (_dir, store) = store();
        seed(&store, "example.invalid/app:1");

        let (_, source) = acquire(
            &store,
            "example.invalid/app:1",
            Some(PullPolicy::Never),
            None,
        )
        .await
        .expect("locally resolvable");

        assert_eq!(source, Source::Local);
    }

    #[tokio::test]
    async fn never_fails_instead_of_pulling_when_absent() {
        let (_dir, store) = store();

        let err = acquire(
            &store,
            "example.invalid/absent:1",
            Some(PullPolicy::Never),
            None,
        )
        .await
        .expect_err("must fail");

        match err {
            RuntimeError::Pull { detail, .. } => {
                assert!(
                    detail.contains("never"),
                    "the policy is not named: {detail}"
                );
            }
            other => panic!("the wrong error: {other}"),
        }
    }
}
