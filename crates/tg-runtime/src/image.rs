//! The image puller on the basis of an OCI distribution client.
//!
//! ADR-0003: our own Rust puller instead of containerd. Fetched layers land in the
//! content-addressed store ([`crate::content`]).

use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};

use crate::content::{ContentStore, Digest256};
use crate::error::RuntimeError;

#[derive(Debug, Clone)]
pub struct PulledImage {
    pub layers: Vec<Digest256>,
    pub entrypoint: Vec<String>,
    pub env: Vec<String>,
}

pub async fn pull(
    store: &ContentStore,
    reference: &str,
    login: Option<crate::network::RegistryLogin>,
) -> Result<PulledImage, RuntimeError> {
    let parsed: Reference = reference.parse().map_err(|err| RuntimeError::Pull {
        reference: reference.to_owned(),
        detail: format!("the reference is not readable: {err}"),
    })?;

    let client = Client::new(ClientConfig {
        protocol: ClientProtocol::Https,
        ..ClientConfig::default()
    });

    // The login comes from the agent (ADR-0096): it holds the data key and opens the
    // secret. Without a setting the pull is anonymous -- and `None` is no error but the
    // default.
    let auth = match login {
        Some(crate::network::RegistryLogin::Basic { user, password }) => {
            RegistryAuth::Basic(user, password)
        }
        Some(crate::network::RegistryLogin::Bearer { token }) => RegistryAuth::Bearer(token),
        None => RegistryAuth::Anonymous,
    };

    let accepted = vec![
        oci_client::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
        oci_client::manifest::IMAGE_LAYER_MEDIA_TYPE,
        oci_client::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
    ];

    let image = client
        .pull(&parsed, &auth, accepted)
        .await
        .map_err(|err| RuntimeError::Pull {
            reference: reference.to_owned(),
            detail: err.to_string(),
        })?;

    // **The order comes from the manifest, not from the network.**
    //
    // `Client::pull` fetches the layers with `buffer_unordered` and up to 16 at once;
    // `image.layers` therefore stands in the order in which the fetches **finished**.
    // Whoever takes them as they come assembles an overlayfs's `lowerdir` arbitrarily
    // -- a file from a lower layer then wins against the upper one, and a whiteout
    // deletes the wrong thing or nothing (ADR-0052). At a single-layer image that never
    // stands out.
    let manifest = image.manifest.as_ref().ok_or_else(|| RuntimeError::Pull {
        reference: reference.to_owned(),
        detail: "the registry delivered no manifest -- without it the order of the \
                 layers is not determinable"
            .to_owned(),
    })?;

    let declared: Vec<String> = manifest
        .layers
        .iter()
        .map(|descriptor| descriptor.digest.clone())
        .collect();
    // Hashed once per layer, and that is no lost work: it **is** the check. Otherwise
    // a received layer could not be assigned to its manifest entry at all --
    // `ImageLayer` does not carry its descriptor along.
    let arrived: Vec<String> = image
        .layers
        .iter()
        .map(oci_client::client::ImageLayer::sha256_digest)
        .collect();

    let ordered = in_manifest_order(&declared, &arrived).map_err(|detail| RuntimeError::Pull {
        reference: reference.to_owned(),
        detail,
    })?;

    let mut layers = Vec::with_capacity(ordered.len());
    for (digest, index) in ordered {
        let layer = &image.layers[index];

        store.verify_blob(&digest, &layer.data)?;
        store.unpack_layer(&digest, &layer.media_type, &layer.data)?;
        layers.push(digest);
    }

    let (entrypoint, env) = image_command(&image.config.data);

    Ok(PulledImage {
        layers,
        entrypoint,
        env,
    })
}

fn in_manifest_order(
    declared: &[String],
    arrived: &[String],
) -> Result<Vec<(Digest256, usize)>, String> {
    let mut ordered = Vec::with_capacity(declared.len());

    for wanted in declared {
        let digest = Digest256::parse(wanted).map_err(|err| err.to_string())?;
        let Some(index) = arrived.iter().position(|got| got == wanted) else {
            return Err(format!(
                "the manifest names the layer {wanted}, it was not fetched"
            ));
        };
        ordered.push((digest, index));
    }

    Ok(ordered)
}

fn image_command(config: &[u8]) -> (Vec<String>, Vec<String>) {
    let Ok(document) = serde_json::from_slice::<serde_json::Value>(config) else {
        return (Vec::new(), Vec::new());
    };
    let Some(image) = document.get("config") else {
        return (Vec::new(), Vec::new());
    };

    let mut command = strings(image, "Entrypoint");
    command.extend(strings(image, "Cmd"));

    (command, strings(image, "Env"))
}

fn strings(object: &serde_json::Value, key: &str) -> Vec<String> {
    object
        .get(key)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entrypoint_and_cmd_are_concatenated() {
        let config = r#"{"config":{"Entrypoint":["/bin/tini","--"],"Cmd":["/app","serve"]}}"#;
        let (command, _) = image_command(config.as_bytes());

        assert_eq!(command, vec!["/bin/tini", "--", "/app", "serve"]);
    }

    #[test]
    fn null_entrypoint_yields_only_cmd() {
        let config = r#"{"config":{"Entrypoint":null,"Cmd":["/bin/sh"]}}"#;
        let (command, _) = image_command(config.as_bytes());

        assert_eq!(command, vec!["/bin/sh"]);
    }

    #[test]
    fn env_is_read_as_given() {
        let config = r#"{"config":{"Env":["PATH=/usr/bin","TZ=UTC"],"Cmd":["/bin/sh"]}}"#;
        let (_, env) = image_command(config.as_bytes());

        assert_eq!(env, vec!["PATH=/usr/bin", "TZ=UTC"]);
    }

    #[test]
    fn escaped_characters_survive() {
        let config = r#"{"config":{"Entrypoint":["a\"b","c\\d"]}}"#;
        let (command, _) = image_command(config.as_bytes());

        assert_eq!(command, vec![r#"a"b"#.to_owned(), r"c\d".to_owned()]);
    }

    #[test]
    fn missing_fields_yield_empty_command() {
        let (command, env) = image_command(b"{}");
        assert!(command.is_empty());
        assert!(env.is_empty());
    }

    // ----------------------------------------------------- The layer order ---

    fn declared(data: &[u8]) -> String {
        format!("sha256:{}", hex(data))
    }

    fn hex(data: &[u8]) -> String {
        use sha2::Digest as _;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher
            .finalize()
            .iter()
            .fold(String::new(), |mut acc, byte| {
                use std::fmt::Write as _;
                let _ = write!(acc, "{byte:02x}");
                acc
            })
    }

    #[test]
    fn layers_follow_the_manifest_and_not_the_arrival() {
        let manifest = vec![declared(b"lower"), declared(b"middle"), declared(b"upper")];
        // As the network can deliver them: somehow.
        let arrived = vec![declared(b"upper"), declared(b"lower"), declared(b"middle")];

        let ordered = super::in_manifest_order(&manifest, &arrived).expect("complete");

        assert_eq!(
            ordered.iter().map(|(_, index)| *index).collect::<Vec<_>>(),
            vec![1, 2, 0],
            "the order must be the manifest's, not the arrival's"
        );
    }

    #[test]
    fn the_digest_comes_from_the_manifest() {
        let manifest = vec![declared(b"real")];
        let arrived = vec![declared(b"real")];

        let ordered = super::in_manifest_order(&manifest, &arrived).expect("complete");

        assert_eq!(
            ordered[0].0.to_string(),
            manifest[0],
            "the identifier is the declared one -- it goes to `verify_blob` that way, \
             and there it is checked against the received bytes"
        );
    }

    #[test]
    fn a_missing_layer_is_an_error() {
        let manifest = vec![declared(b"a"), declared(b"b")];
        let arrived = vec![declared(b"a")];

        assert!(super::in_manifest_order(&manifest, &arrived).is_err());
    }

    #[test]
    fn a_malformed_digest_is_an_error() {
        let arrived = vec!["sha512:abc".to_owned()];

        assert!(super::in_manifest_order(&["sha512:abc".to_owned()], &arrived).is_err());
    }

    // ------------------------------------------ Reading the image config ---

    #[test]
    fn the_build_containers_config_is_not_the_images_config() {
        let docker = concat!(
            r#"{"architecture":"amd64","#,
            r#""container_config":{"Env":["PATH=/only-for-the-build"],"#,
            r#""Cmd":["/bin/sh","-c","nop-cmd"],"Entrypoint":null},"#,
            r#""config":{"Env":["PATH=/usr/bin","APP=1"],"#,
            r#""Cmd":["/real"],"Entrypoint":["/bin/app"]}}"#
        );

        let (command, env) = image_command(docker.as_bytes());

        assert_eq!(command, vec!["/bin/app", "/real"]);
        assert_eq!(env, vec!["PATH=/usr/bin", "APP=1"]);
    }

    #[test]
    fn a_bracket_inside_a_value_does_not_truncate_the_list() {
        let json =
            r#"{"config":{"Entrypoint":["/bin/sh","-c","echo [a]","second"],"Cmd":[],"Env":[]}}"#;

        let (command, _) = image_command(json.as_bytes());

        assert_eq!(command, vec!["/bin/sh", "-c", "echo [a]", "second"]);
    }

    #[test]
    fn a_field_name_inside_a_value_is_not_a_field() {
        let json = concat!(
            r#"{"config":{"Labels":{"doc":"Entrypoint stands here only in the text"},"#,
            r#""Entrypoint":["/real"],"Cmd":[],"Env":[]}}"#
        );

        let (command, _) = image_command(json.as_bytes());

        assert_eq!(command, vec!["/real"]);
    }

    #[test]
    fn a_config_that_is_not_json_yields_nothing() {
        let (command, env) = image_command(b"\xff\xfe no JSON");

        assert!(command.is_empty());
        assert!(env.is_empty());
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
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher as _, Hasher as _};

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

    const VALUES: &[&str] = &[
        "/bin/sh",
        "-c",
        "echo [a]",
        "PATH=/usr/bin",
        "TZ=UTC",
        r#"say "hello""#,
        "back\\slash",
        "",
        "]",
        "\"",
        "{\"Cmd\":[\"/slipped-in\"]}",
        "ümläüte",
    ];

    fn document(rng: &mut Rng) -> (String, Vec<String>, Vec<String>, Vec<String>) {
        let pick = |rng: &mut Rng| VALUES[rng.below(VALUES.len())].to_owned();
        let list = |rng: &mut Rng| (0..rng.below(4)).map(|_| pick(rng)).collect::<Vec<_>>();

        let entrypoint = list(rng);
        let cmd = list(rng);
        let env = list(rng);

        let text = serde_json::json!({
            "architecture": "amd64",
            "container_config": {
                "Entrypoint": ["/bin/sh", "-c", "nop"],
                "Cmd": ["/from-the-build"],
                "Env": ["PATH=/only-for-the-build"],
            },
            "config": {
                "Entrypoint": entrypoint,
                "Cmd": cmd,
                "Env": env,
                "Labels": { "doc": "Entrypoint Cmd Env" },
            },
        })
        .to_string();

        (text, entrypoint, cmd, env)
    }

    #[test]
    fn fuzzing_the_image_config_holds_its_oracle() {
        let seed = fresh_seed();
        let mut rng = Rng(seed);
        let mut read = 0_u32;

        for round in 0..iterations() {
            let (text, entrypoint, cmd, env) = document(&mut rng);

            // Every fourth round is damaged -- the rest carries the oracle.
            if rng.below(4) == 0 {
                let mut bytes = text.into_bytes();
                if !bytes.is_empty() {
                    let at = rng.below(bytes.len());
                    match rng.below(3) {
                        0 => bytes.truncate(at),
                        1 => bytes[at] = u8::try_from(rng.below(256)).expect("fits"),
                        _ => bytes.insert(at, b'"'),
                    }
                }

                let (command, environment) = image_command(&bytes);
                let total: usize = command.iter().chain(&environment).map(String::len).sum();
                assert!(
                    total <= bytes.len(),
                    "seed {seed}, round {round}: more text out than in"
                );
                continue;
            }

            let (command, environment) = image_command(text.as_bytes());
            let mut wanted = entrypoint;
            wanted.extend(cmd);

            assert_eq!(
                (command, environment),
                (wanted, env),
                "seed {seed}, round {round}: what was read was other than what was written"
            );
            read += 1;
        }

        // The assurance from 9c: a run that never reads anything checks nothing.
        assert!(
            read > 0,
            "seed {seed}: not a single document reached the read path"
        );
    }
}
