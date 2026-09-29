//! Secrets in consensus (ADR-0016, ADR-0095).
//!
//! Written **before** the implementation (CLAUDE.md). What is checked here is
//! the state machine: what lies in the log, who may read, and the rejections —
//! pure logic, without a cluster.
//!
//! The **value** is throughout a `Sealed` and never a plaintext: the log is kept
//! (ADR-0020), and a secret in it would be a bearer secret with a retention
//! period.

use tg_consensus::{ClusterState, Command, Outcome, Rejection};
use tg_identity::secrets::{DataKey, Sealed};

const DOCUMENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">
  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1"/>
  </workload>
</workloads>"#;

fn sealed(value: &[u8]) -> Sealed {
    DataKey::generate()
        .expect("key")
        .seal(value)
        .expect("sealable")
}

fn with_api() -> ClusterState {
    let mut state = ClusterState::default();
    let outcome = state.apply(&Command::UpsertWorkload {
        document: DOCUMENT.to_owned(),
    });
    assert!(matches!(outcome, Outcome::Applied), "{outcome:?}");

    state
}

/// **A secret lies in the state, and sealed at that.**
#[test]
fn a_secret_is_stored_sealed() {
    let mut state = ClusterState::default();
    let value = sealed(b"hunter2");

    assert!(matches!(
        state.apply(&Command::PutSecret {
            name: "s3-key".to_owned(),
            value: value.clone(),
        }),
        Outcome::Applied
    ));

    assert_eq!(state.secret("s3-key"), Some(&value));
}

/// **A second `PutSecret` replaces** — a secret is a state, not an event.
#[test]
fn putting_a_secret_twice_replaces_it() {
    let mut state = ClusterState::default();
    let second = sealed(b"new");

    let _ = state.apply(&Command::PutSecret {
        name: "s3-key".to_owned(),
        value: sealed(b"old"),
    });
    let _ = state.apply(&Command::PutSecret {
        name: "s3-key".to_owned(),
        value: second.clone(),
    });

    assert_eq!(state.secret("s3-key"), Some(&second));
}

/// **Deny-by-default** (ADR-0016, ADR-0025): without a grant nobody reads.
#[test]
fn without_a_grant_nobody_may_read() {
    let mut state = with_api();
    let _ = state.apply(&Command::PutSecret {
        name: "s3-key".to_owned(),
        value: sealed(b"hunter2"),
    });

    assert!(
        state.secrets_for("api").is_empty(),
        "without a grant nobody may read"
    );
}

/// **And with a grant exactly the one.**
#[test]
fn a_grant_opens_exactly_one_secret() {
    let mut state = with_api();
    for name in ["s3-key", "db-password"] {
        let _ = state.apply(&Command::PutSecret {
            name: name.to_owned(),
            value: sealed(b"value"),
        });
    }

    assert!(matches!(
        state.apply(&Command::AllowSecret {
            workload: "api".to_owned(),
            secret: "s3-key".to_owned(),
        }),
        Outcome::Applied
    ));

    let readable: Vec<&str> = state
        .secrets_for("api")
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    assert_eq!(readable, vec!["s3-key"]);
}

/// **A revocation takes it back.**
#[test]
fn revoking_takes_the_grant_away() {
    let mut state = with_api();
    let _ = state.apply(&Command::PutSecret {
        name: "s3-key".to_owned(),
        value: sealed(b"hunter2"),
    });
    let _ = state.apply(&Command::AllowSecret {
        workload: "api".to_owned(),
        secret: "s3-key".to_owned(),
    });

    assert!(matches!(
        state.apply(&Command::RevokeSecret {
            workload: "api".to_owned(),
            secret: "s3-key".to_owned(),
        }),
        Outcome::Applied
    ));
    assert!(state.secrets_for("api").is_empty());
}

/// **A grant for an unknown workload is refused.**
///
/// The same check as with `AllowEgress`: a grant for something that does not
/// exist would look to an operator like a grant.
#[test]
fn a_grant_for_an_unknown_workload_is_refused() {
    let mut state = ClusterState::default();
    let _ = state.apply(&Command::PutSecret {
        name: "s3-key".to_owned(),
        value: sealed(b"hunter2"),
    });

    assert!(matches!(
        state.apply(&Command::AllowSecret {
            workload: "doesnotexist".to_owned(),
            secret: "s3-key".to_owned(),
        }),
        Outcome::Rejected(Rejection::UnknownWorkload { .. })
    ));
}

/// **And one for an unknown secret likewise.**
///
/// Accepting it silently would mean: a typo in the name yields a grant that
/// never opens anything — and an operator would look for the error at the
/// workload.
#[test]
fn a_grant_for_an_unknown_secret_is_refused() {
    let mut state = with_api();

    assert!(matches!(
        state.apply(&Command::AllowSecret {
            workload: "api".to_owned(),
            secret: "doesnotexist".to_owned(),
        }),
        Outcome::Rejected(Rejection::UnknownSecret { .. })
    ));
}

/// **A secret somebody may still read is not deleted.**
///
/// The same direction as with `DeleteVolume` (ADR-0027): whoever deletes it
/// takes it from everyone — and a grant that points into the void is one an
/// auditor takes for a real one.
#[test]
fn a_secret_that_is_still_granted_is_not_removed() {
    let mut state = with_api();
    let _ = state.apply(&Command::PutSecret {
        name: "s3-key".to_owned(),
        value: sealed(b"hunter2"),
    });
    let _ = state.apply(&Command::AllowSecret {
        workload: "api".to_owned(),
        secret: "s3-key".to_owned(),
    });

    assert!(matches!(
        state.apply(&Command::RemoveSecret {
            name: "s3-key".to_owned(),
        }),
        Outcome::Rejected(Rejection::SecretInUse { .. })
    ));
    assert!(state.secret("s3-key").is_some());
}

/// **And one a registry points at just as little.**
///
/// The second consumer, and it was unguarded. `SetRegistryCredential`
/// **refuses** when the secret does not exist — with the rationale in the code:
/// *"a mapping into the void would look to an operator like one that carries,
/// and the pull would afterwards run anonymously"* (ADR-0096). Measured,
/// `RemoveSecret` let exactly this state arise:
///
/// ```text
/// RemoveSecret despite a registry mapping: Applied
/// mappings afterwards: [("registry.example.com", "reg")]
/// secret still there? false
/// ```
///
/// The ingest therefore refused to **create** the mapping into the void and let
/// it **arise**. What hangs on it nobody sees at once: the pull runs anonymously
/// and fails at the registry — with `pullPolicy="always"` at the next start,
/// with a cached image arbitrarily late and far from the cause.
#[test]
fn a_secret_a_registry_points_at_is_not_removed() {
    let mut state = ClusterState::default();
    let _ = state.apply(&Command::PutSecret {
        name: "reg-key".to_owned(),
        value: sealed(b"hunter2"),
    });
    let _ = state.apply(&Command::SetRegistryCredential {
        registry: "registry.example.com".to_owned(),
        secret: "reg-key".to_owned(),
    });

    let outcome = state.apply(&Command::RemoveSecret {
        name: "reg-key".to_owned(),
    });
    let Outcome::Rejected(rejection) = outcome else {
        panic!("the secret was removed, the mapping now points into the void: {outcome:?}");
    };
    let text = format!("{rejection:?}");
    assert!(
        text.contains("registry.example.com"),
        "the rejection must name the registry -- otherwise an operator looks \
         for the consumer among the workloads: {text}"
    );

    // **And the secret is still there.** A rejection that deletes anyway would
    // be the worst of all.
    assert!(state.secret("reg-key").is_some());

    // The way stands open: first release the mapping, then delete.
    assert!(matches!(
        state.apply(&Command::ClearRegistryCredential {
            registry: "registry.example.com".to_owned(),
        }),
        Outcome::Applied
    ));
    assert!(matches!(
        state.apply(&Command::RemoveSecret {
            name: "reg-key".to_owned(),
        }),
        Outcome::Applied
    ));
}

/// **Without a grant it can be deleted** — the counter-check.
#[test]
fn an_ungranted_secret_is_removed() {
    let mut state = ClusterState::default();
    let _ = state.apply(&Command::PutSecret {
        name: "s3-key".to_owned(),
        value: sealed(b"hunter2"),
    });

    assert!(matches!(
        state.apply(&Command::RemoveSecret {
            name: "s3-key".to_owned(),
        }),
        Outcome::Applied
    ));
    assert!(state.secret("s3-key").is_none());
}

/// **A withdrawal of the workload takes its grants with it.**
///
/// The same consideration as with the egress permissions: an open door with no
/// room behind it would be inherited by the next workload of the same name.
#[test]
fn removing_a_workload_takes_its_grants() {
    let mut state = with_api();
    let _ = state.apply(&Command::PutSecret {
        name: "s3-key".to_owned(),
        value: sealed(b"hunter2"),
    });
    let _ = state.apply(&Command::AllowSecret {
        workload: "api".to_owned(),
        secret: "s3-key".to_owned(),
    });

    let _ = state.apply(&Command::RemoveWorkload {
        name: "api".to_owned(),
    });

    assert!(
        state.secrets_for("api").is_empty(),
        "the grant outlived the workload"
    );
    // And with that the secret is deletable again.
    assert!(matches!(
        state.apply(&Command::RemoveSecret {
            name: "s3-key".to_owned(),
        }),
        Outcome::Applied
    ));
}

/// **Deleting an unknown secret is settled, not refused** (rule 1 of the state
/// machine).
#[test]
fn removing_an_unknown_secret_is_done() {
    let mut state = ClusterState::default();

    assert!(matches!(
        state.apply(&Command::RemoveSecret {
            name: "doesnotexist".to_owned(),
        }),
        Outcome::Applied
    ));
}

/// **A mapping onto a secret that does not exist is refused** (ADR-0096,
/// determination 1).
///
/// The same exception to rule 1 as with the grant: a mapping into the void would
/// look to an operator like one that carries, and the pull would afterwards run
/// anonymously — with a message from the registry instead of from us.
#[test]
fn a_registry_credential_needs_its_secret() {
    let mut state = ClusterState::default();

    let refused = state.apply(&Command::SetRegistryCredential {
        registry: "registry.test".to_owned(),
        secret: "does-not-exist".to_owned(),
    });
    assert!(
        matches!(
            refused,
            Outcome::Rejected(Rejection::UnknownSecret { ref name }) if name == "does-not-exist"
        ),
        "{refused:?}"
    );
    assert!(
        state.registry_credentials().is_empty(),
        "a refused mapping must leave nothing behind"
    );

    // The counter-check: with the secret it carries.
    assert!(matches!(
        state.apply(&Command::PutSecret {
            name: "does-not-exist".to_owned(),
            value: sealed(b"basic robot:topsecret"),
        }),
        Outcome::Applied
    ));
    assert!(matches!(
        state.apply(&Command::SetRegistryCredential {
            registry: "registry.test".to_owned(),
            secret: "does-not-exist".to_owned(),
        }),
        Outcome::Applied
    ));
    assert_eq!(
        state.registry_credentials(),
        vec![("registry.test", "does-not-exist")]
    );
}

/// **A mapping is replaced, not supplemented**, and `Clear` takes it back — for
/// the same registry exactly one secret applies.
#[test]
fn a_registry_has_exactly_one_credential() {
    let mut state = ClusterState::default();
    for name in ["old", "new"] {
        assert!(matches!(
            state.apply(&Command::PutSecret {
                name: name.to_owned(),
                value: sealed(b"basic robot:topsecret"),
            }),
            Outcome::Applied
        ));
        assert!(matches!(
            state.apply(&Command::SetRegistryCredential {
                registry: "registry.test".to_owned(),
                secret: name.to_owned(),
            }),
            Outcome::Applied
        ));
    }
    assert_eq!(
        state.registry_credentials(),
        vec![("registry.test", "new")],
        "the second mapping must replace the first"
    );

    assert!(matches!(
        state.apply(&Command::ClearRegistryCredential {
            registry: "registry.test".to_owned(),
        }),
        Outcome::Applied
    ));
    assert!(state.registry_credentials().is_empty());
}

/// **A secret name becomes a file name** (ADR-0098) — and it comes from the log,
/// that is, from an operator.
///
/// It is checked **here** so that a `../` stands out at the moment of issuing and
/// not on a node. The agent checks it once more all the same: the log is kept
/// forever (ADR-0020), and an entry from before this check does not carry it.
#[test]
fn a_secret_name_that_is_not_a_single_path_component_is_refused() {
    let mut state = ClusterState::default();

    for hostile in ["..", ".", "../etc/passwd", "a/b", "/absolute", ""] {
        let outcome = state.apply(&Command::PutSecret {
            name: hostile.to_owned(),
            value: sealed(b"value"),
        });

        assert!(
            matches!(
                outcome,
                Outcome::Rejected(Rejection::MalformedSecret { .. })
            ),
            "'{hostile}' must not go into the log: {outcome:?}"
        );
    }

    assert!(
        state.secret_sizes().is_empty(),
        "a refused name leaves nothing behind"
    );
}

/// The counter-direction: an ordinary name goes through.
///
/// Without it a check that refuses **every** name would be just as green — and
/// then no secret could be filed any more.
#[test]
fn an_ordinary_secret_name_is_accepted() {
    let mut state = ClusterState::default();

    let outcome = state.apply(&Command::PutSecret {
        name: "db-password".to_owned(),
        value: sealed(b"value"),
    });

    assert!(matches!(outcome, Outcome::Applied), "{outcome:?}");
    // **And the size stands beside it** -- the one number with which an
    // operator finds a secret over `MAX_SECRET_BYTES` before it costs its
    // container at the next start.
    assert_eq!(state.secret_sizes(), vec![("db-password", b"value".len())]);
}

/// **The data key must never go into the log** (ADR-0095, determination 1).
///
/// The log is kept forever and moved into the WORM archive (ADR-0020). A command
/// that carried the cluster-wide data key would thereby place it there
/// irrevocably — and with it **every** secret that was ever sealed: the
/// ciphertext lies in the same log.
///
/// Measured, the assurance was upheld and **structurally unsecured**:
/// `command.rs` names `DataKey` nowhere, but nothing prevented it. Hence a
/// tripwire and no prose — the same construction as
/// `a_command_kind_can_never_be_removed` beside it.
///
/// Permitted from `tg_identity::secrets` is exactly one type: [`Sealed`]. It is
/// the **envelope**, not the key, and without it `PutSecret` would not exist.
///
/// **The direct way is barred anyway, and doubly so** — measured while building
/// this guard: a field of type `DataKey` no longer lets `Command` compile
/// (`DataKey` derives neither `Clone` nor `Eq` nor `Serialize`, deliberately),
/// and an additional field breaks the exhaustive `match` patterns (`E0027`).
/// This guard covers the way **beside** it: whoever gives `DataKey` the
/// derivations because they want to pass it around somewhere has no compiler
/// error afterwards — only this test.
#[test]
fn no_command_ever_carries_the_data_key() {
    let source = include_str!("../../tg-model/src/command.rs");
    let prod = source
        .split_once("#[cfg(test)]")
        .map_or(source, |(before, _)| before);
    // **Without comment lines.** This guard's rationale names the type by name,
    // and a doc that quotes ADR-0095 would otherwise object to it -- a guard that
    // produces false hits is switched off instead of read (the same filter as in
    // the determinism tripwire).
    let prod: String = prod
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with("/*")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let prod = prod.as_str();

    for forbidden in ["DataKey", "KeyRing"] {
        assert!(
            !prod.contains(forbidden),
            "'{forbidden}' in the command set: the log keeps forever \
             (ADR-0020), and the key would thereby lie beside the ciphertext it \
             opens (ADR-0095, determination 1)"
        );
    }

    // And the counter-direction: the **envelope** belongs in it, otherwise this
    // test only checks that the file has nothing to do with secrets.
    // Since ADR-0134 the path is `crate::secrets::Sealed`: the command set lies
    // in `tg-model`, and the **envelope** moved along as pure data -- the
    // procedure stayed where `ring` is.
    assert!(
        prod.contains("crate::secrets::Sealed"),
        "the command set no longer carries a sealed value -- then this guard is \
         moot and the question is to be asked anew"
    );
    // From that module **only** the envelope may come.
    let others: Vec<&str> = prod
        .match_indices("secrets::")
        .map(|(at, _)| &prod[at + "secrets::".len()..])
        .filter(|rest| !rest.starts_with("Sealed"))
        .map(|rest| {
            rest.split(|c: char| !c.is_alphanumeric())
                .next()
                .unwrap_or("")
        })
        .collect();
    assert!(
        others.is_empty(),
        "only the envelope may go from `tg_identity::secrets` into the log: {others:?}"
    );
}

/// **A target that could never permit anything is not applied** (ADR-0124,
/// determination 1).
///
/// # The finding
///
/// `AllowEgress` did not check `host` at all. `*.s3.example.com` thereby went
/// through, into the log (retention-bound, ADR-0020) and into the slice — and
/// both comparisons of the data plane compare exactly. The target was forbidden
/// **and** the name did not resolve: two silent failures, and the operator got
/// `Applied`.
///
/// What is checked is the **form**, not the existence. Whether the name exists is
/// still said only by DNS — it does not belong here.
#[test]
fn an_egress_target_that_could_never_allow_anything_is_refused() {
    use tg_model::egress::Transport;

    let mut state = with_api();

    for (host, transport) in [
        ("ab*.s3.example.com", Transport::Tcp),
        ("*.com", Transport::Tcp),
        ("*", Transport::Tcp),
        ("*.*.example.com", Transport::Tcp),
        ("-ab.example.com", Transport::Tcp),
        ("a b.example.com", Transport::Tcp),
        ("", Transport::Tcp),
        // **For `udp` there is no wildcard** (determination 4): there the node
        // resolves the name itself, and an unresolvable target freezes its whole
        // rule set (ADR-0092, ADR-0019).
        ("*.s3.example.com", Transport::Udp),
    ] {
        let outcome = state.apply(&Command::AllowEgress {
            workload: "api".to_owned(),
            host: host.to_owned(),
            port: 443,
            transport,
        });
        assert!(
            matches!(
                outcome,
                Outcome::Rejected(Rejection::UnusableEgressTarget { .. })
            ),
            "'{host}' ({transport}) must be refused instead of lying in the log \
             without effect -- was: {outcome:?}"
        );
    }

    assert!(
        state.egress().is_empty(),
        "a refused permission must leave no trace: {:?}",
        state.egress()
    );

    // **The counter-check**: the usable forms go through. Without it a check
    // that refuses everything would be just as green.
    for (host, transport) in [
        ("s3.example.com", Transport::Tcp),
        ("*.s3.example.com", Transport::Tcp),
        ("*.s3.example.com", Transport::Quic),
        ("s3.example.com", Transport::Udp),
    ] {
        let outcome = state.apply(&Command::AllowEgress {
            workload: "api".to_owned(),
            host: host.to_owned(),
            port: 443,
            transport,
        });
        assert_eq!(
            outcome,
            Outcome::Applied,
            "'{host}' ({transport}) is a usable permission"
        );
    }
}

/// **The registry host is lower-cased** (ADR-0125, determination 1).
///
/// # The finding
///
/// Measured, `SetRegistryCredential` stored `REGISTRY.example.com` as written.
/// `oci_client::Reference::registry()` likewise returns the reference's spelling
/// unchanged, and the agent looked up exactly: a capital letter on either of the
/// two sides meant **anonymous, and silently** — the same find as with the SNI in
/// ADR-0041, where `AllowEgress` therefore lower-cases the name.
///
/// A registry host is a DNS name.
#[test]
fn the_registry_host_is_lowercased_on_both_ends() {
    let mut state = with_api();
    state.apply(&Command::PutSecret {
        name: "reg".to_owned(),
        value: sealed(b"basic dXNlcjpwdw=="),
    });

    assert_eq!(
        state.apply(&Command::SetRegistryCredential {
            registry: "REGISTRY.Example.COM".to_owned(),
            secret: "reg".to_owned(),
        }),
        Outcome::Applied
    );
    assert_eq!(
        state.registry_credentials(),
        vec![("registry.example.com", "reg")],
        "it is stored lower-cased -- otherwise the node does not find the login"
    );

    // **And the deletion hits it.** Without the normalization on both sides the
    // mapping would stay standing while the operator takes it for removed.
    assert_eq!(
        state.apply(&Command::ClearRegistryCredential {
            registry: "Registry.Example.com".to_owned(),
        }),
        Outcome::Applied
    );
    assert!(
        state.registry_credentials().is_empty(),
        "the mapping should have been removed: {:?}",
        state.registry_credentials()
    );
}

/// **Who pulls from a registry is said by the state** (ADR-0125, D2 and D3).
///
/// The basis of the hint from determination 3, and pure logic: the state machine
/// parses the stored documents — as the volume check from phase 10a already does
/// — and derives the host with **the same** function `tg-runtime` uses for the
/// pull.
#[test]
fn the_state_knows_who_pulls_from_a_registry() {
    let state = with_api();

    assert_eq!(
        state.pullers_of("registry.example.com"),
        vec!["api".to_owned()],
        "`api` pulls from `registry.example.com/api:1`"
    );
    assert_eq!(
        state.pullers_of("REGISTRY.example.com"),
        vec!["api".to_owned()],
        "case-blind, like the mapping itself"
    );
    assert!(
        state.pullers_of("docker.io").is_empty(),
        "and whoever does not pull there does not stand there"
    );
}
