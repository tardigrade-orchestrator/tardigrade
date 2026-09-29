//! `tgctl node invite` — issuing an invitation per ADR-0037.
//!
//! The token producer has stood since the wiring
//! (`tg_identity::join::generate_token` beside `token_digest`); what was
//! missing was the subcommand. It goes over the admin socket from ADR-0044 and
//! thereby over the surface ADR-0018 provides for — only over a Unix socket
//! instead of over mTLS, for as long as there is no credential for an operator.
//!
//! **Only on the leader.** The socket is node-local; a follower cannot append
//! the command, and forwarding it would mean reaching another machine's socket.
//! If the node answers with `ForwardTo`, `tgctl` names the leader and aborts —
//! that is exactly the information the operator needs.

use crate::now;
use std::path::Path;

use tg_admin::{AdminClient, WriteResult};
use tg_identity::join::{generate_token, token_digest};
use tg_model::command::Command;
use tg_model::command::{
    Attachment, CapacityPolicy, CapacityRule, KeyKind, Origin, Resources, RotationPolicy,
    Schedulability, Topology,
};

pub(crate) const DEFAULT_TTL: i64 = 900;

pub(crate) async fn invite(node: &str, ttl: i64, socket: &Path) -> Result<(), String> {
    // The clock is read **once**. Read twice, the deadline in the command and
    // the one in the message could lie a second apart, and then the information
    // to the operator would not agree with the log.
    let now = now();
    let (token, command) = invitation(node, ttl, now);
    let expires_at = now.saturating_add(ttl);

    let client = AdminClient::connect_unix(socket)?;
    let result = client
        .write(command)
        .await
        .map_err(|status| format!("admin socket {}: {status}", socket.display()))?;

    match result {
        WriteResult::Applied { outcome, .. } => {
            // **The rejection first, then the token.** `Applied` means "the
            // cluster applied the command", not "it accepted it" — the verdict
            // stands in it (ADR-0045). The check was missing here, and it was
            // the **one** of sixteen write sites in `tgctl` without it: the
            // token was printed, the rejection went to stderr, and the call
            // ended with 0.
            //
            // What that costs is exactly this command's rationale:
            // `tgctl node invite tgd-2 > join-token` writes a secret into a
            // file that the log does not know, and the error shows up hours
            // later on the new node as "wrong token".
            //
            // Today `InviteNode` always returns `Applied` in the state machine
            // (measured) — the check stands here for the day on which that no
            // longer holds.
            crate::refuse_if_rejected(node, &outcome)?;

            // The token on **stdout**, everything else on stderr: with that
            // `tgctl node invite api > join-token` is the file the agent reads
            // (it trims the line break). An accompanying line in it would be a
            // token that is not right.
            //
            // The lints from ADR-0048 are **discarded** here: they concern
            // workload definitions, and an invitation is none. Printing them
            // would mean hanging them on an action they have nothing to do
            // with.
            // **Without the outcome in brackets.** It stood here as
            // `{outcome:?}` and could only be `Applied` at this place —
            // `refuse_if_rejected` above has otherwise already left. A line
            // that shows the operator Rust syntax for something that is settled
            // anyway is noise beside a secret.
            eprintln!("{node}: invited until {expires_at} (seconds UTC)");
            println!("{token}");
            Ok(())
        }
        WriteResult::ForwardTo { leader } => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the invitation belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        WriteResult::Failed { detail } => Err(format!("invitation refused: {detail}")),
    }
}

fn invitation(node: &str, ttl: i64, now: i64) -> (String, Command) {
    let token = generate_token();
    let digest = token_digest(&token);

    (
        token,
        Command::InviteNode {
            node: node.to_owned(),
            digest,
            // `saturating_add`: an absurdly large deadline becomes "very
            // long", not an invitation that expires in the past. An overflow
            // here would be an invitation that is invalid at once, and that
            // would look like a clock problem.
            expires_at: now.saturating_add(ttl),
        },
    )
}

pub(crate) fn find_socket(data_dir: &Path, id: Option<u64>) -> Result<std::path::PathBuf, String> {
    if let Some(id) = id {
        let path = tg_admin::socket_path(data_dir, id);
        if !path.exists() {
            return Err(format!("no admin socket under {}", path.display()));
        }
        return Ok(path);
    }

    let mut found = Vec::new();
    let entries = std::fs::read_dir(data_dir)
        .map_err(|err| format!("{} not readable: {err}", data_dir.display()))?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = name
            .strip_prefix("admin-")
            .and_then(|rest| rest.strip_suffix(".sock"))
            .and_then(|id| id.parse::<u64>().ok())
        {
            found.push(id);
        }
    }
    found.sort_unstable();

    match found.as_slice() {
        [] => Err(format!(
            "no admin socket in {} — is tgd running on this node?",
            data_dir.display()
        )),
        [id] => Ok(tg_admin::socket_path(data_dir, *id)),
        several => Err(format!(
            "several nodes in {}: {} — which one? (--node-id)",
            data_dir.display(),
            several
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

pub(crate) async fn set_schedulability(
    node: &str,
    mode: Schedulability,
    socket: &Path,
) -> Result<(), String> {
    let client = AdminClient::connect_unix(socket)?;
    let result = client
        .write(Command::SetSchedulability {
            node: node.to_owned(),
            mode,
        })
        .await
        .map_err(|status| format!("admin socket {}: {status}", socket.display()))?;

    match result {
        WriteResult::Applied { outcome, .. } => {
            // A **rejection** is no error of the call, but no success either:
            // an unknown node reported as "cordoned" would let an operator
            // proceed to the restart reassured.
            crate::refuse_if_rejected(node, &outcome)?;
            println!("{node}: {}", mode.as_str());
            Ok(())
        }
        WriteResult::ForwardTo { leader } => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        WriteResult::Failed { detail } => Err(format!("abgelehnt: {detail}")),
    }
}

pub(crate) async fn revoke_trust(node: &str, socket: &Path) -> Result<(), String> {
    let client = AdminClient::connect_unix(socket)?;
    let result = client
        .write(Command::RevokeTrust {
            node: node.to_owned(),
        })
        .await
        .map_err(|status| format!("admin socket {}: {status}", socket.display()))?;

    match result {
        WriteResult::Applied { outcome, .. } => {
            crate::refuse_if_rejected(node, &outcome)?;
            println!("{node}: trust revoked");
            eprintln!(
                "hint: the ordinal stays (ADR-0039) — it is freed only by \
                 'tgctl node remove'. The Raft port checks against a local peer \
                 list; there the revocation is an operational action \
                 (ADR-0043)."
            );
            Ok(())
        }
        WriteResult::ForwardTo { leader } => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        WriteResult::Failed { detail } => Err(format!("'{node}': {detail}")),
    }
}

pub(crate) async fn remove(node: &str, socket: &Path) -> Result<(), String> {
    let client = AdminClient::connect_unix(socket)?;
    let result = client
        .write(Command::RemoveNode {
            name: node.to_owned(),
        })
        .await
        .map_err(|status| format!("admin socket {}: {status}", socket.display()))?;

    match result {
        WriteResult::Applied { outcome, .. } => {
            crate::refuse_if_rejected(node, &outcome)?;
            println!("{node}: removed");
            eprintln!(
                "hint: the ordinal is thereby free and can go to a new node. What \
                 ran on this node is thereby not cleared away — it is \
                 responsible for that itself (ADR-0058)."
            );

            // **And the data key** (ADR-0095, ADR-0100). A removed node keeps
            // its disk, and `identity/secrets.key` lies on it -- the **one**
            // key with which every secret of the cluster is sealed. Together
            // with a copy of the log or of an audit segment (the ciphertext
            // stands there, ADR-0020) it thereby reads every secret of its
            // period of validity.
            //
            // **First look, then warn.** A cluster without secrets has nothing
            // to protect, and a warning that always appears is read over -- the
            // same consideration as with `cluster remove`, which looks into the
            // projection beforehand.
            if let Ok(secrets) = client.secrets().await
                && !secrets.names.is_empty()
            {
                eprintln!(
                    "warning: this node holds the cluster's data key ({} \
                     secret(s) are sealed with it). Its disk belongs deleted — \
                     and for as long as it lies anywhere, the key belongs \
                     rotated: `tgctl cluster secret rekey` (ADR-0100).",
                    secrets.names.len()
                );
            }

            Ok(())
        }
        WriteResult::ForwardTo { leader } => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        WriteResult::Failed { detail } => Err(format!("'{node}': {detail}")),
    }
}

pub(crate) async fn set_attachment(
    node: &str,
    mode: Attachment,
    socket: &Path,
) -> Result<(), String> {
    let client = AdminClient::connect_unix(socket)?;
    let result = client
        .write(Command::SetAttachment {
            node: node.to_owned(),
            mode,
        })
        .await
        .map_err(|status| format!("admin socket {}: {status}", socket.display()))?;

    match result {
        WriteResult::Applied { outcome, .. } => {
            crate::refuse_if_rejected(node, &outcome)?;
            println!("{node}: {}", mode.as_str());
            if mode == Attachment::Detached {
                eprintln!(
                    "hint: the ordinal and the trust stay. What cannot move (a \
                     writable volume, ADR-0027) stays lying and is reported."
                );
            }
            Ok(())
        }
        WriteResult::ForwardTo { leader } => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        WriteResult::Failed { detail } => Err(format!("abgelehnt: {detail}")),
    }
}

pub(crate) async fn rotation(policy: RotationPolicy, socket: &Path) -> Result<(), String> {
    let client = AdminClient::connect_unix(socket)?;
    let result = client
        .write(Command::SetRotationPolicy {
            policy: policy.clone(),
        })
        .await
        .map_err(|status| format!("admin socket {}: {status}", socket.display()))?;

    match result {
        WriteResult::Applied { outcome, .. } => {
            crate::refuse_if_rejected("rotation policy", &outcome)?;
            if policy.is_empty() {
                println!("rotation policy withdrawn — nothing rotates of its own accord any more");
            } else {
                println!("rotation policy set");
                eprintln!(
                    "hint: the leader spreads the changes over the period \
                     (ADR-0057); a generation decreed by hand wins."
                );
            }
            Ok(())
        }
        WriteResult::ForwardTo { leader } => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        WriteResult::Failed { detail } => Err(format!("abgelehnt: {detail}")),
    }
}

pub(crate) fn rotation_of(specs: &[String]) -> Result<RotationPolicy, String> {
    let mut policy = RotationPolicy::default();

    for spec in specs {
        let (kind, days) = spec
            .split_once('=')
            .ok_or_else(|| format!("'{spec}' is not 'kind=days'"))?;
        let kind: KeyKind = kind.parse()?;
        let days: u32 = days
            .parse()
            .map_err(|_| format!("'{days}' is no number of days"))?;
        policy = policy.with(kind, days);
    }

    Ok(policy)
}

pub(crate) async fn rotate(
    node: &str,
    kind: KeyKind,
    generation: u64,
    socket: &Path,
) -> Result<(), String> {
    let client = AdminClient::connect_unix(socket)?;

    // **First look at what the calendar wants** (ADR-0057). A decree wins
    // against the policy, because `rotations` writes only what is **higher** --
    // and that means: a number above the calendar computation switches the
    // automatic rotation off, for this node and this kind. Measured, with a
    // period of 90 days the generation stood at 230 on 2026-09-08; a decreed
    // 1000 would be overtaken only in 189 years, and in the state that looks
    // like an ordinary decree.
    //
    // The right number hangs on the period (at 365 days it is 56), so an
    // operator cannot guess it. Warned and **not** refused: the decree is a
    // legitimate action (ADR-0055), and whoever issues it possibly knows what
    // they are doing.
    warn_if_it_outruns_the_calendar(&client, node, kind, generation).await;

    let result = client
        .write(Command::SetKeyGeneration {
            node: node.to_owned(),
            kind,
            generation,
        })
        .await
        .map_err(|status| format!("admin socket {}: {status}", socket.display()))?;

    match result {
        WriteResult::Applied { outcome, .. } => {
            crate::refuse_if_rejected(node, &outcome)?;
            println!("{node}: {kind} shall have generation {generation}");
            eprintln!(
                "hint: the node announces the new key and switches over only \
                 when the cluster has confirmed it (ADR-0055). Until then the \
                 old one applies."
            );
            Ok(())
        }
        WriteResult::ForwardTo { leader } => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        WriteResult::Failed { detail } => Err(format!("abgelehnt: {detail}")),
    }
}

async fn warn_if_it_outruns_the_calendar(
    client: &AdminClient,
    node: &str,
    kind: KeyKind,
    generation: u64,
) {
    let Ok(answer) = client.settings().await else {
        return;
    };
    let Some((_, period)) = answer
        .rotation
        .iter()
        .find(|(policy_kind, _)| *policy_kind == kind)
    else {
        return;
    };

    let policy = tg_model::keys::RotationPolicy::default().with(kind, *period);
    let day = tg_model::keys::day_of(u64::try_from(crate::now()).unwrap_or(0));
    let Some(wanted) = policy.wanted(node, kind, day) else {
        return;
    };

    if generation > wanted {
        eprintln!(
            "warning: the policy wants generation {wanted} for {node}/{kind} \
             today (period {period} days). A decreed {generation} lies above \
             it, and `rotations` writes only what is **higher** — the automatic \
             rotation is thereby off until the calendar reaches {generation}."
        );
    }
}

pub(crate) async fn upsert(
    node: &str,
    topology: Topology,
    capacity: Resources,
    reserved: Resources,
    socket: &Path,
) -> Result<(), String> {
    write(
        socket,
        Command::UpsertNode {
            name: node.to_owned(),
            topology,
            capacity,
            reserved,
            // Issued by hand — that is the whole difference from what the
            // leader writes out of a policy (ADR-0049).
            source: Origin::Operator,
        },
        &format!("{node}: entered"),
    )
    .await
}

pub(crate) async fn policy(policy: CapacityPolicy, socket: &Path) -> Result<(), String> {
    let what = if policy.is_empty() {
        "policy withdrawn".to_owned()
    } else {
        "policy set".to_owned()
    };

    write(socket, Command::SetCapacityPolicy { policy }, &what).await
}

async fn write(socket: &Path, command: Command, what: &str) -> Result<(), String> {
    let client = AdminClient::connect_unix(socket)?;
    let result = client
        .write(command)
        .await
        .map_err(|status| format!("admin socket {}: {status}", socket.display()))?;

    match result {
        WriteResult::Applied { outcome, .. } => {
            crate::refuse_if_rejected(what, &outcome)?;
            println!("{what}");
            Ok(())
        }
        WriteResult::ForwardTo { leader } => Err(match leader {
            Some(leader) => {
                format!("this node does not lead — the command belongs on node {leader}")
            }
            None => "this node does not lead and knows no leader".to_owned(),
        }),
        WriteResult::Failed { detail } => Err(format!("abgelehnt: {detail}")),
    }
}

pub(crate) fn resources(entries: &[String]) -> Result<Resources, String> {
    let mut out = Resources::default();

    for entry in entries {
        let (name, amount) = entry
            .split_once('=')
            .ok_or_else(|| format!("'{entry}' needs the form name=number"))?;
        if name.is_empty() {
            return Err(format!("'{entry}': the name is missing"));
        }
        let amount: u64 = amount
            .parse()
            .map_err(|_| format!("'{entry}': '{amount}' is no number"))?;
        out = out.with(name, amount);
    }

    Ok(out)
}

pub(crate) fn policy_of(entries: &[String]) -> Result<CapacityPolicy, String> {
    let mut policy = CapacityPolicy::default();

    for entry in entries {
        let (name, rest) = entry
            .split_once(':')
            .ok_or_else(|| format!("'{entry}' needs the form name:key=value,…"))?;

        let mut rule = CapacityRule {
            subtract: 0,
            percent: u32::MAX,
            cap: None,
            reserve: 0,
        };
        for field in rest.split(',').filter(|field| !field.is_empty()) {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| format!("'{field}' needs the form key=value"))?;
            let number = |what: &str| -> Result<u64, String> {
                value
                    .parse()
                    .map_err(|_| format!("{what}: '{value}' is no number"))
            };
            match key {
                "subtract" => rule.subtract = number("subtract")?,
                "percent" => {
                    rule.percent = value
                        .parse()
                        .map_err(|_| format!("percent: '{value}' is no number"))?;
                }
                "cap" => rule.cap = Some(number("cap")?),
                "reserve" => rule.reserve = number("reserve")?,
                other => {
                    return Err(format!(
                        "unknown key '{other}' — subtract, percent, cap or reserve"
                    ));
                }
            }
        }

        if rule.percent == u32::MAX {
            return Err(format!("'{name}': percent is missing"));
        }
        policy = policy.with(name, rule);
    }

    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_TTL, find_socket, invitation};
    use tg_identity::join::token_digest;
    use tg_model::command::Command;

    fn socket(dir: &std::path::Path, name: &str) {
        std::fs::write(dir.join(name), "").expect("file");
    }

    #[test]
    fn the_digest_in_the_command_belongs_to_the_issued_token() {
        let (token, command) = invitation("tgd-2", DEFAULT_TTL, 1_000);

        match command {
            Command::InviteNode {
                node,
                digest,
                expires_at,
            } => {
                assert_eq!(node, "tgd-2");
                assert_eq!(digest, token_digest(&token));
                assert_eq!(expires_at, 1_000 + DEFAULT_TTL);
            }
            other => panic!("no InviteNode: {other:?}"),
        }
    }

    #[test]
    fn the_token_never_appears_in_the_command() {
        let (token, command) = invitation("tgd-2", DEFAULT_TTL, 0);
        let wire = format!("{command:?}");

        assert!(
            !wire.contains(&token),
            "the token stands in the command: {wire}"
        );
    }

    #[test]
    fn two_invitations_never_share_a_token() {
        let (first, _) = invitation("tgd-2", DEFAULT_TTL, 0);
        let (second, _) = invitation("tgd-2", DEFAULT_TTL, 0);

        assert_ne!(first, second);
        assert_eq!(first.len(), 64, "256 bits of hex");
    }

    #[test]
    fn an_absurd_ttl_saturates_instead_of_wrapping() {
        let (_, command) = invitation("tgd-2", i64::MAX, i64::MAX);

        match command {
            Command::InviteNode { expires_at, .. } => assert_eq!(expires_at, i64::MAX),
            other => panic!("no InviteNode: {other:?}"),
        }
    }

    #[test]
    fn a_hostile_name_is_passed_through_unchanged_and_used_for_nothing() {
        for name in [
            "../../etc/shadow",
            "tgd-1; rm -rf /",
            "tgd-1\nadmin",
            "$(whoami)",
            "",
            "\u{202e}1-dgt",
        ] {
            let (_, command) = invitation(name, DEFAULT_TTL, 0);
            match command {
                Command::InviteNode { node, .. } => assert_eq!(node, name),
                other => panic!("no InviteNode: {other:?}"),
            }
        }
    }

    #[test]
    fn an_explicit_id_is_taken_and_a_missing_socket_is_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        socket(dir.path(), "admin-1.sock");
        socket(dir.path(), "admin-7.sock");

        let found = find_socket(dir.path(), Some(7)).expect("socket 7");
        assert!(found.ends_with("admin-7.sock"), "{found:?}");

        let err = find_socket(dir.path(), Some(9)).expect_err("socket 9 is missing");
        assert!(err.contains("admin-9.sock"), "{err}");
    }

    #[test]
    fn a_single_socket_is_found_without_being_named() {
        let dir = tempfile::tempdir().expect("tempdir");
        socket(dir.path(), "admin-3.sock");

        let found = find_socket(dir.path(), None).expect("socket");
        assert!(found.ends_with("admin-3.sock"), "{found:?}");
    }

    #[test]
    fn several_sockets_are_listed_and_none_is_chosen() {
        let dir = tempfile::tempdir().expect("tempdir");
        socket(dir.path(), "admin-2.sock");
        socket(dir.path(), "admin-11.sock");

        let err = find_socket(dir.path(), None).expect_err("several");
        assert!(err.contains("2, 11"), "unsorted or incomplete: {err}");
        assert!(err.contains("--node-id"), "{err}");
    }

    #[test]
    fn no_socket_says_so_and_names_the_directory() {
        let dir = tempfile::tempdir().expect("tempdir");

        let err = find_socket(dir.path(), None).expect_err("none");
        assert!(err.contains(&dir.path().display().to_string()), "{err}");
        assert!(err.contains("tgd"), "{err}");
    }

    #[test]
    fn near_misses_are_not_sockets() {
        let dir = tempfile::tempdir().expect("tempdir");
        for name in [
            "admin-.sock",
            "admin-x.sock",
            "admin-1.sock.bak",
            "admin-01.sock.tmp",
            "audit-1.jsonl",
            "admin-1",
            "-1.sock",
        ] {
            socket(dir.path(), name);
        }
        socket(dir.path(), "admin-5.sock");

        let found = find_socket(dir.path(), None).expect("only one");
        assert!(found.ends_with("admin-5.sock"), "{found:?}");
    }

    #[test]
    fn a_missing_directory_is_reported_as_unreadable() {
        let err =
            find_socket(std::path::Path::new("/does/not/exist"), None).expect_err("no directory");

        assert!(err.contains("not readable"), "{err}");
    }
}

#[cfg(test)]
mod policy_tests {
    use super::{policy_of, resources};
    use tg_model::command::Resources;

    fn args(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|e| (*e).to_owned()).collect()
    }

    #[test]
    fn any_resource_name_is_accepted() {
        let parsed = resources(&args(&["cpu-millicores=4000", "gpu=2"])).expect("readable");

        assert_eq!(parsed.get(Resources::CPU_MILLICORES), 4000);
        assert_eq!(parsed.get("gpu"), 2);
    }

    #[test]
    fn an_unusable_entry_is_named_and_refused() {
        for entry in ["cpu-millicores", "=4000", "cpu=many", "cpu=-1", "cpu=1.5"] {
            let err = resources(&args(&[entry])).expect_err(entry);
            // **The objected place, not a common word.** Here
            // `|| err.contains("name")` once stood; measured, each of the three
            // messages names the entry, so the second half **never** takes
            // effect and only let through a message that keeps the entry
            // quiet.
            assert!(err.contains(entry), "{entry}: {err}");
        }
    }

    #[test]
    fn a_rule_is_read_as_written() {
        let policy = policy_of(&args(&[
            "cpu-millicores:subtract=2000,percent=80,cap=16000,reserve=1000",
        ]))
        .expect("readable");

        let rule = policy.rule(Resources::CPU_MILLICORES).expect("rule");
        assert_eq!(rule.subtract, 2000);
        assert_eq!(rule.percent, 80);
        assert_eq!(rule.cap, Some(16000));
        assert_eq!(rule.reserve, 1000);
    }

    #[test]
    fn a_rule_without_a_percentage_is_refused() {
        let err = policy_of(&args(&["cpu-millicores:subtract=2000"])).expect_err("without percent");

        assert!(err.contains("percent"), "{err}");
    }

    #[test]
    fn an_unknown_key_is_named() {
        let err = policy_of(&args(&["cpu:percent=80,reserv=1000"])).expect_err("typo");

        assert!(err.contains("reserv"), "{err}");
        assert!(err.contains("reserve"), "{err}");
    }

    #[test]
    fn no_rules_means_no_policy() {
        assert!(policy_of(&[]).expect("empty").is_empty());
    }
}

#[cfg(test)]
mod rotation_tests {
    use super::rotation_of;
    use tg_model::command::KeyKind;

    fn args(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|e| (*e).to_owned()).collect()
    }

    #[test]
    fn both_key_kinds_get_their_own_period() {
        let policy = rotation_of(&args(&["identity=90", "underlay=30"])).expect("readable");

        let day = 1_000;
        let identity = policy
            .wanted("node-1", KeyKind::Identity, day)
            .expect("the identity rotates");
        let underlay = policy
            .wanted("node-1", KeyKind::Underlay, day)
            .expect("the underlay rotates");

        // The shorter period yields the higher generation on the same day —
        // otherwise the two settings would have arrived swapped.
        assert!(
            underlay > identity,
            "identity={identity}, underlay={underlay}"
        );
    }

    #[test]
    fn a_period_of_zero_switches_the_kind_off() {
        let policy = rotation_of(&args(&["identity=0"])).expect("zero is admissible");

        assert_eq!(
            policy.wanted("node-1", KeyKind::Identity, 1_000),
            None,
            "a period of zero must yield no generation"
        );
        assert!(policy.is_empty(), "and the policy applies to nothing");
    }

    #[test]
    fn no_specs_means_no_policy() {
        let policy = rotation_of(&[]).expect("empty is readable");

        assert!(policy.is_empty());
        assert_eq!(policy.wanted("node-1", KeyKind::Identity, 1_000), None);
    }

    #[test]
    fn every_unreadable_spec_names_itself() {
        for (spec, needle) in [
            // No `=`: the whole setting is the objected place.
            ("identity90", "identity90"),
            // A typo in the kind is quoted **and** the alternatives are named —
            // otherwise an operator guesses what the kinds are called.
            ("identitiy=90", "identitiy"),
            ("identitiy=90", "underlay"),
            // No number of days.
            ("identity=ninety", "ninety"),
            ("identity=", "number"),
            // An empty kind names the alternatives — measured, the message
            // quotes an empty `''` in the process, which says nothing on its
            // own; what carries are the two names beside it.
            ("=90", "identity"),
        ] {
            let err = rotation_of(&args(&[spec])).expect_err("unreadable");
            assert!(
                err.contains(needle),
                "'{spec}' has to name '{needle}': {err}"
            );
        }
    }
}
