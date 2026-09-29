//! Call options and time values.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use openraft::{Config, SnapshotPolicy};
use tg_consensus::{NodeId, PeerAddrs};
use tg_telemetry::args::Args as TelemetryArgs;

pub const DEFAULT_DATA_DIR: &str = "/var/lib/tardigrade/control-plane";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    pub heartbeat_ms: u64,
    pub election_min_ms: u64,
    pub election_max_ms: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            heartbeat_ms: 100,
            election_min_ms: 500,
            election_max_ms: 1000,
        }
    }
}

impl Timing {
    pub fn to_config(self, snapshots: Snapshots) -> Result<Config, String> {
        // Zero first, and expressly at that: `openraft` lets it through
        // (`election_min > heartbeat` is satisfied with `500 > 0`), and the rule
        // from ADR-0033 likewise (`0 * 3 = 0`). A heartbeat of zero is, however, at
        // the same time a replication time limit of zero -- the cluster would elect
        // and afterwards never commit anything again, without reporting a single
        // error. Exactly the class of silent failure ADR-0033 describes.
        if self.heartbeat_ms == 0 {
            return Err(
                "heartbeat_interval 0 ms: that is at the same time replication's \
                 time limit, no answer would ever arrive in time -- ADR-0033"
                    .to_owned(),
            );
        }
        if self.election_min_ms < self.heartbeat_ms.saturating_mul(3) {
            return Err(format!(
                "election_timeout_min ({} ms) falls below three times the \
                 heartbeat ({} ms) -- ADR-0033",
                self.election_min_ms, self.heartbeat_ms
            ));
        }
        if self.election_max_ms <= self.election_min_ms {
            return Err(format!(
                "election_timeout_max ({} ms) must lie above the minimum ({} ms)",
                self.election_max_ms, self.election_min_ms
            ));
        }

        if snapshots.every_logs == 0 {
            return Err("--snapshot-every 0: a snapshot would never arise".to_owned());
        }

        Config {
            cluster_name: "tardigrade".to_owned(),
            heartbeat_interval: self.heartbeat_ms,
            election_timeout_min: self.election_min_ms,
            election_timeout_max: self.election_max_ms,
            snapshot_policy: SnapshotPolicy::LogsSinceLast(snapshots.every_logs),
            max_in_snapshot_log_to_keep: snapshots.keep_logs,
            ..Config::default()
        }
        .validate()
        .map_err(|err| err.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshots {
    pub every_logs: u64,
    pub keep_logs: u64,
}

impl Default for Snapshots {
    fn default() -> Self {
        Self {
            every_logs: 5_000,
            keep_logs: 1_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub id: NodeId,
    pub listen: SocketAddr,
    pub cluster_listen: SocketAddr,
    pub node_listen: SocketAddr,
    pub node: String,
    pub peers: PeerAddrs,
    pub signer_listen: Option<SocketAddr>,
    pub signers: BTreeMap<u16, String>,
    pub operator_listen: Option<SocketAddr>,
    pub data_dir: PathBuf,
    pub init: bool,
    pub audit_export: bool,
    pub audit_from: Option<u64>,
    pub audit_to: Option<u64>,
    pub audit_anchor: Option<String>,
    pub init_voters: Option<Vec<NodeId>>,
    pub timing: Timing,
    pub snapshots: Snapshots,
    pub audit_rotate: Option<u64>,
    pub trust_domain: String,
    pub telemetry: TelemetryArgs,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            id: 1,
            // Loopback as the default: in this phase the Raft port is not
            // authenticated (see `tg_consensus::net`). Opening it shall be an
            // action, not an omission.
            // Loopback as the default for all three. Two of them have been
            // authenticated since ADR-0043 and could be bound more widely -- that
            // they may does not mean that they should, as long as nobody has said
            // so.
            listen: SocketAddr::from(([127, 0, 0, 1], 7001)),
            cluster_listen: SocketAddr::from(([127, 0, 0, 1], 7002)),
            node_listen: SocketAddr::from(([127, 0, 0, 1], 7003)),
            // The first label of the hostname, lower-cased: since ADR-0043 the
            // name becomes a SPIFFE identifier, and an FQDN is not one.
            node: tg_syscall::hostname()
                .as_deref()
                .and_then(tg_identity::cluster::node_name_from_hostname)
                .unwrap_or_else(|| "node".to_owned()),
            peers: PeerAddrs::new(),
            signer_listen: None,
            operator_listen: None,
            signers: BTreeMap::new(),
            data_dir: PathBuf::from(DEFAULT_DATA_DIR),
            trust_domain: String::from(tg_identity::DEFAULT_TRUST_DOMAIN),
            init: false,
            audit_export: false,
            audit_from: None,
            audit_to: None,
            audit_anchor: None,
            init_voters: None,
            telemetry: TelemetryArgs::with_port(7101),
            timing: Timing::default(),
            snapshots: Snapshots::default(),
            audit_rotate: Some(tg_consensus::audit::DEFAULT_ROTATE_AT),
        }
    }
}

fn address(arg: &str, raw: &str) -> Result<SocketAddr, String> {
    raw.parse().map_err(|err| format!("{arg}: {err}"))
}

fn signer_arg(options: &mut Options, arg: &str, raw: &str) -> Result<(), String> {
    if arg == "--signer-listen" {
        options.signer_listen = Some(address(arg, raw)?);
        return Ok(());
    }

    let (seat, addr) = raw
        .split_once('=')
        .ok_or_else(|| format!("--signer '{raw}': expected <seat>=<url>"))?;
    let seat: u16 = seat
        .trim()
        .parse()
        .map_err(|err| format!("--signer '{raw}': {err}"))?;

    // Named twice is a finding and not last-one-wins: two addresses for one seat
    // are two accesses to the same share, and `ThresholdSigner::new` refuses that
    // anyway -- here it stands out at the start instead of at the first signing.
    if options.signers.insert(seat, addr.to_owned()).is_some() {
        return Err(format!("--signer: seat {seat} named twice"));
    }

    Ok(())
}

pub const USAGE: &str = "\
tgd -- control-plane node for Tardigrade

Call:
  tgd --id <n> --listen <address> --peer <n>=<url> [...]

Options:
  --id <n>                  own node identifier (default: 1)
  --node <name>             own node name (default: the first label of the
                            hostname, otherwise `node`); stands in the
                            URI SAN of the cluster leaf (ADR-0043)
  --cluster-listen <addr>    Raft port, mTLS against <data-dir>/peers/<id>.pem
                            (default: 127.0.0.1:7002)
  --node-listen <addr>       node session, mTLS against the trust list from
                            the log (default: 127.0.0.1:7003)
  --listen <ip:port>        listening address (default: 127.0.0.1:7001)
  --peer <n>=<url>          node n is reachable at <url>; give it several
                            times, our own node included
  --data-dir <path>         data directory (default: /var/lib/tardigrade/control-plane)
  --trust-domain <name>     the SPIFFE server's trust domain (default:
                            cluster.local). The signing material lies under
                            <data-dir>/signing/ (ca.pem, ca.key.pem,
                            bundle.pem); if it is missing, the node runs
                            without a SPIFFE server
  --operator-listen <addr>   operator port, mTLS against the registration from
                            the log (ADR-0103). Without the setting it stays at
                            the Unix socket; whoever reaches it with a
                            registered key may do everything
  --signer-listen <addr>     the signing group's signer port, mTLS against
                            <data-dir>/signers/<seat>.pem (ADR-0097). Without
                            the setting this node does not offer its share
  --signer <seat>=<url>     seat <seat> of the signing group is reachable at
                            <url>; give it several times, **without** our own
                            seat -- that comes from the share
  --init                    create the membership (exactly once in a cluster's
                            life)
  --init-voters <n,n,...>   who is a voter at the creation
                            (default: all --peer settings). Being reachable
                            and being a member are two different things.
  --heartbeat-ms <n>        heartbeat interval (default: 100, ADR-0033)
  --election-min-ms <n>     lower election timeout (default: 500)
  --election-max-ms <n>     upper election timeout (default: 1000)
  --snapshot-every <n>      a snapshot after n entries (default: 5000)
  --keep-logs <n>           entries that stay in the log after a snapshot
                            (default: 1000)
  --audit-export            write a log range as a sealed segment to stdout
                            and end (ADR-0137). Only with the node stopped --
                            `redb` lets exactly one process at the log.
                            Without verdicts (ADR-0045): the log carries
                            commands, no results
                            [--audit-from <n>] [--audit-to <n>]
                            [--audit-anchor <hex>]
  --audit-rotate <n>        records per audit segment (default: 100000,
                            0 = never rotate). A closed segment can be moved
                            into the WORM archive, an open file cannot
                            (ADR-0020). And it bounds the start: at a full
                            segment the check on opening costs a measured
                            1.18 s, without rotation it grows with the archive
                            (ADR-0132).
";

pub const USAGE_TAIL: &str = "\
  help                      this overview (also -h, --help)

The cluster port demands a client certificate and checks it against
peers/<id>.pem (ADR-0043). The admin access lies on a Unix socket in the
data directory, not on a port (ADR-0044).
";

#[must_use]
pub fn usage() -> String {
    format!("{USAGE}{}{USAGE_TAIL}", TelemetryArgs::USAGE)
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut peers = PeerAddrs::new();
        let mut iter = args.iter();

        while let Some(arg) = iter.next() {
            let mut value = || -> Result<String, String> {
                iter.next()
                    .cloned()
                    .ok_or_else(|| format!("{arg} needs a value"))
            };

            match arg.as_str() {
                "--id" => options.id = number(&value()?, arg)?,
                "--listen" => {
                    let raw = value()?;
                    options.listen = raw
                        .parse()
                        .map_err(|err| format!("--listen '{raw}': {err}"))?;
                }
                "--cluster-listen" => {
                    let raw = value()?;
                    options.cluster_listen = raw
                        .parse()
                        .map_err(|err| format!("--cluster-listen '{raw}': {err}"))?;
                }
                "--node-listen" => {
                    let raw = value()?;
                    options.node_listen = raw
                        .parse()
                        .map_err(|err| format!("--node-listen '{raw}': {err}"))?;
                }
                "--node" => {
                    let raw = value()?;
                    if raw.trim().is_empty() {
                        return Err("--node: an empty name".to_owned());
                    }
                    options.node = raw;
                }
                "--peer" => {
                    let raw = value()?;
                    let (id, addr) = raw
                        .split_once('=')
                        .ok_or_else(|| format!("--peer '{raw}': expected <n>=<url>"))?;
                    peers = peers.with(number(id, "--peer")?, addr);
                }
                "--operator-listen" => {
                    options.operator_listen = Some(address(arg, &value()?)?);
                }
                "--signer-listen" | "--signer" => {
                    signer_arg(&mut options, arg, &value()?)?;
                }
                "--data-dir" => options.data_dir = PathBuf::from(value()?),
                "--trust-domain" => options.trust_domain = value()?,
                "--init" => options.init = true,
                "--audit-export" => options.audit_export = true,
                "--audit-from" => options.audit_from = Some(number(&value()?, arg)?),
                "--audit-to" => options.audit_to = Some(number(&value()?, arg)?),
                "--audit-anchor" => options.audit_anchor = Some(value()?),
                "--init-voters" => {
                    let raw = value()?;
                    let mut ids = Vec::new();
                    for part in raw.split(',') {
                        ids.push(number(part.trim(), "--init-voters")?);
                    }
                    if ids.is_empty() {
                        return Err("--init-voters: an empty list".to_owned());
                    }
                    options.init_voters = Some(ids);
                }
                "--heartbeat-ms" => options.timing.heartbeat_ms = number(&value()?, arg)?,
                "--election-min-ms" => options.timing.election_min_ms = number(&value()?, arg)?,
                "--election-max-ms" => options.timing.election_max_ms = number(&value()?, arg)?,
                "--audit-rotate" => {
                    options.audit_rotate = match number(&value()?, arg)? {
                        // Zero means "never" and not "at every record": one
                        // segment per entry would be a directory full of files with
                        // one line each.
                        0 => None,
                        n => Some(n),
                    }
                }
                "--snapshot-every" => options.snapshots.every_logs = number(&value()?, arg)?,
                "--keep-logs" => options.snapshots.keep_logs = number(&value()?, arg)?,
                other => {
                    // The telemetry settings read the same in all three binaries
                    // and are therefore evaluated in one place.
                    if !options.telemetry.take(other, value)? {
                        return Err(format!("an unknown option '{other}'"));
                    }
                }
            }
        }

        if !peers.is_empty() {
            options.peers = peers;
        }

        consistent(&options)?;
        Ok(options)
    }
}

fn consistent(options: &Options) -> Result<(), String> {
    if options.peers.get(options.id).is_none() {
        return Err(format!(
            "our own node {} is missing from the --peer settings",
            options.id
        ));
    }

    // **`--init-voters` without `--init` is a contradiction**, and without this
    // line a silent one: the setting is read only *within* the initialization
    // (`lib.rs`), so it does nothing otherwise. An operator who types it and
    // forgets `--init` gets a node that waits for its admission -- and believes
    // they have determined the membership.
    //
    // An error and no warning, because it is a **setting** and no runtime
    // condition: the check below refuses likewise.
    if options.init_voters.is_some() && !options.init {
        return Err("--init-voters takes effect only with --init: without the \
             initialization the list is not read"
            .to_owned());
    }

    // A member whose address nobody knows is a node the cluster counts along and
    // never reaches -- the quorum would be smaller from the beginning than it
    // looks.
    if let Some(voters) = &options.init_voters {
        for id in voters {
            if options.peers.get(*id).is_none() {
                return Err(format!(
                    "--init-voters names node {id}, for which no --peer address is present"
                ));
            }
        }
    }

    Ok(())
}

fn number(raw: &str, what: &str) -> Result<u64, String> {
    raw.parse()
        .map_err(|err| format!("{what} '{raw}': no number ({err})"))
}

#[cfg(test)]
mod tests {
    use super::{Options, Timing};
    use std::path::Path;

    fn parse(args: &[&str]) -> Result<Options, String> {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        Options::parse(&args)
    }

    fn minimal(extra: &[&str]) -> Vec<String> {
        let mut args = vec!["--peer".to_owned(), "1=http://127.0.0.1:7001".to_owned()];
        args.extend(extra.iter().map(|a| (*a).to_owned()));
        args
    }

    // --- The time rule from ADR-0033 ---------------------------------------

    #[test]
    fn the_default_profile_is_valid() {
        let timing = Timing::default();

        assert_eq!(timing.heartbeat_ms, 100);
        assert_eq!(timing.election_min_ms, 500);
        assert_eq!(timing.election_max_ms, 1000);

        let config = timing
            .to_config(super::Snapshots::default())
            .expect("the starting profile must be valid");
        assert_eq!(config.heartbeat_interval, 100);
        assert_eq!(config.election_timeout_min, 500);
        assert_eq!(config.election_timeout_max, 1000);
    }

    #[test]
    fn an_election_timeout_too_close_to_the_heartbeat_is_rejected() {
        for (heartbeat, election_min) in [(100, 101), (100, 299), (50, 149), (1000, 2999)] {
            let timing = Timing {
                heartbeat_ms: heartbeat,
                election_min_ms: election_min,
                election_max_ms: election_min * 2,
            };
            let err = timing
                .to_config(super::Snapshots::default())
                .expect_err("it should have been refused");
            assert!(err.contains("ADR-0033"), "{err}");
            assert!(err.contains("three times"), "{err}");
        }
    }

    #[test]
    fn exactly_three_times_the_heartbeat_is_enough() {
        let timing = Timing {
            heartbeat_ms: 100,
            election_min_ms: 300,
            election_max_ms: 600,
        };

        assert!(timing.to_config(super::Snapshots::default()).is_ok());
    }

    #[test]
    fn a_maximum_at_or_below_the_minimum_is_rejected() {
        for max in [499, 500] {
            let timing = Timing {
                heartbeat_ms: 100,
                election_min_ms: 500,
                election_max_ms: max,
            };
            assert!(
                timing.to_config(super::Snapshots::default()).is_err(),
                "max = {max}"
            );
        }
    }

    #[test]
    fn a_zero_heartbeat_does_not_pass_validation() {
        let timing = Timing {
            heartbeat_ms: 0,
            election_min_ms: 500,
            election_max_ms: 1000,
        };

        // Neither `openraft` nor the distance rule catches this case: the test
        // found the gap, and `to_config` has closed it expressly since.
        let err = timing
            .to_config(super::Snapshots::default())
            .expect_err("zero must not get through");
        assert!(err.contains("replication"), "{err}");
    }

    // --- The command line ---------------------------------------------------

    #[test]
    fn a_minimal_call_yields_the_defaults() {
        let options = Options::parse(&minimal(&[])).expect("valid");

        assert_eq!(options.id, 1);
        assert_eq!(options.listen.port(), 7001);
        assert!(!options.init);
        assert_eq!(options.data_dir, Path::new(super::DEFAULT_DATA_DIR));
        assert_eq!(options.timing, Timing::default());
        assert_eq!(options.peers.get(1), Some("http://127.0.0.1:7001"));
    }

    #[test]
    fn every_option_is_read() {
        let options = parse(&[
            "--id",
            "3",
            "--listen",
            "127.0.0.1:9003",
            "--cluster-listen",
            "127.0.0.1:9103",
            "--node-listen",
            "127.0.0.1:9203",
            "--operator-listen",
            "127.0.0.1:9303",
            "--signer-listen",
            "127.0.0.1:9403",
            "--signer",
            "2=http://seat-2:9403",
            "--node",
            "tgd-3",
            "--peer",
            "1=http://a:1",
            "--peer",
            "3=http://c:3",
            "--data-dir",
            "/srv/tg",
            "--init",
            "--init-voters",
            "1,3",
            "--heartbeat-ms",
            "200",
            "--election-min-ms",
            "600",
            "--election-max-ms",
            "1200",
            "--snapshot-every",
            "5000",
            "--keep-logs",
            "2000",
            "--audit-rotate",
            "50000",
            "--audit-export",
            "--audit-from",
            "7",
            "--audit-to",
            "9",
            "--audit-anchor",
            "4711",
            "--trust-domain",
            "acme.internal",
        ])
        .expect("valid");

        assert_eq!(options.id, 3);
        assert_eq!(options.listen.to_string(), "127.0.0.1:9003");
        assert_eq!(options.cluster_listen.to_string(), "127.0.0.1:9103");
        assert_eq!(options.node_listen.to_string(), "127.0.0.1:9203");
        assert_eq!(
            options.operator_listen.map(|at| at.to_string()).as_deref(),
            Some("127.0.0.1:9303")
        );
        assert_eq!(
            options.signer_listen.map(|at| at.to_string()).as_deref(),
            Some("127.0.0.1:9403")
        );
        assert_eq!(
            options.signers.get(&2).map(String::as_str),
            Some("http://seat-2:9403")
        );
        assert_eq!(options.node, "tgd-3");
        assert_eq!(options.data_dir, Path::new("/srv/tg"));
        assert!(options.init);
        assert_eq!(options.init_voters.as_deref(), Some(&[1, 3][..]));
        assert_eq!(options.timing.heartbeat_ms, 200);
        assert_eq!(options.timing.election_min_ms, 600);
        assert_eq!(options.timing.election_max_ms, 1200);
        assert_eq!(options.snapshots.every_logs, 5_000);
        assert_eq!(options.snapshots.keep_logs, 2_000);
        assert_eq!(options.audit_rotate, Some(50_000));
        // ADR-0137: the one-shot mode and its range.
        assert!(options.audit_export);
        assert_eq!(options.audit_from, Some(7));
        assert_eq!(options.audit_to, Some(9));
        assert_eq!(options.audit_anchor.as_deref(), Some("4711"));
        assert_eq!(options.trust_domain, "acme.internal");
        assert_eq!(options.peers.entries().len(), 2);
        assert_eq!(options.peers.get(3), Some("http://c:3"));

        // The counter-direction: **none** of these values is the default.
        let plain = parse(&["--peer", "1=http://a:1"]).expect("valid");
        assert!(plain.operator_listen.is_none(), "the operator port is off");
        assert!(plain.signer_listen.is_none(), "the signer port is off");
        assert!(plain.signers.is_empty());
        assert!(!plain.init);
        assert!(plain.init_voters.is_none());
        // The default is **not** `None`: 100 000 records per segment, and `0`
        // would mean never rotate (ADR-0020).
        assert_eq!(plain.audit_rotate, Some(100_000));
        assert_eq!(plain.trust_domain, tg_identity::DEFAULT_TRUST_DOMAIN);
    }

    #[test]
    fn every_parsed_option_has_a_witness() {
        let source = include_str!("options.rs");
        let cut = source
            .find("#[cfg(test)]")
            .expect("the source has a test module");
        let tests = &source[cut..];

        let missing: Vec<&str> = parsed_options()
            .into_iter()
            .filter(|flag| !tests.contains(flag))
            .collect();
        assert!(
            missing.is_empty(),
            "these settings are parsed and named by no test: {missing:?}"
        );
    }

    fn parsed_options() -> Vec<&'static str> {
        let source = include_str!("options.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap_or(source.len())];

        let mut flags: Vec<&str> = production
            .match_indices("\"--")
            .filter_map(|(at, _)| {
                let rest = &production[at + 1..];
                let end = rest.find('"')?;
                let flag = &rest[..end];
                (flag.len() > 2
                    && flag[2..]
                        .chars()
                        .all(|c| c.is_ascii_lowercase() || c == '-'))
                .then_some(flag)
            })
            .collect();
        flags.sort_unstable();
        flags.dedup();

        // Without this assurance **both** callers would be green too if the search
        // found nothing -- and precisely then they check nothing.
        assert!(
            flags.len() > 15,
            "only {} settings were found -- the cut is wrong",
            flags.len()
        );
        flags
    }

    #[test]
    fn a_node_missing_from_its_own_peer_list_is_rejected() {
        let err = parse(&["--id", "2", "--peer", "1=http://a:1"]).expect_err("must fail");

        assert!(err.contains("own node 2"), "{err}");
    }

    #[test]
    fn a_call_without_peers_is_rejected() {
        assert!(parse(&["--id", "1"]).is_err());
    }

    #[test]
    fn an_unknown_option_aborts() {
        let err = parse(&["--peer", "1=http://a:1", "--whatever"]).expect_err("fails");

        assert!(err.contains("--whatever"), "{err}");
    }

    #[test]
    fn a_dangling_flag_aborts() {
        for flag in ["--id", "--listen", "--peer", "--data-dir", "--heartbeat-ms"] {
            let err = parse(&["--peer", "1=http://a:1", flag]).expect_err("fails");
            assert!(err.contains("needs a value"), "{flag}: {err}");
        }
    }

    #[test]
    fn unusable_values_are_named() {
        let err = parse(&["--peer", "1=http://a:1", "--id", "one"]).expect_err("fails");
        assert!(err.contains("no number"), "{err}");

        let err = parse(&["--peer", "1=http://a:1", "--listen", "no:port"]).expect_err("fails");
        assert!(err.contains("--listen"), "{err}");

        let err = parse(&["--peer", "one=http://a:1"]).expect_err("fails");
        assert!(err.contains("no number"), "{err}");

        let err = parse(&["--peer", "http://a:1"]).expect_err("fails");
        assert!(err.contains("expected <n>=<url>"), "{err}");
    }

    #[test]
    fn only_the_first_equals_sign_separates() {
        let options = parse(&["--peer", "1=http://a:1/?x=y"]).expect("valid");

        assert_eq!(options.peers.get(1), Some("http://a:1/?x=y"));
    }

    #[test]
    fn the_usage_text_lists_every_option() {
        let help = super::usage();
        for flag in parsed_options() {
            assert!(
                tg_telemetry::args::mentions_word(&help, flag),
                "{flag} is missing from the overview"
            );
        }
    }

    #[test]
    fn the_usage_text_names_how_the_ports_are_secured() {
        let usage = super::usage();

        assert!(usage.contains("client certificate"), "{usage}");
        assert!(usage.contains("peers/"), "{usage}");
        assert!(usage.contains("Unix socket"), "{usage}");
        assert!(
            !usage.contains("phase 7"),
            "the outdated note stands there again"
        );
    }

    #[test]
    fn the_composed_usage_carries_all_three_parts() {
        let usage = super::usage();

        assert!(usage.contains("--peer"), "the head is missing");
        assert!(
            usage.contains("--telemetry-addr"),
            "the telemetry is missing"
        );
        assert!(usage.contains("this overview"), "the end is missing");
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::{Options, Snapshots, Timing};

    #[test]
    fn the_defaults_are_openrafts_own() {
        let snapshots = Snapshots::default();

        assert_eq!(snapshots.every_logs, 5_000);
        assert_eq!(snapshots.keep_logs, 1_000);

        let config = Timing::default().to_config(snapshots).expect("valid");
        assert_eq!(config.max_in_snapshot_log_to_keep, 1_000);
        assert!(matches!(
            config.snapshot_policy,
            openraft::SnapshotPolicy::LogsSinceLast(5_000)
        ));
    }

    #[test]
    fn a_snapshot_distance_of_zero_is_rejected() {
        let snapshots = Snapshots {
            every_logs: 0,
            keep_logs: 1_000,
        };

        let err = Timing::default()
            .to_config(snapshots)
            .expect_err("zero must not get through");
        assert!(err.contains("snapshot"), "{err}");
    }

    #[test]
    fn keeping_no_logs_is_allowed_but_never_the_default() {
        let snapshots = Snapshots {
            every_logs: 100,
            keep_logs: 0,
        };

        let config = Timing::default().to_config(snapshots).expect("valid");
        assert_eq!(config.max_in_snapshot_log_to_keep, 0);
        assert_ne!(Snapshots::default().keep_logs, 0);
    }

    #[test]
    fn the_snapshot_options_are_read_from_the_call() {
        let args: Vec<String> = [
            "--peer",
            "1=http://a:1",
            "--snapshot-every",
            "64",
            "--keep-logs",
            "8",
        ]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();

        let options = Options::parse(&args).expect("valid");

        assert_eq!(options.snapshots.every_logs, 64);
        assert_eq!(options.snapshots.keep_logs, 8);
    }

    #[test]
    fn the_usage_text_names_the_compaction_switches() {
        let usage = super::usage();

        assert!(usage.contains("--snapshot-every"));
        assert!(usage.contains("--keep-logs"));
    }
}

#[cfg(test)]
mod membership_tests {
    use super::Options;

    fn parse(args: &[&str]) -> Result<Options, String> {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        Options::parse(&args)
    }

    #[test]
    fn without_the_flag_every_peer_is_a_voter() {
        let options = parse(&["--peer", "1=http://a:1", "--peer", "2=http://b:2"]).expect("valid");

        assert!(options.init_voters.is_none());
    }

    #[test]
    fn the_flag_narrows_the_initial_membership() {
        let options = parse(&[
            "--init",
            "--peer",
            "1=http://a:1",
            "--peer",
            "2=http://b:2",
            "--peer",
            "3=http://c:3",
            "--init-voters",
            "1,2",
        ])
        .expect("valid");

        assert_eq!(options.init_voters, Some(vec![1, 2]));
    }

    #[test]
    fn spaces_around_the_ids_are_tolerated() {
        let options = parse(&[
            "--init",
            "--peer",
            "1=http://a:1",
            "--peer",
            "2=http://b:2",
            "--init-voters",
            "1, 2",
        ])
        .expect("valid");

        assert_eq!(options.init_voters, Some(vec![1, 2]));
    }

    #[test]
    fn a_voter_without_an_address_is_rejected() {
        let err = parse(&["--init", "--peer", "1=http://a:1", "--init-voters", "1,2"])
            .expect_err("must fail");

        assert!(err.contains("node 2"), "{err}");
        assert!(err.contains("--peer"), "{err}");
    }

    #[test]
    fn the_voter_list_needs_the_initialisation() {
        let err = parse(&["--peer", "1=http://a:1", "--init-voters", "1"]).expect_err("must fail");

        assert!(err.contains("--init-voters"), "{err}");
        assert!(err.contains("--init"), "{err}");
    }

    #[test]
    fn with_the_initialisation_the_list_is_fine() {
        let options =
            parse(&["--init", "--peer", "1=http://a:1", "--init-voters", "1"]).expect("valid");

        assert_eq!(options.init_voters, Some(vec![1]));
    }

    #[test]
    fn an_unusable_voter_list_is_named() {
        let err = parse(&["--peer", "1=http://a:1", "--init-voters", "one"]).expect_err("fails");
        assert!(err.contains("no number"), "{err}");

        let err = parse(&["--peer", "1=http://a:1", "--init-voters", ""]).expect_err("fails");
        assert!(err.contains("--init-voters"), "{err}");
    }

    #[test]
    fn the_usage_text_lists_the_flag() {
        assert!(super::USAGE.contains("--init-voters"));
    }
}
