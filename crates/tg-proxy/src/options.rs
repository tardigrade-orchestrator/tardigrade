//! The sidecar's call options.
//!
//! They stand in the library and not in `main.rs` so that they are checkable:
//! the binary itself cannot be started outside a container -- its identity
//! comes over the workload API socket, and that rightly gives nothing to an
//! unattested process. What remains and can be checked is everything that is
//! decided **before** the first byte.
//!
//! # The settings come from the derived unit
//!
//! `tg_model::mesh` writes `--workload` and `--upstream-port` into the
//! sidecar's arguments when it derives it. So the sidecar need neither guess
//! nor look them up -- and both thereby stand in the Raft log and in the audit
//! trail instead of in an environment variable.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use tg_identity::SpiffeId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionsError {
    Missing {
        flag: &'static str,
    },
    Value {
        flag: &'static str,
        got: String,
        detail: String,
    },
}

impl fmt::Display for OptionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { flag } => write!(f, "{flag} is missing"),
            Self::Value { flag, got, detail } => {
                write!(f, "{flag}: '{got}' is unusable -- {detail}")
            }
        }
    }
}

impl std::error::Error for OptionsError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub workload: String,
    pub upstream_port: u16,
    pub socket: PathBuf,
    pub inbound: Option<SocketAddr>,
    pub routes: BTreeMap<String, SocketAddr>,
    pub policy: Option<PathBuf>,
    pub shards: Option<usize>,
    pub trust_domain: String,
    pub telemetry: tg_telemetry::args::Args,
    pub egress_listen: Option<SocketAddr>,
    pub egress: Option<PathBuf>,
    pub mesh_udp: Option<PathBuf>,
    pub mesh_udp_listen: Option<SocketAddr>,
    pub mesh_udp_upstream: Option<u16>,
    pub active_role: Option<PathBuf>,
    pub single_writer: bool,
    pub pin_shards: bool,
    pub mesh_listen: Option<SocketAddr>,
}

fn take_telemetry<'a>(
    telemetry: &mut tg_telemetry::args::Args,
    flag: &str,
    iter: &mut impl Iterator<Item = &'a String>,
) {
    let mut next = || -> Result<String, String> {
        iter.next()
            .cloned()
            .ok_or_else(|| format!("{flag} needs a value"))
    };

    if let Err(err) = telemetry.take(flag, &mut next) {
        eprintln!("tg-proxy: {err}");
    }
}

struct Collected {
    workload: Option<String>,
    upstream_port: Option<u16>,
    socket: Option<PathBuf>,
    inbound: Option<SocketAddr>,
    routes: BTreeMap<String, SocketAddr>,
    policy: Option<PathBuf>,
    shards: Option<usize>,
    trust_domain: String,
    telemetry: tg_telemetry::args::Args,
    egress_listen: Option<SocketAddr>,
    mesh_listen: Option<SocketAddr>,
    egress: Option<PathBuf>,
    mesh_udp: Option<PathBuf>,
    mesh_udp_listen: Option<SocketAddr>,
    mesh_udp_upstream: Option<u16>,
    active_role: Option<PathBuf>,
    single_writer: bool,
    pin_shards: bool,
}

impl Options {
    pub fn parse(args: &[String]) -> Result<Self, OptionsError> {
        let mut workload = None;
        let mut upstream_port = None;
        let mut socket = None;
        let mut inbound = None;
        let mut routes = BTreeMap::new();
        let mut policy = None;
        let mut shards = None;
        let mut trust_domain = String::from(tg_identity::DEFAULT_TRUST_DOMAIN);
        let mut telemetry = tg_telemetry::args::Args::with_port(7103);
        let mut egress_listen = None;
        let mut mesh_listen = None;
        let mut egress = None;
        let mut mesh_udp = None;
        let mut mesh_udp_listen = None;
        let mut mesh_udp_upstream = None;
        let mut active_role = None;
        let mut single_writer = false;
        let mut pin_shards = false;

        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--workload" => workload = iter.next().cloned(),
                // The two upstream ports in one arm -- the same thought as
                // with the paths and addresses below (ADR-0142).
                "--upstream-port" => {
                    let raw = iter.next().cloned().unwrap_or_default();
                    upstream_port = Some(parse_num("--upstream-port", &raw)?);
                }
                "--mesh-udp-upstream" => {
                    let raw = iter.next().cloned().unwrap_or_default();
                    mesh_udp_upstream = Some(parse_num("--mesh-udp-upstream", &raw)?);
                }
                "--route" => {
                    let raw = iter.next().cloned().unwrap_or_default();
                    let (peer, addr) = raw.split_once('=').ok_or_else(|| OptionsError::Value {
                        flag: "--route",
                        got: raw.clone(),
                        detail: "expected <peer>=<address>".to_owned(),
                    })?;
                    routes.insert(peer.to_owned(), parse_addr("--route", addr)?);
                }
                "--trust-domain" => {
                    if let Some(value) = iter.next() {
                        trust_domain.clone_from(value);
                    }
                }
                "--shards" => {
                    let raw = iter.next().cloned().unwrap_or_default();
                    shards = Some(parse_num("--shards", &raw)?);
                }
                "--socket" | "--policy" | "--egress" | "--mesh-udp" | "--active-role" => {
                    let path = iter.next().map(PathBuf::from);
                    match arg.as_str() {
                        "--socket" => socket = path,
                        "--policy" => policy = path,
                        "--egress" => egress = path,
                        "--mesh-udp" => mesh_udp = path,
                        _ => active_role = path,
                    }
                }
                "--listen" | "--egress-listen" | "--mesh-listen" | "--mesh-udp-listen" => {
                    let raw = iter.next().cloned().unwrap_or_default();
                    match arg.as_str() {
                        "--listen" => inbound = Some(parse_addr("--listen", &raw)?),
                        "--egress-listen" => {
                            egress_listen = Some(parse_addr("--egress-listen", &raw)?);
                        }
                        "--mesh-listen" => mesh_listen = Some(parse_addr("--mesh-listen", &raw)?),
                        _ => mesh_udp_listen = Some(parse_addr("--mesh-udp-listen", &raw)?),
                    }
                }
                "--single-writer" => single_writer = true,
                "--pin-shards" => pin_shards = true,
                other => take_telemetry(&mut telemetry, other, &mut iter),
            }
        }

        Self::assemble(Collected {
            workload,
            upstream_port,
            socket,
            inbound,
            routes,
            policy,
            shards,
            trust_domain,
            telemetry,
            egress_listen,
            mesh_listen,
            egress,
            mesh_udp,
            mesh_udp_listen,
            mesh_udp_upstream,
            active_role,
            single_writer,
            pin_shards,
        })
    }

    fn assemble(raw: Collected) -> Result<Self, OptionsError> {
        let Collected {
            workload,
            upstream_port,
            socket,
            inbound,
            routes,
            policy,
            shards,
            trust_domain,
            telemetry,
            egress_listen,
            mesh_listen,
            egress,
            mesh_udp,
            mesh_udp_listen,
            mesh_udp_upstream,
            active_role,
            single_writer,
            pin_shards,
        } = raw;

        // **The sidecar exports no spans** (ADR-0133, determination 2): the
        // data plane gets none (ADR-0022, ADR-0114), and its bootstrap runtime
        // is discarded once the identity is fetched -- a batch exporter would
        // hang on a dead reactor afterwards.
        //
        // Refused instead of ignored: a switch that does nothing is an
        // assurance that stands out only in the incident. And here instead of
        // at the telemetry setup, because the two cases belong apart -- an
        // argument error aborts, a failed telemetry setup is fail-soft
        // (ADR-0019).
        if let Some(endpoint) = telemetry.otlp.as_deref() {
            return Err(OptionsError::Value {
                flag: "--otlp-endpoint",
                got: endpoint.to_owned(),
                detail: "the sidecar exports no spans (ADR-0133)".to_owned(),
            });
        }

        Ok(Self {
            workload: workload.ok_or(OptionsError::Missing { flag: "--workload" })?,
            upstream_port: upstream_port.ok_or(OptionsError::Missing {
                flag: "--upstream-port",
            })?,
            socket: socket.ok_or(OptionsError::Missing { flag: "--socket" })?,
            inbound,
            routes,
            policy,
            shards,
            trust_domain,
            telemetry,
            egress_listen,
            egress,
            mesh_udp,
            mesh_udp_listen,
            mesh_udp_upstream,
            active_role,
            single_writer,
            pin_shards,
            mesh_listen,
        })
    }

    pub fn peer_id(&self, peer: &str) -> Result<SpiffeId, OptionsError> {
        let domain = tg_identity::TrustDomain::new(self.trust_domain.clone()).map_err(|err| {
            OptionsError::Value {
                flag: "--trust-domain",
                got: self.trust_domain.clone(),
                detail: err.to_string(),
            }
        })?;

        SpiffeId::for_workload(&domain, peer).map_err(|err| OptionsError::Value {
            flag: "--route",
            got: peer.to_owned(),
            detail: err.to_string(),
        })
    }
}

fn parse_num<T>(flag: &'static str, raw: &str) -> Result<T, OptionsError>
where
    T: std::str::FromStr<Err = std::num::ParseIntError>,
{
    raw.parse()
        .map_err(|err: std::num::ParseIntError| OptionsError::Value {
            flag,
            got: raw.to_owned(),
            detail: err.to_string(),
        })
}

fn parse_addr(flag: &'static str, raw: &str) -> Result<SocketAddr, OptionsError> {
    raw.parse()
        .map_err(|err: std::net::AddrParseError| OptionsError::Value {
            flag,
            got: raw.to_owned(),
            detail: err.to_string(),
        })
}

pub fn edges_from_text(text: &str) -> Result<Vec<(String, String)>, OptionsError> {
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        let (from, to) = line.split_once("->").ok_or_else(|| OptionsError::Value {
            flag: "--policy",
            got: line.to_owned(),
            detail: "expected 'source -> target'".to_owned(),
        })?;
        let (from, to) = (from.trim(), to.trim());
        if from.is_empty() || to.is_empty() {
            return Err(OptionsError::Value {
                flag: "--policy",
                got: line.to_owned(),
                detail: "expected 'source -> target'".to_owned(),
            });
        }

        out.push((from.to_owned(), to.to_owned()));
    }

    Ok(out)
}

pub fn egress_from_text(
    text: &str,
    workload: &str,
) -> Result<Vec<crate::egress::Permission>, OptionsError> {
    let mut out = Vec::new();

    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        // `<workload> <name> <port> [<transport>]` -- the same line-by-line
        // format as with the edges, for the same reason: the agent writes the
        // file from the slice (ADR-0040), it is re-read in operation, and in
        // case of doubt an operator must be able to understand it with `cat`.
        //
        // The fourth word is **optional**, and that is no leniency: a line
        // without it stems from the time before ADR-0092 and meant `tcp` --
        // the same default as at the log entry and for the same reason.
        let mut fields = line.split_whitespace();
        let (Some(owner), Some(host), Some(port), transport, None) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            return Err(OptionsError::Value {
                flag: "--egress",
                got: line.to_owned(),
                detail: "expected 'workload name port [transport]'".to_owned(),
            });
        };

        // **Only its own.** The slice carries only the targets of this
        // node's workloads anyway (ADR-0041), but several run on one node --
        // and where the neighbour phones is none of this sidecar's business.
        if owner != workload {
            continue;
        }

        let port = port.parse().map_err(|_| OptionsError::Value {
            flag: "--egress",
            got: port.to_owned(),
            detail: "expected a port".to_owned(),
        })?;

        // **An unknown transport is an error, no default.** Whoever quietly
        // pulled it to `tcp` would make a permission out of a line the sidecar
        // does not understand -- and a skew between agent and sidecar would
        // thereby be fail-open instead of fail-closed.
        let transport = match transport {
            Some(word) => {
                crate::egress::Transport::parse(word).ok_or_else(|| OptionsError::Value {
                    flag: "--egress",
                    got: word.to_owned(),
                    detail: "expected 'tcp' or 'quic'".to_owned(),
                })?
            }
            None => crate::egress::Transport::Tcp,
        };

        out.push((host.to_owned(), port, transport));
    }

    Ok(out)
}
