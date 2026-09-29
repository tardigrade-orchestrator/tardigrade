//! Dev tasks for the Tardigrade workspace.
//!
//! ADR-0023. The task `ci` runs the Definition of Done from CLAUDE.md and is
//! thereby the only place a CI system has to call — which one stays open
//! (provider-neutral).

#![forbid(unsafe_code)]

mod codegen;
mod identity;
mod image;
mod leftovers;
mod proto;
mod release;
mod sbom;
mod threshold;

use std::env;
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use tg_dst::evidence::Report;

const USAGE: &str = "\
xtask — dev tasks for the Tardigrade workspace

Calls:
  cargo xtask ci        the complete Definition of Done (codegen --check,
                        fmt, clippy, test, deny, sbom --check)
  cargo xtask codegen   regenerate XSD -> crates/tg-defs/src/generated.rs
  cargo xtask codegen --check
                        check that the generated code matches the XSD
  cargo xtask proto     regenerate workload.proto ->
                        crates/tg-identity/src/workload_api/pb.rs
                        (ADR-0035; without protoc, via protox)
  cargo xtask proto --check
                        check that the server stub matches the .proto
  cargo xtask sbom      rewrite docs/sbom.cdx.json — the bill of materials of
                        what is shipped (ADR-0134, CycloneDX)
  cargo xtask sbom --check
                        check that it still matches the tree
  cargo xtask release   build the four delivery units reproducibly (ADR-0138):
                        remap CARGO_HOME to /cargo, then the counter-check and
                        the digests. Runs **release** and therefore not in the
                        gate.
  cargo xtask image     build the sidecar image into the local content store
                        (--data-dir <path>, --reference <ref>) -- ADR-0059
  cargo xtask identity [--data-dir <path>] [--hours <n>]
                        produce dev identity material (root + agent
                        intermediate, Ed25519) — for a local run, not for a
                        cluster
  cargo xtask dst       deterministic simulation tests, broad seed sweep
                        --report <path> writes the evidence per ADR-0020
                        (plus <path>.jsonl as a checkable segment)
                        (seed, scenario, verdict, sealed)
                        (ADR-0005, ADR-0032; scope via TG_DST_SEEDS)
  cargo xtask attest    attestation at the socket: the separation (ADR-0081).
                        Demands a working OCI runtime and therefore does not
                        run in the normal suite.
  cargo xtask net       kernel path and resolver against real namespaces, veth,
                        bridge, nft and foreign DNS clients (ADR-0012,
                        ADR-0013, ADR-0038). Demands CAP_NET_ADMIN,
                        CAP_SYS_ADMIN and bind-utils; therefore not in the
                        normal suite.
  cargo xtask storage   storage and egress path: real loop devices, `mkfs`,
                        mounts (ADR-0027), `curl` through the egress sidecar
                        (ADR-0041) and the requirement edge on real containers
                        (ADR-0061). Demands CAP_SYS_ADMIN, util-linux,
                        e2fsprogs, curl and an OCI runtime.
  cargo xtask bench     tail latency of the data plane (ADR-0022):
                        work-stealing against thread-per-core, with and
                        without pinning. Runs **release** — in the debug
                        profile one measures `rustls` being unoptimized, not
                        the runtime.
  cargo xtask fmt       format the code (writing, not checking)
  cargo xtask help      this overview
";

#[derive(Debug)]
enum TaskError {
    /// A called tool was missing or could not be started.
    Spawn {
        program: String,
        source: std::io::Error,
    },
    /// A called tool ran but ended with an error status.
    Failed {
        step: String,
    },
    /// The XSD codegen failed.
    Codegen {
        detail: String,
    },
    /// Generated code and XSD have diverged.
    CodegenDrift,
    /// Building the sidecar image failed.
    Image {
        detail: String,
    },
    /// Producing identity material failed.
    Identity {
        detail: String,
    },
    /// The protobuf codegen failed.
    Proto {
        detail: String,
    },
    /// An artifact could not be written.
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    /// Server stub and `.proto` have diverged.
    ProtoDrift,
    /// Unknown subcommand.
    Usage {
        got: String,
    },
    /// A privileged run left kernel resources behind.
    Leftovers {
        detail: String,
    },
    Io(std::io::Error),
}

impl fmt::Display for TaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn { program, source } => {
                write!(f, "'{program}' could not be started: {source}")
            }
            Self::Failed { step } => write!(f, "step '{step}' failed"),
            Self::Codegen { detail } => write!(f, "XSD codegen failed: {detail}"),
            Self::Image { detail } => write!(f, "sidecar image: {detail}"),
            Self::CodegenDrift => write!(
                f,
                "the generated code no longer matches the XSD.\n  \
                 crates/tg-defs/src/generated.rs is stale against schema/workload.xsd.\n  \
                 Fix with: cargo xtask codegen"
            ),
            Self::Identity { detail } => {
                write!(f, "identity material not producible: {detail}")
            }
            Self::Proto { detail } => write!(f, "protobuf codegen failed: {detail}"),
            Self::Write { path, source } => {
                write!(f, "{} not writable: {source}", path.display())
            }
            Self::ProtoDrift => write!(
                f,
                "the server stub no longer matches third-party/spiffe-workload-api/\
                 workload.proto — run `cargo xtask proto` and check the result in \
                 (ADR-0035)"
            ),
            Self::Usage { got } => write!(f, "unknown task '{got}'\n\n{USAGE}"),
            Self::Leftovers { detail } => write!(f, "{detail}"),
            Self::Io(source) => write!(f, "file access failed: {source}"),
        }
    }
}

impl std::error::Error for TaskError {}

impl From<std::io::Error> for TaskError {
    fn from(source: std::io::Error) -> Self {
        Self::Io(source)
    }
}

fn main() -> ExitCode {
    let task = env::args().nth(1).unwrap_or_else(|| "ci".to_owned());

    if matches!(task.as_str(), "help" | "-h" | "--help") {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    match dispatch(&task) {
        Ok(()) => {
            eprintln!("\nxtask: '{task}' succeeded.");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("\nxtask: {err}");
            ExitCode::FAILURE
        }
    }
}

/// The path behind `--report`, if one was given.
///
/// Without it `dst` runs the sweep and passes its output through; with it the
/// artifact per ADR-0020 arises.
fn report_argument() -> Option<String> {
    let args: Vec<String> = env::args().collect();
    args.iter()
        .position(|arg| arg == "--report")
        .and_then(|at| args.get(at + 1))
        .cloned()
}

/// Whether a flag stands in the command line.
fn has_flag(flag: &str) -> bool {
    env::args().any(|arg| arg == flag)
}

fn dispatch(task: &str) -> Result<(), TaskError> {
    let root = workspace_root();

    match task {
        "ci" => ci(&root),
        "codegen" => {
            let check = env::args().any(|a| a == "--check");
            codegen::run(&root, check)
        }
        "proto" => {
            let check = env::args().any(|a| a == "--check");
            proto::run(&root, check)
        }
        "release" => release::run(&root),
        "image" => {
            let args: Vec<String> = env::args().collect();
            let value = |flag: &str| {
                args.iter()
                    .position(|arg| arg == flag)
                    .and_then(|at| args.get(at + 1))
                    .cloned()
            };
            let data_dir = value("--data-dir")
                .map_or_else(|| root.join("target/xtask-image"), std::path::PathBuf::from);
            let reference = value("--reference");
            image::run(
                &root,
                &data_dir,
                reference.as_deref().unwrap_or(image::DEFAULT_REFERENCE),
            )
        }
        "identity" => {
            let args: Vec<String> = env::args().collect();
            let value = |flag: &str| {
                args.iter()
                    .position(|arg| arg == flag)
                    .and_then(|at| args.get(at + 1))
                    .cloned()
            };
            let data_dir = value("--data-dir")
                .map_or_else(|| root.join("target").join("dev-node"), PathBuf::from);
            let hours = value("--hours")
                .and_then(|raw| raw.parse().ok())
                .unwrap_or_else(identity::default_hours);

            identity::run(&data_dir, hours)
        }
        "threshold" => {
            let args: Vec<String> = env::args().collect();
            let root = args
                .iter()
                .position(|arg| arg == "--out")
                .and_then(|at| args.get(at + 1))
                .map_or_else(|| root.join("target").join("dev-group"), PathBuf::from);

            // **The trust domain is a setting**, with the constant as the
            // default (ADR-0006). It goes into the group's CA certificate; hard
            // coded, every ceremony carried `cluster.local`.
            let domain = args
                .iter()
                .position(|arg| arg == "--domain")
                .and_then(|at| args.get(at + 1))
                .map_or_else(
                    || tg_identity::DEFAULT_TRUST_DOMAIN.to_owned(),
                    String::clone,
                );

            threshold::run(&root, &domain)
        }
        "sbom" => sbom::run(&root, has_flag("--check")),
        "attest" => attest(),
        "net" => net(),
        "storage" => storage(),
        "dst" => dst(report_argument().as_deref()),
        "bench" => bench(),
        "fmt" => run("cargo", &["fmt", "--all"], "fmt"),
        other => Err(TaskError::Usage {
            got: other.to_owned(),
        }),
    }
}

/// The Definition of Done from CLAUDE.md, in this order.
///
/// The unsafe guard-rail check no longer lies here: it existed **twice**, and
/// the two versions disagreed about the scope. What stayed is the one that runs
/// in `cargo test --workspace` (`crates/tg-syscall/tests/invariants.rs`).
fn ci(root: &Path) -> Result<(), TaskError> {
    codegen::run(root, true)?;
    proto::run(root, true)?;
    run("cargo", &["fmt", "--all", "--check"], "cargo fmt --check")?;
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
        "cargo clippy",
    )?;
    run("cargo", &["test", "--workspace", "--locked"], "cargo test")?;
    // The doc references fire only at `cargo doc`, i.e. not in
    // `cargo test --workspace` -- what does not run in the gate does not run.
    run(
        "cargo",
        &["doc", "--workspace", "--no-deps", "--locked"],
        "cargo doc",
    )?;
    run("cargo", &["deny", "check"], "cargo deny check")?;
    // The bill of materials belongs in the gate (ADR-0134, determination 5): a
    // dependency that is added shall stand in a pull request's diff.
    sbom::run(root, true)
}

/// Runs the DST suite with a broad seed sweep.
///
/// `cargo test` runs the scenarios with few seeds — they belong to the
/// Definition of Done and must not draw it out. The broad sweep is an action of
/// its own: it searches for the seed that tips the suite, and it is at the same
/// time the place at which the evidence per ADR-0020 arises. The scope comes
/// from `TG_DST_SEEDS`; a single reported failure is reproduced with
/// `TG_DST_SEED=<n> cargo test -p tg-dst`.
fn dst(report_to: Option<&str>) -> Result<(), TaskError> {
    let seeds = env::var("TG_DST_SEEDS").unwrap_or_else(|_| "32".to_owned());
    eprintln!("xtask: DST sweep over {seeds} seed(s) per scenario.");

    // Passed as the child process's environment. `std::env::set_var` would be
    // shorter but is `unsafe` in edition 2024 — excluded per invariant 2.
    let mut command = Command::new("cargo");
    command
        .args(["test", "-p", "tg-dst", "--locked"])
        .env("TG_DST_SEEDS", &seeds);

    // Without a report the output passes through — a sweep takes time, and a
    // mute run looks like a hanging one. With a report it is collected and
    // printed **afterwards**: it is the source of the artifact.
    let Some(path) = report_to else {
        let status = command.status().map_err(|source| TaskError::Spawn {
            program: "cargo".to_owned(),
            source,
        })?;
        return if status.success() {
            Ok(())
        } else {
            Err(TaskError::Failed {
                step: "cargo xtask dst".to_owned(),
            })
        };
    };

    // **One call per test target**, and that is the answer to a measured error.
    // The first draft ran all targets in one call and read the provenance from
    // cargo's `Running` lines. Those stand on **stderr** while `libtest` writes
    // its results to **stdout**: concatenated, all provenance lines come after
    // all results, and the mapping is destroyed. The report then announced
    // "0 resilience scenarios" with 65 checks — and looked proper doing so.
    let targets = test_targets(&workspace_root().join("tests/dst/tests"));
    let mut collected = String::new();
    let mut ok = true;

    for target in &targets {
        let mut per_target = Command::new("cargo");
        per_target
            .args(["test", "-p", "tg-dst", "--locked"])
            .env("TG_DST_SEEDS", &seeds);
        if target == "lib" {
            per_target.arg("--lib");
        } else {
            per_target.args(["--test", target]);
        }
        // `--test-threads=1` makes the output stable. The report sorts anyway;
        // what has to be stable is the **output** an auditor keeps beside it.
        per_target.args(["--", "--test-threads=1"]);

        let output = per_target.output().map_err(|source| TaskError::Spawn {
            program: "cargo".to_owned(),
            source,
        })?;
        ok &= output.status.success();

        // The provenance line is **prepended**, not read: it is a fact of this
        // call.
        let _ = writeln!(collected, "     Running tests/{target}.rs");
        collected.push_str(&String::from_utf8_lossy(&output.stdout));
        // stderr passes through so that a compile error stays visible — but
        // **not** into the parsed text: there it would stand behind the results
        // and shift the mapping.
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    let report = Report::parse(&collected, &seed_values(&seeds));
    fs::write(path, report.render()).map_err(|source| TaskError::Write {
        path: PathBuf::from(path),
        source,
    })?;

    // **Two files, and the second is the checkable one.** The rendered report is
    // for humans; the segment beside it is the same format as the audit archive
    // and is recomputed by `tgctl audit` — without a second procedure (11c).
    let segment_path = format!("{path}.jsonl");
    fs::write(&segment_path, report.to_jsonl()).map_err(|source| TaskError::Write {
        path: PathBuf::from(&segment_path),
        source,
    })?;

    eprintln!(
        "xtask: evidence written to {path}, segment to {segment_path} — \
         {} resilience scenarios, {} checks.",
        report.resilience_scenarios(),
        report.scenarios.len()
    );

    // **The report arises on a failure too** — then it is all the more what an
    // auditor wants to see. The error is nevertheless passed through: a red run
    // must not end green just because an artifact arose.
    if ok && report.is_clean() {
        Ok(())
    } else {
        Err(TaskError::Failed {
            step: "cargo xtask dst".to_owned(),
        })
    }
}

/// The test targets of `tg-dst`, read from the directory.
///
/// From the file system and not from `cargo metadata`: the targets **are** the
/// files in `tests/`. The library comes along as `lib`, because its unit tests
/// are checks too. Sorted, so that a report arises the same way twice.
fn test_targets(dir: &Path) -> Vec<String> {
    let mut targets: Vec<String> = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension()? == "rs")
                .then(|| path.file_stem()?.to_str().map(str::to_owned))
                .flatten()
        })
        .collect();
    targets.sort();
    targets.push("lib".to_owned());
    targets
}

/// The seeds `tg_dst::seeds` derives from the same setting.
///
/// Recomputed and not read from the run: the test process prints them nowhere,
/// and making it do so would turn the output into a handover format. The same
/// computation in two places is defensible here, because the alternative would
/// be a protocol.
fn seed_values(seeds: &str) -> Vec<u64> {
    if let Ok(single) = env::var("TG_DST_SEED")
        && let Ok(parsed) = single.parse()
    {
        return vec![parsed];
    }

    let count: u64 = seeds.parse().unwrap_or(2);
    (0..count.max(1))
        .map(|index| 0x5EED_0000_0000_0000 ^ index.wrapping_mul(0x9E37_79B9_7F4A_7C15))
        .collect()
}

/// Checks what a privileged run left behind.
///
/// A gate and not a note: this session cleared such leftovers away **four
/// times** by hand, and twice only the full disk pointed at them. The rationale
/// stands in [`leftovers`].
fn guard(task: &str, before: &std::collections::BTreeSet<String>) -> Result<(), TaskError> {
    let new = leftovers::since(before);
    if new.is_empty() {
        return Ok(());
    }
    Err(TaskError::Leftovers {
        detail: leftovers::report(task, &new),
    })
}

/// Runs the attestation against a real container (ADR-0006, phase 7a).
///
/// The test behind it is `#[ignore]` because it demands **privileges** — the
/// same boundary as `cargo xtask net` and `cargo xtask storage`.
fn attest() -> Result<(), TaskError> {
    // The name stayed, the object changed (ADR-0081): the attestation needs no
    // container any more, because the **socket** is it. What runs privileged
    // here is the separation — that the host path does not yield a socket while
    // the bind mount does.
    eprintln!(
        "xtask: attestation at the socket — the separation by the directory (demands mount)."
    );
    build_workspace()?;
    let before = leftovers::snapshot();

    run(
        "cargo",
        &[
            "test",
            "-p",
            "tg-identity",
            "--test",
            "attestation",
            "--",
            "--ignored",
            "--nocapture",
        ],
        "cargo xtask attest",
    )?;

    guard("cargo xtask attest", &before)
}

/// Runs the kernel path from phase 9b (ADR-0012, ADR-0038).
///
/// These tests create real namespaces, span veth pairs into a real bridge, let
/// `nft` apply a real rule set, let `dig`, `host` and **glibc** query the
/// resolver from phase 9c, send packets through a real `WireGuard` tunnel
/// (phase 9d), start a real container in a prepared namespace and run `tgd` and
/// `tg-agent` as processes. Demanded are `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`,
/// `bind-utils`, an OCI runtime and the `WireGuard` kernel module.
///
/// They clear up after themselves. What **stays** is the bridge `tg0`, the
/// underlay interface `tgwg0` with its routes, the table `inet tardigrade` and
/// `net.ipv4.ip_forward = 1` — the same state a running agent leaves behind.
fn net() -> Result<(), TaskError> {
    eprintln!(
        "xtask: kernel path against real namespaces (demands CAP_NET_ADMIN and CAP_SYS_ADMIN)."
    );
    build_workspace()?;

    // **The sidecar image before the tests**, for the same reason as at
    // `storage`: `mesh_container` starts two containers with the real
    // `tg-proxy`, and a `cargo run` from inside a test waited for the lock on
    // the target directory that `cargo test` itself holds.
    let root = workspace_root();
    image::run(
        &root,
        &root.join("target/xtask-image"),
        image::DEFAULT_REFERENCE,
    )?;

    let before = leftovers::snapshot();

    for (package, test) in [
        ("tg-syscall", "netns"),
        ("tg-net", "kernel_path"),
        // ADR-0094: the original destination of a UDP datagram. It stands here
        // because it needs `nft` and a namespace.
        ("tg-proxy", "quic_origdst"),
        // And the path on it: container -> redirect -> sidecar -> endpoint.
        ("tg-proxy", "quic_path"),
        // ADR-0130: the deadline sweeps even without a datagram. It needs
        // **no** privileges but time -- a full deadline, around 60 s.
        ("tg-proxy", "quic_sweep"),
        // ADR-0012: a real container in a real namespace. It stands here and
        // not at `storage`, because it needs a bridge and veth.
        ("tg-runtime", "network_path"),
        // ADR-0059: the sidecar arises, runs and shares its workload's
        // namespace. The same preconditions as `network_path`.
        ("tg-runtime", "sidecar_path"),
        ("tg-net", "dns_interop"),
        ("tg-net", "underlay_path"),
        // The path this system actually builds: a container on node A reaches a
        // container on node B. Four namespaces, a real tunnel — and the test
        // that found the missing rule in the node's rule set
        // (`iifname tgwg0 oifname tg0 accept`).
        ("tg-net", "two_nodes"),
        // Two **real** sidecar containers and mTLS between them: the path that
        // was substantiated at every place individually and never together.
        ("tg-identity", "mesh_container"),
        ("tg-agent", "node_network"),
        // **The operations manual's path in one piece**: a real `tgd`, a real
        // `tg-agent`, a real container. Measured, **every** test with a real
        // `tgd` used a runtime dummy until here, and every test with a real
        // container called `reconcile::once` directly.
        ("tg-agent", "cluster_container"),
        // ADR-0051: egress behind a **real** redirect. It stands here and not at
        // `storage`, because it needs `CAP_NET_ADMIN` and a namespace.
        ("tg-proxy", "egress_netns"),
        // ADR-0060: the mesh behind a real redirect. The same preconditions as
        // `egress_netns`, only that mTLS arises here.
        ("tg-proxy", "mesh_netns"),
        // ADR-0039: the connection of the underlay. It creates `tgwg0` on the
        // host and demands the WireGuard module.
        ("tg-agent", "session"),
    ] {
        run(
            "cargo",
            &[
                "test",
                "-p",
                package,
                "--test",
                test,
                "--",
                "--ignored",
                // The tests share bridge, table and address range. Concurrently
                // they cleared each other's namespaces away.
                "--test-threads=1",
                "--nocapture",
            ],
            "cargo xtask net",
        )?;
    }

    guard("cargo xtask net", &before)
}

/// Runs the privileged paths **without a network**: storage and egress from
/// phase 10 (ADR-0027, ADR-0041), the whiteouts (ADR-0052) and the requirement
/// edge (ADR-0061).
///
/// These tests create real images, run `mkfs.ext4` on them, mount them over a
/// loop device and grow them. That demands `CAP_SYS_ADMIN` and the programs from
/// `util-linux` and `e2fsprogs`. What an aborted run leaves behind is an
/// occupied loop device — `losetup -D` clears it away.
fn storage() -> Result<(), TaskError> {
    eprintln!(
        "xtask: local PV path, egress, whiteouts, secrets and the requirement \
         edge (demands CAP_SYS_ADMIN, CAP_MKNOD, losetup and mkfs)."
    );
    build_workspace()?;

    // **The sidecar image before the tests**, not inside one: a `cargo run` from
    // inside a test waited for the lock on the target directory that
    // `cargo test` itself holds — and a test that hangs is worse than one that
    // fails. `sidecar_image` reads it from `target/xtask-image`.
    let root = workspace_root();
    image::run(
        &root,
        &root.join("target/xtask-image"),
        image::DEFAULT_REFERENCE,
    )?;

    let before = leftovers::snapshot();

    // One file at a time and with `--test-threads=1`: two containers of the same
    // name claim the same cgroup (ADR-0006), and side by side the second fails
    // with `BrokenChannel` — measured in two of six runs.
    for (package, target) in [
        ("tg-runtime", "bundle_owner"),
        // **The effect of the seccomp profile** (ADR-0090): a probe that calls
        // `bpf(2)` with an invalid command — `EPERM` against `EINVAL`. Demands
        // `cc` in the PATH as well.
        ("tg-runtime", "seccomp_path"),
        // **The effect of the user namespace** (ADR-0091): a container with a
        // mapping that writes its rootfs, a file from the image (copy-up) and
        // its volume -- and on disk belongs to the range.
        ("tg-runtime", "userns_path"),
        // ADR-0059: the **real** `tg-proxy` in a container -- the only test that
        // touches the image, and the only one that shows it carries what the
        // program needs. Plus the whole identity chain over a real socket.
        //
        // It lies in `tg-identity` and not in `tg-runtime`: the chain is the
        // object, and `tg-runtime` must not know `tg-identity`.
        ("tg-identity", "sidecar_image"),
        // ADR-0081: **two** real containers, and each gets only its own
        // identity. That ADR's open point read "no witness over two
        // containers".
        ("tg-identity", "socket_isolation"),
        ("tg-runtime", "lease_path"),
        // ADR-0129: the self-fence stands before the reaping, and all unwanted
        // ones share one grace period. Time is measured, so it needs real
        // containers that ignore their `SIGTERM`.
        ("tg-runtime", "fence_before_reaping"),
        ("tg-runtime", "isolation_never_reaps"),
        // ADR-0070: a changed declaration does not reach a running container —
        // and that is reported. Needs a real container.
        ("tg-runtime", "spec_drift"),
        ("tg-runtime", "dependency_gate"),
        // ADR-0110: a **drained** node executes its tombstones nonetheless. It
        // needs no privileges, only an OCI runtime in the PATH.
        ("tg-runtime", "orders"),
        ("tg-proxy", "egress_path"),
        ("tg-runtime", "layers"),
        ("tg-runtime", "volumes"),
        // ADR-0099: the snapshot of a **mounted** volume carries the
        // application's state and not the disk's -- the promise for whose sake
        // the freeze exists. Measured without it: **zero** of 200 files.
        // Demands `fsfreeze` (util-linux) as well.
        ("tg-runtime", "snapshots"),
        // ADR-0098: the mount arrives in the container -- a real container that
        // reads its secrets and afterwards no longer has them.
        ("tg-runtime", "secrets_path"),
        // ADR-0017: and a **foreign user** really does not get into the store.
        // Until here the mode was checked and not the access -- `0700` is a
        // number, and that the kernel makes a lock out of it is shown only by a
        // `runuser -u nobody`.
        ("tg-runtime", "private_store"),
    ] {
        run(
            "cargo",
            &[
                "test",
                "-p",
                package,
                "--test",
                target,
                "--",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ],
            "cargo xtask storage",
        )?;
    }

    // **ADR-0118: the guard sees a leftover cgroup.** It creates one and clears
    // it away; in the normal suite it thereby changed the snapshot its
    // neighbours read concurrently.
    run(
        "cargo",
        &[
            "test",
            "-p",
            "xtask",
            "--bin",
            "xtask",
            "the_snapshot_sees_a_leftover_cgroup",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ],
        "cargo xtask storage",
    )?;

    // **ADR-0118: the consumption on a real cgroup.** It lies in the lib target
    // and not in `tests/`, because `report_consumption` is private. Demands root
    // (creating a cgroup) and nothing else.
    run(
        "cargo",
        &[
            "test",
            "-p",
            "tg-runtime",
            "--lib",
            "a_real_cgroup",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ],
        "cargo xtask storage",
    )?;

    // **The witnesses on a real tmpfs lie in the binary** (ADR-0098) and not in
    // an integration test: `SecretStore` is `pub(crate)`. `--bins` instead of
    // `--test`, otherwise they do not run.
    run(
        "cargo",
        &[
            "test",
            "-p",
            "tg-agent",
            "--bins",
            "secrets",
            "--",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ],
        "cargo xtask storage",
    )?;

    guard("cargo xtask storage", &before)
}

/// The measurement from ADR-0022 (`crates/tg-proxy/tests/tail_latency.rs`).
///
/// **`--release`, and that is half the job.** Measured: in the debug profile the
/// same round trip lies at around 250 µs median, in release at around 130 µs —
/// the difference between the variants at issue is smaller than that factor.
///
/// It stands in a run of its own because it loads the machine for some seconds
/// and its result depends on it.
fn bench() -> Result<(), TaskError> {
    eprintln!(
        "xtask: tail latency of the data plane (ADR-0022). The numbers hold for \
         **this** machine — load and echo service share it with the shards."
    );

    run(
        "cargo",
        &[
            "test",
            "--release",
            "-p",
            "tg-proxy",
            "--test",
            "tail_latency",
            "--",
            "--ignored",
            "--nocapture",
        ],
        "cargo xtask bench",
    )
}

/// Builds the whole workspace before a privileged suite runs.
///
/// These suites **start binaries**, and `cargo test -p X --test Y` builds only
/// that package's targets — whoever changes the control plane and then runs one
/// of these suites would check against the old one, and it would look perfectly
/// normal.
fn build_workspace() -> Result<(), TaskError> {
    run(
        "cargo",
        &["build", "--workspace", "--quiet"],
        "cargo build --workspace",
    )
}

fn run(program: &str, args: &[&str], step: &str) -> Result<(), TaskError> {
    eprintln!("--> {program} {}", args.join(" "));

    let status = Command::new(program)
        .args(args)
        .current_dir(workspace_root())
        .status()
        .map_err(|source| TaskError::Spawn {
            program: program.to_owned(),
            source,
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(TaskError::Failed {
            step: step.to_owned(),
        })
    }
}

/// Workspace root: the parent directory of the xtask manifest.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    /// **Every privileged test file is named by a task.**
    ///
    /// Because once it was not so:
    /// `crates/tg-runtime/tests/isolation_never_reaps.rs` checks the sharpest
    /// security statement from ADR-0062 and stood in no list. An `#[ignore]`
    /// test no task names runs in the Definition of Done **never**.
    ///
    /// Checked over the **file name** and not the arguments, because there are
    /// two forms: most tasks enumerate targets as `("crate", "file")`, `attest`
    /// writes its arguments flat. A guard that knows only the first form
    /// reported `attestation` as missing although it is run.
    #[test]
    fn every_privileged_test_file_is_named_by_a_task() {
        let root = super::workspace_root();
        let me = std::fs::read_to_string(root.join("xtask/src/main.rs")).expect("xtask readable");

        let mut checked = 0_usize;
        let mut findings = Vec::new();

        let crates = std::fs::read_dir(root.join("crates")).expect("crates readable");
        for krate in crates.filter_map(Result::ok) {
            let dir = krate.path().join("tests");
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.filter_map(Result::ok) {
                let path = entry.path();
                if path.extension().is_none_or(|ext| ext != "rs") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                if !text.contains("#[ignore") {
                    continue;
                }
                checked += 1;
                let stem = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .unwrap_or_default()
                    .to_owned();
                if !me.contains(&format!("\"{stem}\"")) {
                    findings.push(stem);
                }
            }
        }

        // A guard that has found nothing confirms everything.
        assert!(
            checked >= 15,
            "only {checked} privileged test files found — the search does not bite"
        );
        assert!(
            findings.is_empty(),
            "these test files carry `#[ignore]` and are named by no `xtask` \
             task — they never run in the Definition of Done: {findings:?}"
        );
    }

    /// **Every `#[ignore]` says why.**
    ///
    /// Measured 119 with a reason and **none** without. What a latch protects is
    /// the day somebody adds a bare `#[ignore]`: then the suite says "ignored"
    /// and nothing else, and a forgotten test is indistinguishable from a
    /// privileged one.
    ///
    /// The neighbour above checks the **wiring**, this one the **information**.
    #[test]
    fn every_ignore_carries_its_reason() {
        let root = super::workspace_root();
        let mut with_reason = 0_usize;
        let mut bare = Vec::new();

        let mut files = Vec::new();
        collect_rust(&root.join("crates"), &mut files);
        collect_rust(&root.join("xtask"), &mut files);

        for file in &files {
            let Ok(text) = std::fs::read_to_string(file) else {
                continue;
            };
            for (number, line) in text.lines().enumerate() {
                let t = line.trim_start();
                // Only the attribute itself — a comment mentioning `#[ignore]`
                // is no hit. Measured twelve such mentions in module headers.
                if t.starts_with("#[ignore = ") {
                    with_reason += 1;
                } else if t.starts_with("#[ignore]") {
                    bare.push(format!("{}:{}", file.display(), number + 1));
                }
            }
        }

        // Measured 119. A bound on the measured number would be the trap this
        // tree has already paid for once with a fuzz coverage assertion.
        assert!(
            with_reason >= 50,
            "only {with_reason} substantiated `#[ignore]` found — the search does not \
             bite, and without it this guard confirms everything"
        );
        assert!(
            bare.is_empty(),
            "these `#[ignore]` do not say why — the suite then says `ignored` \
             and nothing else: {bare:?}"
        );
    }

    /// Collects `.rs` files under a directory.
    fn collect_rust(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                collect_rust(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// **And every named test target exists.**
    ///
    /// The opposite direction of the guard above, and it catches a different
    /// error: a **renamed** test file falls out of the harness without anything
    /// turning red — `cargo test --test <name>` of a target that does not exist
    /// is one line of output in an `xtask` run and not a failure somebody reads.
    #[test]
    fn every_named_test_target_exists() {
        let root = super::workspace_root();
        let me = std::fs::read_to_string(root.join("xtask/src/main.rs")).expect("xtask readable");

        let mut checked = 0_usize;
        let mut findings = Vec::new();

        // The enumerations stand as `("tg-crate", "file")`.
        //
        // **Without comment lines** -- this line names the form by example, and
        // a text comparison over the whole file promptly found itself.
        for (at, line) in me.lines().enumerate() {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let Some(rest) = line.split_once("(\"tg-") else {
                continue;
            };
            let Some((krate, rest)) = rest.1.split_once("\",") else {
                continue;
            };
            let Some(file) = rest.split('"').nth(1) else {
                continue;
            };
            if file.is_empty() || file.contains('/') {
                continue;
            }
            checked += 1;
            let path = root.join(format!("crates/tg-{krate}/tests/{file}.rs"));
            if !path.exists() {
                findings.push(format!("main.rs:{}: tg-{krate}/tests/{file}.rs", at + 1));
            }
        }

        // A guard that has read nothing confirms everything.
        assert!(
            checked >= 20,
            "only {checked} named test targets read — the guard hardly read \
             anything"
        );
        assert!(
            findings.is_empty(),
            "the harness names these test targets and they do not exist: \
             {findings:?}"
        );
    }
}
