//! `tgctl signer repair` — restoring a lost share (ADR-0108).
//!
//! **A verb group of its own**, for the same reason for which `cluster` is
//! separate from `apply`: two targets, two verbs. Here it is a third target —
//! the signing group is **decoupled** from consensus (ADR-0014,
//! determination 1), the seat and the Raft identifier are independent
//! (ADR-0097), and this command reaches **no** admin socket: it dials the
//! helpers' signer ports and puts material down. Under `cluster` it would be a
//! verb that works without a cluster.
//!
//! It runs on the node of the **affected** seat — the same role as
//! `cargo xtask threshold` at the ceremony (determination 7): `tgd` does not
//! start without a share, so the process cannot repair itself.

use std::path::Path;

pub(crate) fn command(
    args: &[String],
    data_dir: &Path,
    domain: &str,
    runtime: &tokio::runtime::Handle,
) -> Result<(), String> {
    const USE: &str = "expected: tgctl signer repair <seat> --helper <n>=<url> [--helper …]";

    match args.first().map(String::as_str) {
        Some("repair") => repair(&args[1..], data_dir, domain, runtime),
        _ => Err(USE.to_owned()),
    }
}

fn repair(
    args: &[String],
    data_dir: &Path,
    domain: &str,
    runtime: &tokio::runtime::Handle,
) -> Result<(), String> {
    const USE: &str = "expected: tgctl signer repair <seat> --helper <n>=<url> [--helper …]";

    let seat = args
        .iter()
        .find(|arg| !arg.starts_with("--"))
        .ok_or(USE)?
        .parse::<u16>()
        .map_err(|err| format!("<seat>: not a number ({err}) — {USE}"))?;

    let mut helpers = Vec::new();
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        if arg != "--helper" {
            continue;
        }
        let spec = rest.next().ok_or("--helper needs <n>=<url>")?;
        let (number, url) = spec.split_once('=').ok_or_else(|| {
            format!("--helper '{spec}': expected <n>=<url>, e.g. 1=http://tgd-1:9443")
        })?;
        let number = number
            .parse::<u16>()
            .map_err(|err| format!("--helper '{spec}': '{number}' is no seat number ({err})"))?;
        helpers.push((number, url.to_owned()));
    }
    if helpers.is_empty() {
        return Err(format!("repair needs at least one --helper — {USE}"));
    }

    let domain = tg_identity::TrustDomain::new(domain).map_err(|err| err.to_string())?;
    let repair = tg_identity::seats::Repair::prepare(data_dir, &domain, seat, &helpers)?;
    let epoch = repair.epoch();

    // **What is happening right now stands on stderr** — the call takes three
    // network rounds, and an operator who reads nothing takes it for hung.
    eprintln!(
        "repairing seat {seat} in {epoch} over {} helpers — the deltas go from \
         seat to seat, this call sees none (ADR-0108, determination 1)",
        helpers.len()
    );

    repair.run(runtime)?;

    println!("seat {seat} restored ({epoch})");
    eprintln!(
        "checked against the group key **before** anything was written \
         (determination 6) — `tgd` reads the share at startup"
    );

    Ok(())
}
