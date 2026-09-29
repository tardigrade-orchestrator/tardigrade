//! Control-plane binary (ADR-0002, ADR-0005).

#![forbid(unsafe_code)]
// **No panic-capable call in the production path** (ADR-0082): since then a panic
// costs its task and not the node -- and that is a state an operator sees only at
// a metric. `not(test)`, because the unit tests in `src` need them; the guard lies
// in `tg-syscall/tests/invariants.rs`.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo)
)]

use std::process::ExitCode;

use tgd::options::{Options, usage};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // The helper lies in `tg_telemetry::args`, where the shared part of the
    // overview lies too. `tgd` additionally takes the **empty** call: without
    // `--peer` it does not start anyway.
    if args.is_empty() || tg_telemetry::args::wants_help(&args) {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }

    // The three following messages stay `eprintln!`, and that is no oversight:
    // they arise **before** the subscriber. A `tracing` event without a subscriber
    // is discarded silently -- a caller with a wrong argument would then get no
    // answer at all. (If the setup itself falls, the fallback in
    // `tg_telemetry::init` takes hold; here it does not stand yet.)
    let options = match Options::parse(&args) {
        Ok(options) => options,
        Err(message) => {
            eprintln!("tgd: {message}\n\n{}", usage());
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("tgd: the tokio runtime is not startable: {err}");
            return ExitCode::FAILURE;
        }
    };

    // The telemetry comes up **here** and not in `run`: the holder must outlive
    // the whole process so that buffered spans still go out at the end. A holder
    // within `run` falls with the first error path, and the last spans of a crash
    // would be exactly the ones that are missing.
    let telemetry = match tg_telemetry::init::init(
        &options.telemetry.to_options(
            "tgd",
            // The **name** and not the Raft identifier: `tg_task_alive` is set in
            // `tgd` and in the agent, and two formats under one label are two
            // values for an alarm rule.
            tg_telemetry::init::Reporter::Node(options.node.clone()),
        ),
        tg_telemetry::init::Reactor::In(runtime.handle()),
    ) {
        Ok(telemetry) => telemetry,
        Err(err) => {
            eprintln!("tgd: {err}");
            return ExitCode::FAILURE;
        }
    };
    let scrape = telemetry.scrape();

    // **The one-shot mode, before the service** (ADR-0137): it opens the same log
    // `run` would open in a moment, and `redb` lets exactly one process at it. It
    // ends instead of starting.
    if options.audit_export {
        return match runtime.block_on(tgd::audit_export(&options)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("tgd: {err}");
                ExitCode::FAILURE
            }
        };
    }

    match runtime.block_on(tgd::run(options, scrape)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(error = %err, "tgd ended");
            ExitCode::FAILURE
        }
    }
}
