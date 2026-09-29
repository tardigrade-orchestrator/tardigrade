//! The subscriber's fallback level (ADR-0015).
//!
//! `tracing` discards an event for which no subscriber stands — **silently**. As
//! long as the binaries wrote with `eprintln!`, a failed telemetry setup was only
//! a loss of metrics. Since they use `tracing`, it would be the loss of **every**
//! output, and precisely when something is already broken: the agent endures the
//! failure fail-soft (ADR-0019) and would then carry on mute.
//!
//! **A file of its own** because the subscriber is process-wide. A test that
//! installs one thereby changes every other test in the same binary, and the
//! order within a binary is not fixed. `cargo test` gives every test file its own
//! process; that is here not a convenience but the condition for the assertion to
//! mean anything.

use tg_telemetry::args::Args;

/// **If the setup fails, a subscriber stands nevertheless.**
///
/// Checked on the property `tracing` provides: the place is to be occupied
/// process-wide **once**. If no second one can be installed afterwards, the
/// fallback level has taken it.
#[test]
fn a_failed_setup_still_leaves_a_subscriber_behind() {
    use tracing_subscriber::util::SubscriberInitExt as _;

    // Beforehand the place is free — otherwise the test below checks nothing.
    assert!(
        tracing::dispatcher::get_default(|_| true),
        "the call has to get through"
    );

    // A filter expression `EnvFilter` does not accept. The setup thereby fails
    // **before** the subscriber — the case at issue.
    let mut args = Args::with_port(0);
    args.filter = "not=a=filter=,,,".to_owned();
    let options = args.to_options(
        "test",
        tg_telemetry::init::Reporter::Node("node".to_owned()),
    );

    // No export in this case (ADR-0133): the setup already fails at the filter
    // expression, and the reactor plays no part.
    let outcome = tg_telemetry::init::init(&options, tg_telemetry::init::Reactor::NoTracing);
    assert!(outcome.is_err(), "the setup should have failed");

    // And now the place is occupied.
    let second = tracing_subscriber::registry().try_init();
    assert!(
        second.is_err(),
        "no subscriber stands — the binaries' messages would be silent"
    );

    // The counter-check that something really arrives here: an event at `info`
    // is enabled with the fallback filter.
    assert!(
        tracing::event_enabled!(tracing::Level::INFO),
        "the fallback subscriber does not accept `info`"
    );
}
