//! Setup of tracing and metrics (ADR-0015).
//!
//! Two determinations that are not obvious:
//!
//! **Structured to stderr, not into a file.** A process that manages its own
//! log files also manages their rotation, their permissions and their full
//! disk. `stderr` leaves that to whoever starts the process — and a full file
//! system then does not cripple the orchestrator. The audit trail from ADR-0020
//! is **untouched** by this: it writes its own file, because it is subject to
//! retention and logs are not.
//!
//! **OTLP is a setting, not a compulsion.** Without `--otlp-endpoint` the node
//! runs without export. That is ADR-0019 in miniature: a node's observability
//! must not hang on a collector being reachable. The local endpoint from
//! [`crate::serve`] stands independently of it.

use std::time::Duration;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[derive(Debug, Clone)]
pub struct Options {
    pub service: String,
    pub reporter: Reporter,
    pub filter: String,
    pub json: bool,
    pub otlp_endpoint: Option<String>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            service: "tardigrade".to_owned(),
            reporter: Reporter::Node(String::new()),
            filter: "info".to_owned(),
            json: true,
            otlp_endpoint: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reporter {
    Node(String),
    Workload(String),
}

impl Reporter {
    #[must_use]
    pub fn label(&self) -> (&'static str, &str) {
        match self {
            Self::Node(name) => ("node", name.as_str()),
            Self::Workload(name) => ("workload", name.as_str()),
        }
    }
}

#[must_use = "if the holder drops, buffered spans are lost"]
pub struct Telemetry {
    handle: PrometheusHandle,
    otlp: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.debug_struct("Telemetry")
            .field("otlp", &self.otlp.is_some())
            .finish_non_exhaustive()
    }
}

impl Telemetry {
    #[must_use]
    pub fn scrape(&self) -> crate::serve::Scrape {
        let handle = self.handle.clone();
        std::sync::Arc::new(move || handle.render())
    }
}

impl Drop for Telemetry {
    fn drop(&mut self) {
        if let Some(provider) = self.otlp.take() {
            let _ = provider.shutdown();
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitError {
    pub detail: String,
}

impl std::fmt::Display for InitError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "telemetry: {}", self.detail)
    }
}

impl std::error::Error for InitError {}

pub const GAUGE_IDLE_SECONDS: u64 = 15 * 60;

// **Not shorter than the slowest legitimate scrape cadence.** A build assertion
// and not a test, because it is decidable at compile time: whoever sets the
// deadline below a scrape interval shall get no binary rather than a red run
// one can repeat. Prometheus typically asks every 15 to 60 seconds; below that
// the series of **healthy** objects lapse, and monitoring reports holes that do
// not exist.
const _: () = assert!(GAUGE_IDLE_SECONDS > 60);

#[derive(Debug, Clone, Copy)]
pub enum Reactor<'a> {
    In(&'a tokio::runtime::Handle),
    NoTracing,
}

pub fn init(options: &Options, reactor: Reactor<'_>) -> Result<Telemetry, InitError> {
    match setup(options, reactor) {
        Ok(telemetry) => Ok(telemetry),
        Err(err) => {
            // **Messages always need a home.**
            //
            // `tracing` discards an event for which no subscriber stands —
            // silently. As long as the binaries wrote with `eprintln!`, a
            // failed setup was only a loss of metrics; since they use
            // `tracing`, it would be the loss of **every** output, and
            // precisely when something is already broken.
            //
            // Hence here and not at the caller: a fallback level everybody
            // would have to hook in themselves is one somebody forgets.
            fallback();
            Err(err)
        }
    }
}

fn fallback() {
    let _ = tracing_subscriber::registry()
        .with(EnvFilter::new("info"))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init();
}

fn setup(options: &Options, reactor: Reactor<'_>) -> Result<Telemetry, InitError> {
    let fail = |detail: String| InitError { detail };

    let filter = EnvFilter::try_new(&options.filter).map_err(|err| fail(err.to_string()))?;

    // The metrics carry the node name as a label. **Only** it: ADR-0015 names
    // cardinality as an open point, and the most expensive way to answer it
    // wrongly is a label whose value range is unbounded — a peer address, a
    // connection id, a SPIFFE ID. The node name is bounded by the cluster size
    // (ADR-0031: five).
    let mut builder = PrometheusBuilder::new()
        .set_bucket_duration(Duration::from_mins(1))
        .map_err(|err| fail(err.to_string()))?
        // **Gauges decay, counters do not** (ADR-0088). Without it the exporter
        // keeps every series until the process ends: `tg_workload_ready{...} 0`
        // of a withdrawn workload then fires forever, and the alert could only
        // be silenced by a restart. For a **counter** the same decay would be
        // wrong — disappearing and returning reads to `rate()` as a reset.
        //
        // Measured against the library: the series disappears after the
        // deadline and comes back on the next set.
        .idle_timeout(
            metrics_util::MetricKindMask::GAUGE,
            Some(Duration::from_secs(GAUGE_IDLE_SECONDS)),
        );
    let (label, value) = options.reporter.label();
    if !value.is_empty() {
        builder = builder.add_global_label(label, value.to_owned());
    }
    let handle = builder
        .install_recorder()
        .map_err(|err| fail(err.to_string()))?;

    let otlp = match options.otlp_endpoint.as_deref() {
        None => {
            build_subscriber(filter, options.json, None)?;
            None
        }
        Some(endpoint) => {
            let Reactor::In(handle) = reactor else {
                return Err(fail(format!(
                    "this process exports no spans, \
                     --otlp-endpoint {endpoint} stays without effect (ADR-0133)"
                )));
            };
            // **In the reactor**, not beside it (determination 1): the exporter
            // builds a hyper channel.
            let _guard = handle.enter();
            let provider = otlp_provider(endpoint, &options.service)?;
            let tracer = opentelemetry::trace::TracerProvider::tracer(&provider, "tardigrade");
            build_subscriber(filter, options.json, Some(tracer))?;
            Some(provider)
        }
    };

    Ok(Telemetry { handle, otlp })
}

fn otlp_provider(
    endpoint: &str,
    service: &str,
) -> Result<opentelemetry_sdk::trace::SdkTracerProvider, InitError> {
    use opentelemetry_otlp::WithExportConfig as _;

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .map_err(|err| InitError {
            detail: err.to_string(),
        })?;

    Ok(opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name(service.to_owned())
                .build(),
        )
        .build())
}

fn build_subscriber(
    filter: EnvFilter,
    json: bool,
    tracer: Option<opentelemetry_sdk::trace::SdkTracer>,
) -> Result<(), InitError> {
    let fail = |err: tracing_subscriber::util::TryInitError| InitError {
        detail: err.to_string(),
    };

    // The OTLP layer is rebuilt in **every** branch and not once beforehand:
    // its type parameter is that of the subscriber it hangs under, and that
    // differs in the two branches (`JsonFields` against `DefaultFields`). A
    // pre-built layer could only be placed in one of the two.
    if json {
        tracing_subscriber::registry()
            .with(filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_writer(std::io::stderr),
            )
            .with(tracer.map(|tracer| tracing_opentelemetry::layer().with_tracer(tracer)))
            .try_init()
            .map_err(fail)
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .with(tracer.map(|tracer| tracing_opentelemetry::layer().with_tracer(tracer)))
            .try_init()
            .map_err(fail)
    }
}
