//! The local telemetry endpoint: `/metrics`, `/livez`, `/readyz`.
//!
//! **Per node and failure-decoupled** (ADR-0015, ADR-0019). The endpoint asks
//! nobody — it reads what stands in the process. An endpoint that queried the
//! control plane would be silent precisely when it is needed.
//!
//! On `hyper` instead of the HTTP server `metrics-exporter-prometheus` brings
//! along: `hyper` lies in the tree via `tonic` anyway (zero new crates), and
//! three paths on **one** port are simpler to operate than two listeners.

use std::convert::Infallible;
use std::net::SocketAddr;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

use crate::probes::Health;

pub type Scrape = std::sync::Arc<dyn Fn() -> String + Send + Sync>;

pub async fn serve(addr: SocketAddr, health: Health, scrape: Scrape) -> Result<(), std::io::Error> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    // The empty `match` is where [`serve_on`]'s return type becomes visible:
    // there is no value, hence no way out of here. This function's `Result`
    // belongs to the `bind` above.
    match serve_on(listener, health, scrape).await {}
}

pub async fn serve_on(
    listener: tokio::net::TcpListener,
    health: Health,
    scrape: Scrape,
) -> Infallible {
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                if let Some(pause) = tg_syscall::accept::classify(&error).pause() {
                    tracing::warn!(%error, "telemetry endpoint does not accept — waiting");
                    tokio::time::sleep(pause).await;
                }
                continue;
            }
        };
        let health = health.clone();
        let scrape = scrape.clone();

        tokio::spawn(async move {
            let service = service_fn(move |request: Request<hyper::body::Incoming>| {
                let health = health.clone();
                let scrape = scrape.clone();
                async move { Ok::<_, Infallible>(route(&request, &health, scrape.as_ref())) }
            });

            // An error on a connection is an error on **one** connection. It
            // must not end the endpoint — otherwise an aborted scrape takes
            // observability with it.
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

pub fn route(
    request: &Request<hyper::body::Incoming>,
    health: &Health,
    scrape: &(dyn Fn() -> String + Send + Sync),
) -> Response<Full<Bytes>> {
    // `SystemTime` and no monotonic clock: the watchdog measures wall-clock time
    // against wall-clock time, and both come from the same source. ADR-0024
    // separates the time sources by purpose; here what counts is that it is the
    // **same** one.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();

    match request.uri().path() {
        "/metrics" => {
            sample_process();
            // **And the registered refreshes** (ADR-0088, determination 3): a
            // gauge decays after 15 minutes without an update, so that an alert
            // about a withdrawn workload falls silent. Whoever sets more rarely
            // sets here — for the same reason `sample_process` names below.
            health.refresh();
            text(StatusCode::OK, scrape())
        }
        "/livez" => {
            let probe = health.liveness(now);
            text(status(probe.ok), probe.body())
        }
        "/readyz" => {
            let probe = health.readiness();
            text(status(probe.ok), probe.body())
        }
        _ => text(
            StatusCode::NOT_FOUND,
            "/metrics /livez /readyz\n".to_owned(),
        ),
    }
}

// One `allow` for both metrics instead of two: a Prometheus metric *is* an
// `f64`. It would get imprecise beyond 2^53 — with a number of open descriptors
// that is out of reach, and this system's hard limit lies six orders of
// magnitude below it.
#[allow(clippy::cast_precision_loss)]
fn sample_process() {
    if let Some(open) = tg_syscall::fds::open() {
        metrics::gauge!(crate::names::OPEN_FDS).set(open as f64);
    }
    if let Some(limit) = tg_syscall::fds::limit() {
        metrics::gauge!(crate::names::MAX_FDS).set(limit as f64);
    }
}

const fn status(ok: bool) -> StatusCode {
    if ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

fn text(code: StatusCode, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(code)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::new())))
}
