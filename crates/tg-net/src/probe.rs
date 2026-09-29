//! An instance's readiness probe.
//!
//! # Why it lies here
//!
//! A TCP connect **in an instance's network namespace** — that is network
//! knowledge, and `tg-net` is the place for it. The agent calls it via the seam
//! `tg_runtime::network::Wiring::probe`, and the privileged harness calls **the
//! same** function: two versions would be two opportunities to make them
//! differently strict, and then a test would check a copy instead of the thing.
//!
//! # Why in the namespace, and why over loopback
//!
//! Both are measured and not chosen:
//!
//! - **From outside it does not work.** After the mesh redirect a connect to
//!   the container's address lands at the **sidecar** — so the probe would
//!   measure it and not the workload. And that refuses without an active
//!   role: a warm standby would appear permanently unready although there is
//!   nothing wrong with it.
//! - **Over loopback it works**, because `prerouting` does **not fire** on
//!   loopback — the same kernel property the sidecar's own way to its
//!   workload rests on; guarded by `the_redirect_does_not_touch_loopback` in
//!   `tests/kernel_path.rs`.
//!
//! # Two probes, one deadline
//!
//! [`connect_in`] asks whether **somebody is listening** — that is the start-up
//! case, and a server that answers `500` counts as ready in it. [`get_in`] asks
//! whether the application **answers**: a process that binds and answers
//! nothing is the case a connect does not see — and the more frequent one as
//! soon as a workload has to load something at startup.
//!
//! Which of the two runs is decided by the declaration: with `<readiness
//! path="…">` the second, without it the first. Both share [`TIMEOUT`], and on
//! the HTTP way it applies to **the whole** operation — connection, sending and
//! reading together. Two deadlines would be two opportunities to breach the
//! ordering condition below.

use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_millis(250);

const _: () = assert!(
    TIMEOUT.as_millis() < tg_model::lease::FENCE_WAKE_FLOOR_MILLIS as u128,
    "a hanging probe must not breach the fence's detection latency \
     (ADR-0076, ADR-0080)"
);

pub fn connect_in(netns: &str, port: u16) -> Result<(), String> {
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));

    // **`run_in` creates its thread itself**, and that is no convenience here:
    // `setns` applies to a **thread**, and a `setns` on the thread of a running
    // runtime would take the network from every task on it.
    tg_syscall::netns::run_in(netns, move || {
        TcpStream::connect_timeout(&target, TIMEOUT)
            .map(drop)
            .map_err(|err| format!("{}: {err}", err.kind()))
    })
    .map_err(|err| format!("namespace {netns}: {err}"))?
}

const STATUS_LIMIT: usize = 64;

const STATUS_MINIMUM: usize = 12;

pub fn get_in(netns: &str, port: u16, path: &str) -> Result<(), String> {
    let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let request = format!(
        // `Host:` is mandatory in HTTP/1.1, and `Connection: close` spares both
        // sides the question of when it ends: the server closes, and a `read` of
        // 0 is thereby a proper end and no hang.
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
    );

    // **One deadline for the whole operation.** One of its own per step would
    // mean three times it in the worst case — and with that the ordering
    // condition at [`TIMEOUT`] would be breached without any of the three
    // numbers looking wrong.
    let deadline = Instant::now() + TIMEOUT;

    // `run_in` creates its thread itself — the same reason as with
    // [`connect_in`]: `setns` applies to a **thread**.
    tg_syscall::netns::run_in(netns, move || {
        let mut stream = TcpStream::connect_timeout(&target, remaining(deadline)?)
            .map_err(|err| format!("{}: {err}", err.kind()))?;

        stream
            .set_write_timeout(Some(remaining(deadline)?))
            .and_then(|()| stream.write_all(request.as_bytes()))
            .and_then(|()| stream.flush())
            .map_err(|err| format!("send: {}: {err}", err.kind()))?;

        let mut seen = Vec::with_capacity(STATUS_LIMIT);
        let mut chunk = [0_u8; STATUS_LIMIT];
        while seen.len() < STATUS_MINIMUM {
            stream
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(|err| format!("read: {}: {err}", err.kind()))?;
            let room = STATUS_LIMIT - seen.len();
            let read = stream
                .read(&mut chunk[..room])
                .map_err(|err| format!("read: {}: {err}", err.kind()))?;
            if read == 0 {
                // The other side closed before a status line was complete.
                // That is no error on our side and nevertheless no answer.
                break;
            }
            seen.extend_from_slice(&chunk[..read]);
        }

        status_of(&seen)
    })
    .map_err(|err| format!("namespace {netns}: {err}"))?
}

fn remaining(deadline: Instant) -> Result<Duration, String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("TimedOut: the probe has expired".to_owned());
    }
    Ok(left.max(Duration::from_millis(1)))
}

fn status_of(seen: &[u8]) -> Result<(), String> {
    // **Truncated before the interpretation, not after.** The read path abides
    // by `STATUS_LIMIT`, but this function is the one that quotes — and a bound
    // that stands in another function is no assurance of this one. Truncated on
    // **bytes**: `from_utf8_lossy` makes valid UTF-8 out of them, while a cut on
    // the `&str` could fall in the middle of a multibyte character and panic.
    let seen = &seen[..seen.len().min(STATUS_LIMIT)];
    let line = String::from_utf8_lossy(seen);
    let line = line.split(['\r', '\n']).next().unwrap_or_default();

    let mut fields = line.split(' ');
    let version = fields.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(format!("no HTTP answer: {line:?}"));
    }

    let code: u16 = fields
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("no status line: {line:?}"))?;

    // `2xx` and not `< 400`: a redirect is no statement about readiness, and
    // following it would be a decision of its own.
    if (200..300).contains(&code) {
        return Ok(());
    }
    Err(format!("status {code}"))
}

#[cfg(test)]
mod tests {
    use super::{Duration, Instant, remaining, status_of};

    #[test]
    fn a_two_hundred_is_ready() {
        for line in [
            "HTTP/1.1 200 OK\r\n",
            "HTTP/1.1 200",
            "HTTP/1.0 204 No Content\r\n",
            // The edge: 200 and 299 belong to it.
            "HTTP/1.1 299 Special case\r\n",
        ] {
            assert!(
                status_of(line.as_bytes()).is_ok(),
                "{line:?} has to count as ready"
            );
        }
    }

    #[test]
    fn everything_outside_two_hundred_is_unready() {
        for (line, expected) in [
            ("HTTP/1.1 301 Moved\r\n", "status 301"),
            ("HTTP/1.1 302 Found\r\n", "status 302"),
            ("HTTP/1.1 199 Weird\r\n", "status 199"),
            ("HTTP/1.1 300 Choices\r\n", "status 300"),
            ("HTTP/1.1 503 Unavailable\r\n", "status 503"),
        ] {
            assert_eq!(
                status_of(line.as_bytes()).unwrap_err(),
                expected,
                "{line:?}"
            );
        }
    }

    #[test]
    fn a_response_that_is_not_http_is_refused() {
        for line in [
            "",
            "\r\n",
            "SSH-2.0-OpenSSH_9.6\r\n",
            // Truncated: the server closed before the code was complete.
            "HTTP/1.1 2",
            "HTTP/1.1 \r\n",
            "HTTP/1.1 twohundred\r\n",
            // A binary stream: `from_utf8_lossy` must not panic.
            "\u{0}\u{1}\u{2}",
        ] {
            assert!(
                status_of(line.as_bytes()).is_err(),
                "{line:?} must not count as ready"
            );
        }
    }

    #[test]
    fn nothing_behind_the_status_line_is_read() {
        let long = format!("HTTP/1.1 500 Nope\r\nX-Large: {}\r\n\r\n", "A".repeat(4096));
        let message = status_of(long.as_bytes()).unwrap_err();
        assert_eq!(message, "status 500");

        let noise = format!("not-http {}\r\n", "B".repeat(4096));
        let message = status_of(noise.as_bytes()).unwrap_err();
        assert!(
            message.len() < 128,
            "the message must not grow with the answer: {} bytes",
            message.len()
        );
    }

    #[test]
    fn an_exhausted_deadline_is_an_error_not_an_unlimited_wait() {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("the clock has been running for more than a second");
        assert!(remaining(past).is_err());

        let soon = Instant::now() + Duration::from_micros(1);
        let left = remaining(soon).expect("time left");
        assert!(
            left >= Duration::from_millis(1),
            "a deadline of zero would mean none at all to `std`: {left:?}"
        );

        let ample = Instant::now() + Duration::from_secs(5);
        let left = remaining(ample).expect("time left");
        assert!(left > Duration::from_secs(4), "{left:?}");
        assert!(left <= Duration::from_secs(5), "{left:?}");
    }

    // ============================================================= Fuzz run

    const DEFAULT_ITERATIONS: u32 = 20_000;

    fn iterations() -> u32 {
        std::env::var("TG_FUZZ_ITERATIONS")
            .ok()
            .and_then(|raw| raw.parse().ok())
            .unwrap_or(DEFAULT_ITERATIONS)
    }

    fn fresh_seed() -> u64 {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher as _, Hasher as _};

        RandomState::new().build_hasher().finish() | 1
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, bound: usize) -> usize {
            usize::try_from(self.next() % bound as u64).expect("fits")
        }
    }

    const MESSAGE_BOUND: usize = 512;

    fn response(rng: &mut Rng) -> (Vec<u8>, usize) {
        const CODES: &[u16] = &[200, 201, 204, 299, 199, 300, 301, 404, 503];
        const VERSIONS: &[&str] = &["HTTP/1.1", "HTTP/1.0", "HTTP/2", "SSH-2.0"];
        const REASONS: &[&str] = &["OK", "No Content", "", "Nope", "Moved Permanently"];

        let version = VERSIONS[rng.below(VERSIONS.len())];
        let code = CODES[rng.below(CODES.len())];
        let reason = REASONS[rng.below(REASONS.len())];
        let line = format!("{version} {code} {reason}");

        let mut full = line.clone().into_bytes();

        // **Every fourth answer has no line ending** — and that is no
        // completeness exercise: only then does the noise become part of the
        // *first* line and go into the message. Without this case the run would
        // never reach the path on which `{line:?}` escapes and the message grows
        // — the invariant about it would confirm itself. Measured: 57 bytes
        // longest message with CRLF against 323 without.
        let closed = rng.below(4) != 0;
        if closed {
            full.extend_from_slice(b"\r\n");
        }
        let behind = full.len();

        // The body: header lines and payload as they stand behind the status
        // line — sometimes large enough to exceed `STATUS_LIMIT`.
        //
        // **Every eighth answer consists of control characters.** Random bytes
        // hit one only every eighth time, and `{line:?}` inflates precisely
        // those (`\u{1b}` is six characters for one byte). Without this case the
        // measured upper bound would stay far below the real one — but a
        // container sends what suits it.
        //
        // And **300 bytes and not 80**: with 80, 79 control characters without
        // the truncation yielded around 500 bytes of message and thereby stayed
        // below the bound — the counter-check "truncation removed" bit and had
        // no effect. A run that cannot produce the difference does not guard it
        // either.
        let control = rng.below(8) == 0;
        for _ in 0..rng.below(300) {
            let byte = if control {
                u8::try_from(1 + rng.next() % 31).expect("control character")
            } else {
                u8::try_from(rng.next() % 256).expect("byte")
            };
            full.push(byte);
        }
        let behind = if closed { behind } else { full.len() };
        (full, behind)
    }

    #[test]
    fn no_response_from_a_container_breaks_the_probe() {
        let seed = fresh_seed();
        let mut rng = Rng(seed);
        let rounds = iterations();

        let mut ready = 0_u32;
        let mut unready = 0_u32;
        let mut behind_the_line = 0_u32;
        let mut longest = 0_usize;

        for round in 0..rounds {
            let (clean, behind) = response(&mut rng);
            let before = status_of(&clean);

            // Damaged is either **in** the status line or behind it.
            let mut damaged = clean.clone();
            let inside = rng.below(3) == 0 || damaged.len() <= behind;
            let at = if inside {
                rng.below(behind)
            } else {
                behind + rng.below(damaged.len() - behind)
            };
            damaged[at] = u8::try_from(rng.next() % 256).expect("byte");

            let after = status_of(&damaged);

            if !inside {
                behind_the_line += 1;
                assert_eq!(
                    before.as_ref().map_err(String::as_str),
                    after.as_ref().map_err(String::as_str),
                    "seed {seed}, round {round}: a damage behind the line \
                     ending changed the verdict (byte {at})"
                );
            }

            match &after {
                Ok(()) => ready += 1,
                Err(message) => {
                    unready += 1;
                    longest = longest.max(message.len());
                    assert!(
                        message.len() <= MESSAGE_BOUND,
                        "seed {seed}, round {round}: the message is {} bytes \
                         long — the sender determines its length",
                        message.len()
                    );
                }
            }
        }

        // A run that never enters the acceptance path confirms every invariant
        // itself. The thresholds are **measured** and not computed (see the
        // comment at the test below).
        let twentieth = rounds / 20;
        assert!(
            ready > twentieth,
            "seed {seed}: only {ready} of {rounds} answers counted as ready"
        );
        assert!(
            unready > twentieth,
            "seed {seed}: only {unready} of {rounds} answers were refused"
        );
        assert!(
            behind_the_line > twentieth,
            "seed {seed}: only {behind_the_line} damages lay behind the line \
             ending — the load-bearing invariant hardly ran"
        );

        // **The bound must also be reached.** Without this assurance a message
        // that never grows would be indistinguishable from a bounded one — and
        // precisely that state was in place as long as every answer had a line
        // ending (57 bytes instead of 323). Measured 313 to 323; demanded is
        // 200.
        assert!(
            longest > 200,
            "seed {seed}: the longest message was {longest} bytes — the \
             escaping path was hardly entered, and the bound checks nothing"
        );
    }
}
