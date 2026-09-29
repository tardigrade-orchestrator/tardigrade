//! The shared invocation options of the telemetry.
//!
//! Three binaries need the same four settings. Writing them three times would
//! mean that `--otlp-endpoint` in `tgd` eventually means something other than
//! in `tg-agent` — not because anybody wanted it so, but because two of three
//! places were maintained.

use std::net::SocketAddr;

#[must_use]
pub fn wants_help(args: &[String]) -> bool {
    args.iter()
        .any(|a| matches!(a.as_str(), "help" | "-h" | "--help"))
}

#[must_use]
pub fn mentions_word(usage: &str, flag: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';

    usage.match_indices(flag).any(|(at, _)| {
        let before = usage[..at].chars().next_back().is_none_or(|c| !word(c));
        let after = usage[at + flag.len()..]
            .chars()
            .next()
            .is_none_or(|c| !word(c));
        before && after
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub addr: Option<SocketAddr>,
    pub otlp: Option<String>,
    pub filter: String,
    pub json: bool,
}

impl Args {
    #[must_use]
    pub fn with_port(port: u16) -> Self {
        Self {
            addr: Some(SocketAddr::from(([127, 0, 0, 1], port))),
            ..Self::default()
        }
    }

    pub fn take(
        &mut self,
        flag: &str,
        mut value: impl FnMut() -> Result<String, String>,
    ) -> Result<bool, String> {
        match flag {
            "--telemetry-addr" => {
                let raw = value()?;
                // "off" as an explicit setting: otherwise an operator who wants
                // to switch the telemetry off would have to know the default and
                // name an address on which nothing listens.
                self.addr = if raw.eq_ignore_ascii_case("off") || raw == "-" {
                    None
                } else {
                    Some(
                        raw.parse()
                            .map_err(|_| format!("--telemetry-addr: '{raw}' is not an address"))?,
                    )
                };
            }
            "--otlp-endpoint" => self.otlp = Some(value()?),
            "--log-filter" => self.filter = value()?,
            "--log-format" => {
                let raw = value()?;
                self.json = match raw.as_str() {
                    "json" => true,
                    "text" => false,
                    other => {
                        return Err(format!("--log-format: '{other}', expected json or text"));
                    }
                };
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub const USAGE: &'static str = concat!(
        "  --telemetry-addr <addr>   address for /metrics /livez /readyz,\n",
        "                            'off' switches the endpoint off\n",
        "  --otlp-endpoint <url>     export spans via OTLP (ADR-0015);\n",
        "                            without it nothing is exported\n",
        "  --log-filter <expr>       like RUST_LOG (default: info)\n",
        "  --log-format json|text    default: json\n",
    );

    #[must_use]
    pub fn to_options(
        &self,
        service: &str,
        reporter: crate::init::Reporter,
    ) -> crate::init::Options {
        crate::init::Options {
            service: service.to_owned(),
            reporter,
            filter: self.filter.clone(),
            json: self.json,
            otlp_endpoint: self.otlp.clone(),
        }
    }
}

impl Default for Args {
    fn default() -> Self {
        Self {
            addr: None,
            otlp: None,
            filter: "info".to_owned(),
            json: true,
        }
    }
}

#[cfg(test)]
mod help_tests {
    use super::wants_help;

    #[test]
    fn the_usage_is_asked_for_in_three_spellings() {
        for spelling in ["help", "-h", "--help"] {
            assert!(
                wants_help(&[String::from(spelling)]),
                "'{spelling}' has to ask for the overview"
            );
        }
        assert!(
            wants_help(&[String::from("--once"), String::from("--help")]),
            "behind other flags too"
        );

        assert!(!wants_help(&[]), "an empty invocation starts the process");
        assert!(
            !wants_help(&[String::from("--interval"), String::from("3")]),
            "ordinary settings are not a question about the overview"
        );
        assert!(
            !wants_help(&[String::from("--h"), String::from("-help")]),
            "and only these three spellings"
        );
    }

    #[test]
    fn the_question_wins_over_the_position() {
        assert!(wants_help(&[
            String::from("--data-dir"),
            String::from("--help")
        ]));
    }
}
