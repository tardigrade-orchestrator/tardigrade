//! The signing group's seats and its restoration coordinator (ADR-0097,
//! ADR-0108).
//!
//! # Why this lies here
//!
//! It lay in `tgd`, and `tgctl signer repair` called it -- whereby the CLI linked
//! the whole consensus core (ADR-0134). The comment there named the reason
//! expressly: "`tgctl` calls it instead of building the path a second time
//! (ADR-0023 counts the crates of a delivery binary)". The calculation was right
//! and the place wrong: the credential on the signer port is the **node key**
//! (ADR-0097), and that belongs to this crate.
//!
//! What stays in `tgd` is the **service**: whoever calls lands there.

use std::collections::BTreeMap;
use std::path::Path;

use std::sync::Arc;

use crate::threshold::{PublicKeyPackage, Seat};
use crate::{NodeTrust, TrustDomain};

const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

const CALL_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(1);

#[derive(Debug, Clone, Default)]
pub struct Seats {
    names: BTreeMap<u16, String>,
    trust: NodeTrust,
}

impl Seats {
    #[must_use]
    pub fn load(data_dir: &Path, domain: &TrustDomain) -> (Self, Vec<String>) {
        let dir = crate::layout::signers(data_dir);
        let mut seats = Self::default();
        let mut notes = Vec::new();
        let mut read: Vec<(u16, String, Vec<u8>)> = Vec::new();

        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) => {
                notes.push(format!("{}: {err}", dir.display()));
                return (seats, notes);
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) != Some("pem") {
                continue;
            }
            // The file name gives the **seat**, the leaf the node name. Both are
            // read: the number says which seat this leaf represents, the name is
            // the trust list's key (ADR-0043) and the binding with which a call
            // checks that the one answering is the one dialled.
            let Some(number) = path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .and_then(|stem| stem.parse::<u16>().ok())
            else {
                notes.push(format!(
                    "{}: the file name is no seat number",
                    path.display()
                ));
                continue;
            };
            match crate::cluster::read_leaf(&path, domain) {
                Ok((name, spki)) => {
                    read.push((number, name, spki));
                }
                Err(detail) => notes.push(format!("{}: {detail}", path.display())),
            }
        }

        // **One name, one seat** -- and a collision costs **both**.
        //
        // The list is keyed by seat, the trust list below it by node name
        // (ADR-0043). Measured, the consequence was silent: two leaves with the
        // same name yielded two admissions and **one** registration, without a word
        // -- the seat whose entry was overwritten did not get through the handshake
        // afterwards, while `tg_identity_signer_seats` counted it along. Exactly
        // that number tells an operator whether the group *can* reach the threshold
        // (determination 7).
        //
        // Taking one of the two would be guessing -- the same argument as with the
        // doubly declared workload in ADR-0062: **which one** would be decided by
        // the order in which the files are read, and the loser would look
        // admitted.
        let mut by_name: BTreeMap<&str, Vec<u16>> = BTreeMap::new();
        for (number, name, _) in &read {
            by_name.entry(name.as_str()).or_default().push(*number);
        }
        let colliding: std::collections::BTreeSet<u16> = by_name
            .iter()
            .filter(|(_, numbers)| numbers.len() > 1)
            .flat_map(|(name, numbers)| {
                let places: Vec<String> = numbers.iter().map(u16::to_string).collect();
                notes.push(format!(
                    "'{name}' represents more than one seat ({}) -- both are \
 refused, because otherwise one looks admitted and does not \
 get through the handshake",
                    places.join(", ")
                ));
                numbers.iter().copied()
            })
            .collect();

        for (number, name, spki) in read {
            if colliding.contains(&number) {
                continue;
            }
            seats.names.insert(number, name.clone());
            seats.trust.insert(&name, spki);
        }

        (seats, notes)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    #[must_use]
    pub fn seat_of(&self, node: &str) -> Option<u16> {
        self.names
            .iter()
            .find(|(_, name)| name.as_str() == node)
            .map(|(number, _)| *number)
    }

    #[must_use]
    pub fn trust(&self) -> NodeTrust {
        self.trust.clone()
    }

    #[must_use]
    pub fn dial(
        &self,
        seat: u16,
        url: &str,
        identity: &crate::NodeIdentity,
        domain: &TrustDomain,
    ) -> Option<tonic::transport::Channel> {
        let name = self.names.get(&seat)?;
        let verifier =
            crate::NodeVerifier::new(domain.clone(), crate::cluster::shared(self.trust.clone()))
                .expecting(name);
        let config = crate::cluster::client_config(identity, verifier).ok()?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

        let endpoint = tonic::transport::Endpoint::from_shared(url.to_owned())
            .ok()?
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(CALL_TIMEOUT);

        Some(
            endpoint.connect_with_connector_lazy(tower::service_fn(move |uri: http::Uri| {
                let connector = connector.clone();
                async move {
                    let host = uri.host().unwrap_or("127.0.0.1").to_owned();
                    let port = uri.port_u16().unwrap_or(80);
                    let stream = tokio::net::TcpStream::connect((host, port)).await?;
                    let name = rustls_pki_types::ServerName::try_from(crate::SNI)
                        .map_err(std::io::Error::other)?;
                    let tls = connector.connect(name, stream).await?;

                    Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
                }
            })),
        )
    }
}

#[derive(Debug)]
pub struct Repair {
    lost: Seat,
    helpers: Vec<(Seat, tonic::transport::Channel)>,
    group: PublicKeyPackage,
    epoch: crate::threshold::Epoch,
    data_dir: std::path::PathBuf,
}

impl Repair {
    pub fn prepare(
        data_dir: &Path,
        domain: &TrustDomain,
        lost: u16,
        helpers: &[(u16, String)],
    ) -> Result<Self, String> {
        let lost = Seat::new(lost).map_err(|err| err.to_string())?;

        // **Our own seat first**, before every access to the disk: the setting a
        // human typed comes before the environment (the same order as at `node
        // invite` and `cluster apply`).
        if helpers.iter().any(|(seat, _)| *seat == lost.number()) {
            return Err(format!(
                "seat {} stands among its own helpers -- whoever has the share does not need it (ADR-0108)",
                lost.number()
            ));
        }

        let signing = crate::layout::signing(data_dir);
        let key_path = crate::layout::dir(data_dir).join(crate::layout::NODE_KEY);
        let key_pem = std::fs::read_to_string(&key_path)
            .map_err(|err| format!("{}: {err}", key_path.display()))?;
        let key = rcgen::KeyPair::from_pem(&key_pem)
            .map_err(|err| format!("{}: {err}", key_path.display()))?;
        let id = crate::SpiffeId::for_node(domain, &node_name(data_dir, domain)?)
            .map_err(|err| err.to_string())?;
        let identity = crate::NodeIdentity::new(&key, id)?;

        // The group key and **its generation**: a share without an epoch would be
        // one nobody can classify (ADR-0107).
        //
        // **Not `Material::load`** -- that needs the share, and that is here exactly
        // what is missing. The group is read **alone**: the half generation `epochs`
        // expressly does not count *is* the repair case. And the **highest** one,
        // because a helper lays out its deltas from `newest_material()`; if this
        // coordinator took a lower one, `restore` would fail -- loudly, and for a
        // reason the message does not name.
        let epoch = *crate::threshold::groups(data_dir)
            .map_err(|err| format!("{}: {err}", signing.display()))?
            .last()
            .ok_or_else(|| {
                format!(
                    "no group key under {} -- without it there is nothing the \
                     restored share could be checked against (ADR-0108, \
                     determination 6)",
                    signing.display()
                )
            })?;
        let group = crate::threshold::load_group(data_dir, epoch)
            .map_err(|err| format!("group key {epoch}: {err}"))?;

        let threshold = group.min_signers().ok_or_else(|| {
            "the group key does not name its threshold (a package before frost-core 3.0)".to_owned()
        })?;
        let available = u16::try_from(helpers.len()).unwrap_or(u16::MAX);
        if available < threshold {
            return Err(format!(
                "{available} helpers do not reach the threshold of {threshold} -- with fewer the sigmas would yield a share that looks valid and is wrong (ADR-0108, determination 6)"
            ));
        }

        let (seats, notes) = Seats::load(data_dir, domain);
        let mut channels = Vec::with_capacity(helpers.len());
        for (seat, url) in helpers {
            let seat = Seat::new(*seat).map_err(|err| err.to_string())?;
            let channel = seats.dial(seat.number(), url, &identity, domain).ok_or_else(|| {
 format!(
                    "seat {} has no leaf under {}/{}.pem -- without it there is no channel, for the credential needs the binding to the one dialled (ADR-0097){}",
 seat.number(),
 crate::layout::signers(data_dir).display(),
 seat.number(),
 if notes.is_empty() {
 String::new()
                    } else {
 format!(" -- reported: {}", notes.join("; "))
                    }
                )
            })?;
            channels.push((seat, channel));
        }

        Ok(Self {
            lost,
            helpers: channels,
            group,
            epoch,
            data_dir: data_dir.to_path_buf(),
        })
    }

    #[must_use]
    pub fn epoch(&self) -> crate::threshold::Epoch {
        self.epoch
    }

    pub fn run(self, runtime: &tokio::runtime::Handle) -> Result<(), String> {
        let places: Vec<Seat> = self.helpers.iter().map(|(seat, _)| *seat).collect();
        let links: Vec<(Seat, crate::threshold::GrpcLink)> = self
            .helpers
            .into_iter()
            .map(|(seat, channel)| {
                (
                    seat,
                    crate::threshold::GrpcLink::new(seat, channel, runtime.clone()),
                )
            })
            .collect();

        match Self::rounds(&links, &places, self.lost, &self.group) {
            Ok(share) => {
                // **The restored share goes sealed onto the disk** (ADR-0140).
                // The custody arises here and not at the caller: this coordinator
                // runs beside `tgd`, and a second way to choose it would be a
                // second way to forget it.
                let custody =
                    crate::threshold::custody_for(&crate::layout::signing(&self.data_dir))
                        .map_err(|err| err.to_string())?;

                crate::threshold::Material::save(
                    &self.data_dir,
                    &share,
                    &self.group,
                    self.epoch,
                    custody.as_ref(),
                )
                .map_err(|err| err.to_string())
            }
            Err(err) => {
                // **No state beyond the run** (ADR-0108, D4) -- the same thing
                // `ThresholdSigner::refresh` does with `refresh_abandon`. Without
                // this arm the helpers that took part hold their inboxes until a
                // new run comes at some point: a delta alone says nothing, but it
                // is material, and `repair::Delta` is `Copy` -- nobody can delete
                // it (the TPM is the answer, ADR-0014).
                //
                // **A failure here is swallowed**, and that is the right direction:
                // the cause is the error above, and an unreachable helper cannot
                // clear its inbox anyway -- it has none either.
                for (_, link) in &links {
                    crate::threshold::SignerLink::repair_abandon(link, self.lost);
                }

                Err(err)
            }
        }
    }

    fn rounds(
        links: &[(Seat, crate::threshold::GrpcLink)],
        places: &[Seat],
        lost: Seat,
        group: &PublicKeyPackage,
    ) -> Result<crate::threshold::KeyPackage, String> {
        // Steps 1 and 2: every helper produces its deltas and **delivers them
        // itself**. This coordinator sees none -- exactly ADR-0108's point:
        // passed-through deltas yield the share.
        for (seat, link) in links {
            crate::threshold::SignerLink::repair_deal(link, lost, places)
                .map_err(|err| format!("step 1 at seat {}: {err}", seat.number()))?;
        }

        // Step 3: the sigmas. **Only this seat gets them** -- the port compares
        // the connection's credential (determination 3).
        let mut sigmas = Vec::with_capacity(links.len());
        for (seat, link) in links {
            let sigma = crate::threshold::SignerLink::repair_sigma(link, lost)
                .map_err(|err| format!("sigma from seat {}: {err}", seat.number()))?;
            sigmas.push(sigma);
        }

        crate::threshold::repair::restore(&sigmas, lost, group).map_err(|err| err.to_string())
    }
}

pub(crate) fn node_name(data_dir: &Path, domain: &TrustDomain) -> Result<String, String> {
    let path = crate::layout::dir(data_dir).join(crate::layout::NODE_LEAF);
    let (name, _) = crate::cluster::read_leaf(&path, domain)
        .map_err(|detail| format!("{}: {detail}", path.display()))?;

    Ok(name)
}
