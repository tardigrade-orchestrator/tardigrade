//! The custody of the runtime shares (ADR-0014 sub-decision 2).
//!
//! The root lies in the HSM, air-gapped -- that is the offline path and does not
//! occur in this codebase. The **runtime shares** are TPM-sealed, per node. What
//! stands here is the seam for that: a trait with two methods, behind which a TPM
//! steps without a line in the signature path becoming different.
//!
//! Why TPM and not HSM: an HSM per node would have put the PKCS#11 FFI into
//! **every** control-plane node's runtime path and made procuring an HSM a
//! precondition for adding a node at all. A share alone is worthless below the
//! threshold t anyway.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;

use ring::aead;
use ring::rand::SecureRandom as _;

use crate::threshold::KeyPackage;
use crate::threshold::error::ThresholdError;
use crate::threshold::group::Seat;

/// A sealed share.
///
/// What stands in `blob` only the [`ShareCustody`] that sealed it knows. For
/// everything else it is an opaque block that belongs to exactly one seat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedShare {
    seat: Seat,
    blob: Vec<u8>,
}

impl SealedShare {
    /// A sealed share from a custody's bytes.
    #[must_use]
    pub fn new(seat: Seat, blob: Vec<u8>) -> Self {
        Self { seat, blob }
    }

    /// The seat it belongs to.
    #[must_use]
    pub fn seat(&self) -> Seat {
        self.seat
    }

    /// The sealed bytes.
    #[must_use]
    pub fn blob(&self) -> &[u8] {
        &self.blob
    }
}

/// The seam to the TPM.
///
/// It deliberately sits around the **whole** share and not around a key handle:
/// FROST computes with the share, so it must lie in memory in order to sign. What
/// the custody delivers is that it lies there only as long as a signature takes,
/// and never stands unsealed on the disk.
pub trait ShareCustody: std::fmt::Debug + Send + Sync {
    /// Seals a share.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the sealing fails.
    fn seal(&self, seat: Seat, share: &KeyPackage) -> Result<SealedShare, ThresholdError>;

    /// Opens a sealed share.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the opening fails -- in operation the case
    /// in which the TPM no longer attests the state the share was bound to.
    fn unseal(&self, sealed: &SealedShare) -> Result<KeyPackage, ThresholdError>;
}

/// A custody that seals nothing.
///
/// **Not the custody model from ADR-0014.** There the runtime shares are TPM-sealed;
/// here they lie as bytes in memory. This implementation exists so that the
/// threshold path can be built and checked without a TPM -- just as `LocalSigner`
/// existed in phase 7a so that the SVID path could be built without a threshold
/// group. It carries that in its name so that nobody takes it for one.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlainCustody;

impl ShareCustody for PlainCustody {
    fn seal(&self, seat: Seat, share: &KeyPackage) -> Result<SealedShare, ThresholdError> {
        let blob = share.serialize().map_err(|err| ThresholdError::Custody {
            detail: err.to_string(),
        })?;

        Ok(SealedShare::new(seat, blob))
    }

    fn unseal(&self, sealed: &SealedShare) -> Result<KeyPackage, ThresholdError> {
        KeyPackage::deserialize(sealed.blob()).map_err(|err| ThresholdError::Custody {
            detail: err.to_string(),
        })
    }
}

// =========================================================== The TPM (0140)

/// The marker by which a sealed share is recognizable on the disk.
///
/// **It must be distinguishable from a FROST package**, and that is measured: a
/// serialized [`KeyPackage`] begins with the ciphersuite head `00 b1 69 f0 da`, that
/// is, with a zero byte. A `T` is `0x54`. The distinction is thereby not probably
/// right but certainly so -- and a witness records the head so that a format change
/// in `frost-core` stands out instead of slipping through.
const MARK: &[u8; 8] = b"TGSHARE1";

/// The envelope key's length -- ChaCha20-Poly1305, as in [`crate::secrets`]
/// (ADR-0140, determination 1).
const KEY_LEN: usize = 32;

/// The nonce's length.
const NONCE_LEN: usize = 12;

/// How long a `tpm2_*` call may take.
///
/// Measured, the most expensive one (`tpm2_load` + `tpm2_unseal`) costs **0.38 s**.
/// The ten seconds are the error case and not the expectation: a TPM behind the
/// resource manager can wait among several callers. The minute from
/// `tg_runtime::volume` would be too much here -- there a volume setup hangs on it,
/// here the **signature path**, and a signer that stands still for a minute is
/// worse than one that gives up.
const TOOL_TIMEOUT: Duration = Duration::from_secs(10);

/// The device by which a TPM is recognizable.
///
/// The resource manager (`tpmrm0`), not the raw device: it multiplexes the TPM's
/// limited object slots between callers. Whoever takes `tpm0` fails as soon as a
/// second process has the same idea.
const DEVICE: &str = "/dev/tpmrm0";

/// With what a different device can be named.
///
/// **A path, no switch** -- and the difference is the whole intent. "Sealing off"
/// would be a setting somebody sets in production and nobody sees afterwards (the
/// shape ADR-0017, ADR-0090 and ADR-0113 expressly reject). Naming a *device* is
/// something else: if the path points into the void, the situation is the same as on
/// a machine without a TPM, and [`custody_for`] reports it with the same warning.
///
/// It is needed by the test rig: `cargo test` runs the test binaries concurrently,
/// and a TPM is **one serial device for the whole machine**. Measured, the signing
/// group's witnesses fall over in rows as soon as forty-five `tgd` processes share
/// it -- run serially, the same nine are green. That is the same finding as at the
/// telemetry port in 11b and at the bridge address in 10a, and the same answer: the
/// test gets its own situation instead of living off fail-soft.
const DEVICE_VAR: &str = "TG_TPM_DEVICE";

/// The device this process uses.
fn device() -> String {
    std::env::var(DEVICE_VAR).unwrap_or_else(|_| DEVICE.to_owned())
}

/// The custody from ADR-0014, sub-decision 2.
///
/// # An envelope instead of direct sealing
///
/// The share does **not** fit into a TPM object. Measured: a serialized
/// [`KeyPackage`] is 134 bytes, `tpm2_create -i` takes 128 (at 256 it refuses). Six
/// bytes are missing at exactly the place at which [`ShareCustody`] per its own
/// documentation sits "deliberately" around the whole share.
///
/// So an envelope (ADR-0140, determination 1): a 32-byte key is sealed, the share
/// encrypted with it. The procedure is the same as in [`crate::secrets`] --
/// ChaCha20-Poly1305 from `ring` --, so **no second crypto in the tree**.
///
/// The key from ADR-0095 is expressly **not** used along in the process, only its
/// procedure: that one is cluster-wide and is delivered, this one is per node and
/// never leaves the TPM. And it is **optional** -- a cluster without secrets has
/// none, and hanging the CA on it would mean making it dependent on a file that need
/// not exist on the normal path.
///
/// # Bound to what
///
/// To this TPM, **to nothing else** (ADR-0140, determinations 4 and 5). No PCR
/// policy: the price is substantiated at the device -- an extended PCR makes the
/// share unreadable, and firmware, bootloader and `dbx` updates extend PCRs by
/// themselves. With five seats at t = 3 a rolling firmware update hits three of them
/// in one maintenance window, and then the CA has not failed but is **gone**.
///
/// No auth value: every source for it would lie beside the blob in `signing/`
/// (`0700`, ADR-0115). Whoever can read the blob would read the password too -- the
/// argument from ADR-0044, ADR-0081 and ADR-0115.
///
/// What remains is exactly this module's protection goal: a copied disk, a backup, a
/// VM snapshot do not give the share away. The TPM does not export the seed, not
/// even for root.
#[derive(Debug)]
pub struct TpmCustody {
    /// Where the `tpm2_*` calls' context and object files lie.
    ///
    /// They carry **no** secrets: the primary context is a handle, `.pub`/`.priv`
    /// are the sealed object. The key goes in over stdin and out over stdout, never
    /// over argv and never over a file (ADR-0140, determination 2 -- the same
    /// discipline as the LUKS passphrase in ADR-0113).
    work: PathBuf,

    /// The TPM is a serial device, and the file names are fixed.
    ///
    /// A `Mutex` instead of unique names: two simultaneous openings would bring the
    /// TPM nothing, because it processes them one after another anyway, and unique
    /// names would be one more clearing-up question.
    gate: Mutex<()>,
}

impl TpmCustody {
    /// A custody with a working directory under `dir`.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the directory cannot be created.
    pub fn new(dir: &Path) -> Result<Self, ThresholdError> {
        let work = dir.join(".tpm");
        std::fs::create_dir_all(&work).map_err(|err| ThresholdError::Custody {
            detail: format!("{}: {err}", work.display()),
        })?;
        // **Expressly `0700` and not left to the umask** (ADR-0115). No secret
        // lies here, but whoever can swap these files determines which object the
        // TPM opens.
        std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
            ThresholdError::Custody {
                detail: format!("{}: {err}", work.display()),
            }
        })?;

        Ok(Self {
            work,
            gate: Mutex::new(()),
        })
    }

    /// Whether this node has a TPM at all.
    ///
    /// What is asked for is the **device**, not the program: if the program is
    /// missing while the device is present, that is an operational error and shall
    /// stand out as an error, not pass as "no TPM" (ADR-0140, determination 7 -- no
    /// silent fallback).
    #[must_use]
    pub fn present() -> bool {
        Path::new(&device()).exists()
    }

    /// Makes sure of the primary key.
    ///
    /// **Derived, not persisted** (ADR-0140, determination 3): measured,
    /// `tpm2_createprimary -C o` yields the same key twice, and the second opens the
    /// first one's blob. With that `tpm2_evictcontrol` falls away, **no NV slot is
    /// consumed**, and a TPM clear is the only way to lose it.
    ///
    /// The context stays as a file -- it is the shortcut of 0.13 s and no state we
    /// carry: if it is no longer usable (after a TPM reset), it is derived anew.
    fn primary(&self) -> Result<PathBuf, ThresholdError> {
        let ctx = self.work.join("primary.ctx");
        if ctx.exists() {
            return Ok(ctx);
        }

        run(
            "tpm2_createprimary",
            &[
                "-C",
                "o",
                "-g",
                "sha256",
                "-G",
                "ecc",
                "-c",
                &ctx.to_string_lossy(),
            ],
        )?;

        Ok(ctx)
    }

    /// As [`Self::primary`], but forces the re-derivation.
    ///
    /// The fallback for a context that did not survive a TPM reset.
    fn primary_afresh(&self) -> Result<PathBuf, ThresholdError> {
        let ctx = self.work.join("primary.ctx");
        let _ = std::fs::remove_file(&ctx);
        self.primary()
    }
}

impl ShareCustody for TpmCustody {
    fn seal(&self, seat: Seat, share: &KeyPackage) -> Result<SealedShare, ThresholdError> {
        let plaintext = share.serialize().map_err(|err| ThresholdError::Custody {
            detail: err.to_string(),
        })?;

        let random = ring::rand::SystemRandom::new();
        let mut key = [0_u8; KEY_LEN];
        let mut nonce = [0_u8; NONCE_LEN];
        random
            .fill(&mut key)
            .and_then(|()| random.fill(&mut nonce))
            .map_err(|_| ThresholdError::Custody {
                detail: "no randomness for the envelope -- nothing is sealed".to_owned(),
            })?;

        let mut ciphertext = plaintext;
        sealing_key(&key)?
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(seat.number().to_be_bytes()),
                &mut ciphertext,
            )
            .map_err(|_| ThresholdError::Custody {
                detail: "the envelope could not be closed".to_owned(),
            })?;

        let (public, private) = {
            let _held = self.gate.lock().map_err(|_| ThresholdError::Custody {
                detail: "the TPM lock is poisoned".to_owned(),
            })?;
            let public = self.work.join("seal.pub");
            let private = self.work.join("seal.priv");
            let ctx = self.primary()?;

            run_with_secret(
                "tpm2_create",
                &[
                    "-C",
                    &ctx.to_string_lossy(),
                    "-g",
                    "sha256",
                    "-i",
                    "-",
                    "-u",
                    &public.to_string_lossy(),
                    "-r",
                    &private.to_string_lossy(),
                ],
                &key,
            )?;

            (read(&public)?, read(&private)?)
        };

        Ok(SealedShare::new(
            seat,
            envelope(seat, &public, &private, &nonce, &ciphertext),
        ))
    }

    fn unseal(&self, sealed: &SealedShare) -> Result<KeyPackage, ThresholdError> {
        let Parts {
            seat,
            public,
            private,
            nonce,
            ciphertext,
        } = Parts::of(sealed.blob())?;

        // **The seat in the envelope and the handle's must be the same.** They
        // come from different directions -- the one from the bytes, the other from
        // the caller --, and where they go apart, somebody put a share at a foreign
        // seat. The AEAD would fall over it anyway (the seat is its AAD), but then
        // the finding would read "does not belong to this key", and an operator
        // would look at the TPM instead of at the directory.
        if seat != sealed.seat() {
            return Err(ThresholdError::Custody {
                detail: format!(
                    "the envelope names seat {}, expected was {}",
                    seat.number(),
                    sealed.seat().number()
                ),
            });
        }

        let key = {
            let _held = self.gate.lock().map_err(|_| ThresholdError::Custody {
                detail: "the TPM lock is poisoned".to_owned(),
            })?;
            let public_at = self.work.join("open.pub");
            let private_at = self.work.join("open.priv");
            let object = self.work.join("open.ctx");
            write(&public_at, &public)?;
            write(&private_at, &private)?;

            // **First with the context that lies there, then with a fresh one.** A
            // stored primary context does not survive a TPM reset; deriving it anew
            // every time cost 0.13 s per signature, never deriving it anew turned a
            // reboot into an outage.
            let mut loaded = load(&self.primary()?, &public_at, &private_at, &object);
            if loaded.is_err() {
                loaded = load(&self.primary_afresh()?, &public_at, &private_at, &object);
            }
            loaded?;

            run("tpm2_unseal", &["-c", &object.to_string_lossy()])?
        };

        if key.len() != KEY_LEN {
            return Err(ThresholdError::Custody {
                detail: format!(
                    "the TPM handed out {} instead of {KEY_LEN} bytes",
                    key.len()
                ),
            });
        }

        let mut buffer = ciphertext;
        let opened = sealing_key(&key)?
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(sealed.seat().number().to_be_bytes()),
                &mut buffer,
            )
            .map_err(|_| ThresholdError::Custody {
                detail: "the envelope does not belong to this key or this seat".to_owned(),
            })?;

        KeyPackage::deserialize(opened).map_err(|err| ThresholdError::Custody {
            detail: err.to_string(),
        })
    }
}

/// The custody that belongs to this node (ADR-0140).
///
/// **A TPM is used when it is there** -- not on request, not over a setting. A
/// switch would mean that unsealed is selectable, and a node on which somebody
/// forgot it would look from outside like any other (the shape from ADR-0017,
/// ADR-0090 and ADR-0113).
///
/// Without a device it stays at [`PlainCustody`], with a report. That is **no**
/// fallback in the sense of ADR-0140 determination 7: that one concerns a TPM that
/// *is there* and does not answer, and then nothing is taken back here --
/// [`TpmCustody`] gives an error, and the seat holds still. Which one it became is
/// said by the metric (the same shape as at the signing group, ADR-0097
/// determination 6).
///
/// # Errors
///
/// [`ThresholdError::Custody`] when a device is there but the working directory
/// cannot be created.
pub fn custody_for(dir: &Path) -> Result<std::sync::Arc<dyn ShareCustody>, ThresholdError> {
    if TpmCustody::present() {
        return Ok(std::sync::Arc::new(TpmCustody::new(dir)?));
    }

    tracing::warn!(
        device = %device(),
        "no TPM -- the share lies unsealed on the disk (ADR-0014 demands it \
         differently, ADR-0140 names the way)"
    );

    Ok(std::sync::Arc::new(PlainCustody))
}

/// Whether these bytes are an envelope -- and not a naked share.
///
/// The one place at which the distinction happens. It is the basis of the migration
/// in [`Material::adopt`](crate::threshold::Material::adopt): what does not carry
/// the marker comes from the time before ADR-0140 and lies in the clear.
#[must_use]
pub fn is_envelope(bytes: &[u8]) -> bool {
    bytes.starts_with(MARK)
}

/// The seat an envelope names -- without opening it.
///
/// The way on which the disk can form a [`SealedShare`]: it must know the seat
/// before it has the share, and in the share it stands only afterwards.
///
/// # Errors
///
/// [`ThresholdError::Custody`] when the bytes are no envelope.
pub fn envelope_seat(bytes: &[u8]) -> Result<Seat, ThresholdError> {
    Parts::of(bytes).map(|parts| parts.seat)
}

/// The key for an envelope.
fn sealing_key(key: &[u8]) -> Result<aead::LessSafeKey, ThresholdError> {
    aead::UnboundKey::new(&aead::CHACHA20_POLY1305, key)
        .map(aead::LessSafeKey::new)
        .map_err(|_| ThresholdError::Custody {
            detail: "the envelope key has the wrong length".to_owned(),
        })
}

/// Assembles the envelope -- **length-prefixed**, like `renew_message`.
///
/// Without lengths a field could be lengthened at the next one's expense, and two
/// different envelopes would yield the same bytes.
///
/// **The seat stands in it**, right behind the marker, and that is no convenience:
/// it is the envelope's AAD, so it must be readable *before* it is opened.
/// Otherwise one would have to know the share already in order to be able to open it
/// -- and the disk that carries it does not know it.
fn envelope(seat: Seat, public: &[u8], private: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        MARK.len() + 18 + public.len() + private.len() + nonce.len() + ciphertext.len(),
    );
    out.extend_from_slice(MARK);
    out.extend_from_slice(&seat.number().to_be_bytes());
    for field in [public, private, nonce, ciphertext] {
        // The length fits: all four fields are smaller than a kilobyte, and
        // `envelope` gets only what `seal` itself produced.
        let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// An envelope's fields.
///
/// The `Debug` shows **lengths instead of content** -- not out of secrecy (nothing
/// open stands here) but because when looking for a format error the length is the
/// information and 200 bytes of hex make the line unreadable.
struct Parts {
    seat: Seat,
    public: Vec<u8>,
    private: Vec<u8>,
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
}

impl Parts {
    /// Takes an envelope apart.
    ///
    /// # Errors
    ///
    /// [`ThresholdError::Custody`] when the marker is missing, a length points
    /// beyond the end or something is left over. **Nothing may be left over**:
    /// otherwise the same share would carry arbitrarily many representations, and a
    /// comparison on bytes would depend on which one one catches.
    fn of(bytes: &[u8]) -> Result<Self, ThresholdError> {
        let malformed = |what: &str| ThresholdError::Custody {
            detail: format!("the sealed share is unusable: {what}"),
        };

        let rest = bytes
            .strip_prefix(MARK)
            .ok_or_else(|| malformed("the marker"))?;
        let (head, mut rest) = rest
            .split_at_checked(2)
            .ok_or_else(|| malformed("the seat is missing"))?;
        // `head` is exactly two bytes long -- `split_at_checked` promised it.
        let seat = Seat::new(u16::from_be_bytes(head.try_into().unwrap_or([0; 2])))?;

        let mut fields = Vec::with_capacity(4);
        for _ in 0..4 {
            let (head, tail) = rest
                .split_at_checked(4)
                .ok_or_else(|| malformed("a length"))?;
            // `head` is exactly four bytes long -- `split_at_checked` promised
            // it.
            let len = u32::from_be_bytes(head.try_into().unwrap_or([0; 4])) as usize;
            let (field, tail) = tail
                .split_at_checked(len)
                .ok_or_else(|| malformed("a field reaches beyond the end"))?;
            fields.push(field.to_vec());
            rest = tail;
        }
        if !rest.is_empty() {
            return Err(malformed("bytes behind the last field"));
        }

        let mut fields = fields.into_iter();
        // Four fields were just inserted.
        let (Some(public), Some(private), Some(nonce), Some(ciphertext)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(malformed("the field count"));
        };

        Ok(Self {
            seat,
            public,
            private,
            nonce: nonce
                .as_slice()
                .try_into()
                .map_err(|_| malformed("the nonce length"))?,
            ciphertext,
        })
    }
}

impl std::fmt::Debug for Parts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Parts")
            .field("seat", &self.seat.number())
            .field("public", &self.public.len())
            .field("private", &self.private.len())
            .field("nonce", &self.nonce.len())
            .field("ciphertext", &self.ciphertext.len())
            .finish()
    }
}

/// Loads a sealed object under a primary context.
///
/// # Errors
///
/// [`ThresholdError::Custody`] when `tpm2_load` fails.
fn load(
    primary: &Path,
    public: &Path,
    private: &Path,
    object: &Path,
) -> Result<(), ThresholdError> {
    run(
        "tpm2_load",
        &[
            "-C",
            &primary.to_string_lossy(),
            "-u",
            &public.to_string_lossy(),
            "-r",
            &private.to_string_lossy(),
            "-c",
            &object.to_string_lossy(),
        ],
    )
    .map(|_| ())
}

fn read(path: &Path) -> Result<Vec<u8>, ThresholdError> {
    std::fs::read(path).map_err(|err| ThresholdError::Custody {
        detail: format!("{}: {err}", path.display()),
    })
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), ThresholdError> {
    std::fs::write(path, bytes).map_err(|err| ThresholdError::Custody {
        detail: format!("{}: {err}", path.display()),
    })
}

/// Calls a `tpm2_*` program; the output is **binary**.
///
/// `tpm2_unseal` writes the key as bytes to stdout. Sending it through
/// `String::from_utf8_lossy` -- the way in `tg_runtime::volume`, where the output is
/// always text -- would destroy every byte above `0x7f`.
fn run(program: &'static str, args: &[&str]) -> Result<Vec<u8>, ThresholdError> {
    spawn(program, args, None)
}

/// As [`run`], but with a secret on stdin.
fn run_with_secret(
    program: &'static str,
    args: &[&str],
    secret: &[u8],
) -> Result<Vec<u8>, ThresholdError> {
    spawn(program, args, Some(secret))
}

/// The one call path -- **both forms**, so that a failure is not named differently
/// at two places (the finding out of which `tg-wire` arose).
fn spawn(
    program: &'static str,
    args: &[&str],
    secret: Option<&[u8]>,
) -> Result<Vec<u8>, ThresholdError> {
    let owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let secret = secret.map(<[u8]>::to_vec);
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = (|| {
            let mut child = Command::new(program)
                .args(&owned)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;
            // **The handle falls here**, with or without a secret: without the
            // `drop` a child with `-i -` sees no EOF and waits.
            if let (Some(mut stdin), Some(secret)) = (child.stdin.take(), &secret) {
                stdin.write_all(secret)?;
            }
            child.wait_with_output()
        })();
        let _ = tx.send(outcome);
    });

    match rx.recv_timeout(TOOL_TIMEOUT) {
        Ok(Ok(output)) if output.status.success() => Ok(output.stdout),
        Ok(Ok(output)) => Err(ThresholdError::Custody {
            detail: format!(
                "{program}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        }),
        Ok(Err(err)) => Err(ThresholdError::Custody {
            detail: if err.kind() == std::io::ErrorKind::NotFound {
                format!(
                    "{program} is not in the PATH -- tpm2-tools is an operational \
                     prerequisite for a node with a signer seat (ADR-0140)"
                )
            } else {
                format!("{program}: {err}")
            },
        }),
        Err(_) => Err(ThresholdError::Custody {
            detail: format!(
                "{program} did not answer within {} s",
                TOOL_TIMEOUT.as_secs()
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MARK, Parts, SealedShare, ShareCustody, TpmCustody, device, envelope, is_envelope,
    };
    use crate::threshold::KeyPackage;
    use crate::threshold::group::Seat;

    /// The ciphersuite head with which a serialized `KeyPackage` begins.
    ///
    /// **Measured**, not from the specification: three shares from a
    /// `generate_with_dealer` run all began with these five bytes, and only
    /// afterwards did they differ (in the identifier).
    const FROST_HEAD: [u8; 5] = [0x00, 0xb1, 0x69, 0xf0, 0xda];

    fn seat(number: u16) -> Seat {
        Seat::new(number).expect("seat")
    }

    /// A real share from a dealer run -- synthetic, like every piece of test
    /// material here.
    fn a_share() -> KeyPackage {
        let (shares, _group) = frost_ed25519::keys::generate_with_dealer(
            5,
            3,
            frost_ed25519::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .expect("dealer");
        let secret = shares.into_values().next().expect("one share");

        KeyPackage::try_from(secret).expect("package")
    }

    /// The assertion the whole migration rests on.
    #[test]
    fn the_mark_cannot_be_mistaken_for_a_frost_package() {
        assert!(
            !FROST_HEAD.starts_with(&MARK[..1]),
            "the marker begins like a FROST package -- then a plaintext share \
             cannot be distinguished from an envelope"
        );
        assert!(!is_envelope(&FROST_HEAD));
    }

    #[test]
    fn a_plain_share_is_not_an_envelope() {
        let mut plain = FROST_HEAD.to_vec();
        plain.extend_from_slice(&[7; 129]);

        assert!(!is_envelope(&plain));
        assert!(Parts::of(&plain).is_err());
    }

    #[test]
    fn an_envelope_survives_being_taken_apart() {
        let blob = envelope(seat(3), b"pub", b"priv", &[9; 12], b"cipher");

        assert!(is_envelope(&blob));
        let parts = Parts::of(&blob).expect("take apart");
        assert_eq!(parts.seat, seat(3));
        assert_eq!(parts.public, b"pub");
        assert_eq!(parts.private, b"priv");
        assert_eq!(parts.nonce, [9; 12]);
        assert_eq!(parts.ciphertext, b"cipher");
    }

    /// Different fields yield different bytes -- the property for whose sake the
    /// fields are length-prefixed.
    #[test]
    fn shifting_a_byte_between_fields_changes_the_envelope() {
        let left = envelope(seat(1), b"ab", b"c", &[0; 12], b"x");
        let right = envelope(seat(1), b"a", b"bc", &[0; 12], b"x");

        assert_ne!(left, right);
    }

    #[test]
    fn an_envelope_without_its_mark_is_refused() {
        let blob = envelope(seat(1), b"pub", b"priv", &[0; 12], b"cipher");
        let err = Parts::of(&blob[1..]).expect_err("without the marker");

        assert!(err.to_string().contains("the marker"), "{err}");
    }

    #[test]
    fn a_truncated_envelope_is_refused() {
        let blob = envelope(seat(1), b"pub", b"priv", &[0; 12], b"cipher");
        for cut in [MARK.len(), MARK.len() + 2, blob.len() - 1] {
            assert!(
                Parts::of(&blob[..cut]).is_err(),
                "at {cut} bytes it should have been refused"
            );
        }
    }

    /// A length that points beyond the end must be no access beyond the buffer --
    /// this parser's actual security promise.
    #[test]
    fn a_length_beyond_the_end_is_refused_and_does_not_panic() {
        let mut blob = Vec::from(MARK.as_slice());
        blob.extend_from_slice(&1_u16.to_be_bytes());
        blob.extend_from_slice(&u32::MAX.to_be_bytes());
        blob.extend_from_slice(b"short");

        let err = Parts::of(&blob).expect_err("a length beyond the end");
        assert!(err.to_string().contains("beyond the end"), "{err}");
    }

    /// An appendage must not get through: otherwise the same share would carry
    /// arbitrarily many representations.
    #[test]
    fn trailing_bytes_are_refused() {
        let mut blob = envelope(seat(1), b"pub", b"priv", &[0; 12], b"cipher");
        blob.push(0);

        let err = Parts::of(&blob).expect_err("an appendage");
        assert!(err.to_string().contains("behind the last field"), "{err}");
    }

    #[test]
    fn a_nonce_of_the_wrong_length_is_refused() {
        let blob = envelope(seat(1), b"pub", b"priv", &[0; 11], b"cipher");
        let err = Parts::of(&blob).expect_err("a short nonce");

        assert!(err.to_string().contains("nonce"), "{err}");
    }

    #[test]
    fn a_seat_outside_the_group_is_refused() {
        let mut blob = Vec::from(MARK.as_slice());
        blob.extend_from_slice(&0_u16.to_be_bytes());
        for field in [b"pub".as_slice(), b"priv", &[0; 12], b"cipher"] {
            blob.extend_from_slice(&u32::try_from(field.len()).expect("short").to_be_bytes());
            blob.extend_from_slice(field);
        }

        assert!(Parts::of(&blob).is_err(), "seat 0 does not exist");
    }

    /// The way at the real device -- **no substitute, no simulator**.
    ///
    /// Skipped without a TPM, and that is no fail-soft here: the assertion applies
    /// to a kernel device, and a machine without this device can neither hold nor
    /// violate it.
    #[test]
    fn a_share_survives_the_round_trip_through_the_tpm() {
        if !TpmCustody::present() {
            eprintln!("no {} -- skipped", device());
            return;
        }

        let dir = tempfile::tempdir().expect("directory");
        let custody = TpmCustody::new(dir.path()).expect("custody");
        let share = a_share();

        let sealed = custody.seal(seat(1), &share).expect("seal");
        assert!(is_envelope(sealed.blob()), "no envelope");
        assert!(
            !sealed
                .blob()
                .windows(4)
                .any(|w| w == &share.serialize().expect("bytes")[..4]),
            "the share stands in the clear in the envelope"
        );

        let opened = custody.unseal(&sealed).expect("open");
        assert_eq!(
            opened.serialize().expect("bytes"),
            share.serialize().expect("bytes")
        );
    }

    /// An envelope of seat 1 must not open as seat 2.
    #[test]
    fn an_envelope_does_not_open_at_another_seat() {
        if !TpmCustody::present() {
            eprintln!("no {} -- skipped", device());
            return;
        }

        let dir = tempfile::tempdir().expect("directory");
        let custody = TpmCustody::new(dir.path()).expect("custody");
        let sealed = custody.seal(seat(1), &a_share()).expect("seal");

        let moved = SealedShare::new(seat(2), sealed.blob().to_vec());
        let err = custody.unseal(&moved).expect_err("a foreign seat");

        assert!(err.to_string().contains("seat"), "{err}");
    }

    /// The working directory gets `0700` **expressly** (ADR-0115), and not what the
    /// umask happens to leave over.
    #[test]
    fn the_work_directory_is_not_left_to_the_umask() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("directory");
        let custody = TpmCustody::new(dir.path()).expect("custody");
        let mode = std::fs::metadata(dir.path().join(".tpm"))
            .expect("read")
            .permissions()
            .mode();

        assert_eq!(mode & 0o777, 0o700);
        drop(custody);
    }
}
