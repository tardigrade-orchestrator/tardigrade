# ADR-0140: The Share That Does Not Fit Into the TPM

- **Status:** accepted
- **Date:** 2026-09-14
- **Decider:** Dana Schlifka
- **Technical context:** `tg-identity` (`threshold::custody`, `secrets`), `tgd`,
  operational prerequisites

## Context and Problem Statement

ADR-0014 sub-decision 2 decided: **root in the HSM, runtime shares TPM-sealed,
per node.** Of that, only the **seam** has been built since phase 7b —
`ShareCustody`, a trait with two methods, and behind it `PlainCustody`, which
carries in its name that it is not the model. `custody.rs` says so itself:

> a trait with two methods, behind which a TPM steps without a single line of
> the signature path being different.

The blocker was the hardware; it is gone. What is missing is the decision: **by
which way, bound to which state, and what the case costs in which the sealing no
longer opens.** ADR-0014 names only the goal.

## Decision Drivers

- **ADR-0014, sub-decision 2** — the mandate. And the justification `custody.rs`
  draws from it: *"an HSM per node would have put the PKCS#11 FFI into the
  runtime path of **every** control-plane node."*
- **The protection goal, verbatim from `custody.rs`** — the share lies in memory
  only as long as a signature takes, and **never unsealed on disk**.
- **ADR-0019** — availability must not hang on a fragile component. A node that
  no longer signs after a firmware update is the inversion of the keystone.
- **ADR-0038 / ADR-0039 / ADR-0113** — the cheapest boundary to a foreign tool:
  it is **called**, not linked.
- **ADR-0108** — RTS replaces a lost seat **without a ceremony**. That is the
  reason why a lost share is bearable.
- **ADR-0031 / ADR-0014** — five seats, t = 3. What is dangerous is never the
  first loss but the third.
- **ADR-0115** — *"a MAC over the entries is rejected: whoever can write them is
  root."* The same trade-off, the same directory.

## The measured state

Everything here is measured on **this** TPM (TPM 2.0, `/dev/tpmrm0`, tpm2-tools
5.7, tpm2-tss 4.1.3), not taken from the specification.

| | |
|---|---|
| `KeyPackage::serialize()`, FROST 3.0.0 | **134 B** |
| `tpm2_create -i` | 128 B **OK**, 256 B **FAIL** |
| `tpm2_createprimary -C o` | 0.127 s, **produced identically twice** — and the second opens the first's blob |
| `tpm2_create` (seal, via stdin) | 0.125 s |
| `tpm2_load` + `tpm2_unseal` | 0.376 s |
| The blob on disk | `.pub` 48 B, `.priv` 160 B |
| `ring::aead` ChaCha20-Poly1305 | lies in `tg-identity/src/secrets.rs`, `KEY_LEN = 32` — **zero new crates** |
| `tss-esapi` 7.7.0 | Apache-2.0, **+39 crates**, requires `tss2-sys.pc` as a **build** condition (not installed here: `cargo build` aborts); 8.x is alpha |
| `tpm2-tools` / `tpm2-tss` | BSD-3 / BSD-2 — **no** licence collision, unlike nftables (ADR-0038) and WireGuard (ADR-0039) |
| The data key from ADR-0095 | **optional** — `load_data_key` returns `None`: *"no data key — on this cluster there are no secrets"* |
| `SIGNER_SEATS` | counts leaves under `signers/`, that is, **whom the node believes** — not what it can open |

The first row against the second decides the construction, and the difference is
**six bytes**: the share around which the seam, by its own documentation, sits
*"deliberately"* does not fit into the sensitive area of a TPM object.

## Options Considered

**How the share gets in:**

- **A — direct sealing.** Barred, measured: 134 > 128.
- **B — seal only `signing_share`** (32 B) and put the public remainder beside
  it. Fits, but turns `SealedShare` into a struct with public fields instead of
  an opaque block — and the seam would have to know the decomposition of a FROST
  type.
- **C — envelope.** A 32 B key is sealed, the share encrypted with it. The seam
  stays byte for byte as it is.

**The way to the TPM:**

- **D — `tss-esapi`.** C FFI, +39 crates, and `tpm2-tss-devel` becomes a **build
  condition of the workspace**: whoever builds only `tgctl` needs the C library.
- **E — `tpm2_*` as its own process.** Zero crates, an operational prerequisite
  like `nft`, `cryptsetup`, `losetup`, youki.

**Bound to what:**

- **F — PCR policy.** Additionally catches the attacker who boots the machine
  with a foreign kernel.
- **G — no policy.** Binding to this TPM alone.

**The auth value:**

- **H — derived from the data key**, as ADR-0113 does the LUKS passphrase.
- **I — a file of its own** in `signing/`.
- **J — empty.**

## Decision

Chosen: **C, E, G, J**, and in addition five determinations that make the
residual case cheap and visible.

### Determination 1 — envelope, not direct sealing

A 32-byte key is sealed in the TPM; the share thereby lies encrypted on disk.
The procedure is **ChaCha20-Poly1305 from `ring::aead`** — the same one
`secrets.rs` has used since ADR-0095, hence zero new crates and no second crypto
procedure in the tree.

**`DataKey` from ADR-0095 is not reused in the process, only its procedure.**
The data key is cluster-wide and delivered on the credential path; the envelope
key is per node and never leaves the TPM. Taking the same type would be the
pitfall from 9d in a new form, and the rotation from ADR-0100 would drag along
shares that have nothing to do with it. `secrets.rs` states the difference
itself: *"this is a different procedure with a different purpose."*

`SealedShare` stays unchanged — an opaque block that belongs to exactly one
seat. Not a line of the signature path changes, exactly as the seam promised.

### Determination 2 — `tpm2_*` as its own process

The same relationship ADR-0003 has to youki, ADR-0038 to `nft` and ADR-0113 to
`cryptsetup`. **Here, exceptionally, the licence decides nothing** — both ways
are permissive — but the build and operating boundary does: the FFI way makes
`tpm2-tss-devel` a prerequisite for building the whole workspace at all, and
puts a second C FFI into the runtime path of every control-plane node — exactly
what ADR-0014 wanted to avoid with the choice of TPM over HSM.

The secret goes in via **stdin** and out via **stdout**, never via argv — the
same discipline as the LUKS passphrase in ADR-0113.

### Determination 3 — the primary is derived, not persisted

`tpm2_createprimary -C o` is measured to be deterministic: produced twice it
yields the same key, and the second opens the first's blob. That makes
`tpm2_evictcontrol` unnecessary, **no NV slot is consumed**, and the node need
remember nothing except two files of 208 bytes in total.

### Determination 4 — no PCR policy

The price is substantiated on the real TPM rather than claimed — seal to a
policy, then extend the PCR, as a firmware update does:

```text
-- unseal before the change --  OK
-- extend PCR 16 --
-- unseal afterwards --         FAIL — the share is gone
```

What the policy buys is an attacker with physical access who boots the machine
with a foreign kernel. What it costs comes by itself: firmware, bootloader and
secure-boot databases are updated, mostly without anyone's involvement, and each
of those turns a healthy node into an RTS case. At five seats with t = 3 an
fwupd update rolling across the control plane is exactly the procedure that hits
three in one maintenance window — then the CA has not failed but is **gone**, and
only the ceremony with the air-gapped root helps.

Against root on the running machine the policy does not help anyway: root calls
`unseal`, and the TPM is satisfied, because the PCRs do match. This project has
made the same argument three times — ADR-0044, ADR-0081, ADR-0115.

What remains **without** a policy is exactly the protection goal from
`custody.rs`: the blob is bound to this TPM. A copied disk, a backup, a VM
snapshot do not yield the share, and not even root can lift that — the TPM does
not export the seed.

### Determination 5 — no auth value

Not forgotten but decided: **every available source lies beside the blob.**

The data key is measured out — it is **optional** (ADR-0095), and a cluster
without secrets has none. If the share hung on it, such a cluster could no longer
issue SVIDs: the CA would depend on a file that need not exist on the normal
path.

A password file of its own would lie in `signing/` beside `share` (ADR-0097
determination 3), both `0700 root` (ADR-0115). Whoever can read the blob thereby
reads the password too; whoever cannot read it does not need it. The auth value
protects only if it comes from elsewhere — and "elsewhere" would mean here: a
human types it at startup, whereby no node starts unattended any more
(ADR-0019).

Retrofitting later costs a `-p` in two calls and breaks no format.

### Determination 6 — the share is opened at startup

Not only at the first signature. Otherwise a TPM problem stands out while a
workload needs an SVID, and looks to the caller like a CA outage. At startup it
is a log line and **not ready** (ADR-0015): the node takes on no work it cannot
do.

That is at the same time the self-test against the only real residual worry of
the process way — a `tpm2-tools` update that changes the calls then stands out at
startup instead of weeks later.

### Determination 7 — no silent fallback to `PlainCustody`

If the TPM does not answer, the seat stays silent; the share is **not** written
back in plaintext. The same construction as ADR-0113 and ADR-0090: an escape
that switches off the safeguard is taken — and the failure would be mute. A
`tgd` without a seat runs on; a `tgd` that cannot open its seat does not fill it
unsealed as a substitute.

### Determination 8 — one metric, and the alert stands at t + 1

What is counted is how many seats actually **could open** their share.
`SIGNER_SEATS` does not answer that — it counts leaves under `signers/`, that
is, whom the node believes.

The alert stands at **t + 1**, not at t. At t the CA is still there, but the next
failure costs it; an alert that fires only then reports a state from which only
the ceremony leads out. Direction and `for:` duration belong in
`docs/alerts.yml`, the threshold is a number per installation.

### Determination 9 — change over with a counter-check

On switching from `PlainCustody` to the TPM: seal, **open again immediately,
compare with the original**, and only then replace the plaintext. A TPM that
seals and does not open would otherwise be the moment in which all five seats
disappear at once.

## What the build produced

Five findings, all measured, and the first changed the scope.

### The seam did not sit at the disk

`ShareCustody` stands between `Participant` and the signing — that is, in
**memory**. To disk writes `Material::save`, and that knew no custody:

```rust
let share_bytes = share.serialize()…;
write(&share_path_at(data_dir, epoch), &share_bytes, 0o600)?;
```

With that the second half-sentence in `custody.rs`'s documentation — *"and never
stands unsealed on disk"* — was already false before this ADR, and a mere
exchange of `PlainCustody` for `TpmCustody` would not have redeemed it.
`Material` therefore now goes through the custody; `save` seals, `load` reads
**both forms**, and the marker distinguishes them.

What the seam achieves in memory stays right and is the first half-sentence: the
plaintext lies there only as long as a signature takes (core dump, swap,
`/proc/pid/mem`).

### The seat stands in the envelope

The envelope's AAD is the seat — otherwise a share from seat 1 would open at
seat 2 as well. That means the seat must be readable **before** opening: the
disk does not know it, it has only bytes, and in the share it stands only
afterwards. It therefore lies behind the marker in plaintext (2 bytes), and
`unseal` checks it against the expected one. The AEAD would trip over it anyway,
but then the finding would read "does not belong to this key", and an operator
would look at the TPM instead of at the directory.

### The ceremony writes plaintext, and that is as it should be

`cargo xtask threshold` runs on **one** machine and produces shares for **five**
nodes. Sealing them there would mean that no other node could ever open its own
— the device binding is the purpose.

The share therefore leaves the ceremony open, is transported, and **every node
seals it itself at first startup** (`Material::adopt`). The window between the
ceremony and the first start is unavoidable and was always there; what is new is
that it **ends**.

### The TPM is a serial device for the whole machine

Measured on the signing group's test harness: `cargo test` runs the test
binaries concurrently, and nine witnesses each start five `tgd` processes.
Forty-five processes at one TPM — **eight of nine fell over**, serially the same
nine are green (67 s). The same finding as with the telemetry port in 11b and the
bridge address in 10a.

The answer is the same as there — the test gets its own situation — and it is a
**device path, not a switch**: `TG_TPM_DEVICE` names a device. If it points into
the void, the situation is the same as on a machine without a TPM, with the same
warning. "Sealing off" would be a setting somebody sets in production and nobody
sees any more — the construction that ADR-0017, ADR-0090 and ADR-0113 reject.

For operations it means: `tgd` and a concurrently running `tgctl signer repair`
(ADR-0108) share the device. Within a process a `Mutex` serializes, between
processes the kernel resource manager (`/dev/tpmrm0`, not `tpm0`).

### The working directory lies under `signing/`

`tpm2_load` needs `.pub` and `.priv` as **files**, so there is
`<data-dir>/signing/.tpm/` with `0700`. No secret lies in it — the primary
context is a handle, the two object files are the sealed material, and the key
goes via stdin and stdout. It is an extension of what ADR-0097 determination 3
enumerates under `signing/`, and it stands here so that it is not read as drift.

## Consequences

**Positive**

- ADR-0014 sub-decision 2 is redeemed instead of deferred; `PlainCustody`
  remains what it was built for — the path without a TPM.
- **Zero new crates.** The procedure lies in `secrets.rs`, the tool is a
  process.
- A host update is without consequence. Kernel, UEFI, GRUB, shim, `dbx`,
  packages: the TPM still measures into the PCRs, but nobody reads them.
- The share never stands unsealed on disk, and a disk that leaves the node does
  not yield it.

**Negative / costs**

- **`tpm2-tools` becomes an operational prerequisite** of a node that holds a
  signer seat — like `nft`, `cryptsetup` and the OCI runtime.
- An opening costs ~0.5 s. That lies on the minting path, not in the hot path of
  workload communication (invariant 4), and determination 6 moves it into the
  start.
- Three events still cost the share, and none of them is an update: **TPM clear**
  (a BIOS option, also as a side effect of a firmware *reset*), **mainboard
  replacement**, and a **VM restore without the vTPM state**.
- The protection against a compromised node does not grow. Nor should it: root
  reads the agent intermediate from disk anyway (ADR-0044, ADR-0081).

**For the operations manual** — two lines nobody otherwise suspects:

- The **vTPM state belongs in the backup** of a control-plane VM. A restore
  without it restores the node and not its seat.
- **"Clear TPM" is an RTS case**, not a restart.
- The RTS procedure (ADR-0108, `threshold/repair.rs`) belongs in the manual as a
  walked-through procedure, not as a reference to a function. It is the reason
  why this risk is bearable: **share gone does not mean CA gone**, it means one
  seat must be refilled — without a ceremony and without the root.

**Risks & open points**

- **The threshold of the alert rule** is a number per installation, like
  `RTT(p99)` in ADR-0033.
- **The root in the HSM stays outside this codebase** (ADR-0014: offline path).
  This ADR concerns exclusively the runtime shares.
- **A `tpm2-tools` major change** can alter the calls. Determination 6 turns
  that into a startup error instead of a late outage, but it remains a foreign
  interface without a stability promise — the same situation as with `nft`
  (ADR-0038), where `socket cgroupv2` is measured to be printed and not accepted
  back.

## Related ADRs

- Depends on: ADR-0014 (the mandate), ADR-0095 (the AEAD procedure), ADR-0097
  (the storage place of the share), ADR-0108 (RTS as the recovery path)
- Follows the pattern of: ADR-0003, ADR-0038, ADR-0039, ADR-0113 (a tool is
  called, not linked), ADR-0115 (whoever can read them is root)
- Affects: ADR-0015 (a metric and an alert rule), ADR-0019 (the startup path of
  a signer node)
