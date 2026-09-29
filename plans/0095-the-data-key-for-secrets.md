# ADR-0095: The data key for secrets at rest

- **Status:** accepted
- **Date:** 2026-09-06
- **Deciders:** Dana Schlifka
- **Technical context:** `tg-identity`, `tgd::identity`, `tg-agent::join`, `tgctl`

## Context and Problem Statement

ADR-0016 is `accepted` and **not built**. It requires a secret's value to lie in the
store as **ciphertext**, encrypted "with a key from the threshold/air-gapped trust or a
KMS (ADR-0014)".

**Measured, that key does not exist, and it cannot be produced from what is there:**

| Candidate | Finding |
|---|---|
| the FROST group (ADR-0014) | a **signature** group (Ed25519). `frost-ed25519` knows no threshold decryption |
| its custody seams | `ShareCustody`, `PlainCustody`, `SignerLink`, `ThresholdSigner` — **zero** callers in all four binaries |
| a KMS | does not exist |
| any AEAD use in the tree | **none** except the fixed QUIC initial keys (ADR-0092) |

ADR-0016 is therefore not merely unbuilt but **blocked** — and with it everything that
hangs on it: the at-rest encryption of the volumes (ADR-0027) and the **registry
credentials** (ADR-0003). The last is a functional hole: an image from a private
registry cannot be pulled today.

Plaintext in the log is no way out. The log is **retained** (ADR-0020); a secret in it
would be a bearer secret with a retention period — exactly the reason only the **hash**
of an invitation stands in the log (ADR-0037).

## Decision Drivers

- **Self-contained** (ADR-0002): no foreign daemon in a secret's path.
- **Zero new crates without a reason** (ADR-0023). Measured, `x25519-dalek` (through
  ADR-0039) and `ring` (through `rustls`/`rcgen`) have long been in the tree.
- **The log is retention-obliged** (ADR-0020) — what lies there lies there forever.
- **Static stability** (ADR-0019): delivery must not become a runtime dependency of the
  workloads.
- **A new node has to be able to read what is already there.** ADR-0031 explicitly
  foresees rolling replacement; a ceremony per node change would be an operational
  burden nobody plans for.
- **No second custody model without a reason.** Every private key of this system today
  lies in the clear in `<data-dir>/identity/`, `0600` in a `0700` directory (ADR-0017):
  `node.key.pem`, `intermediate.pem`, `underlay.key`.

## Options Considered

- **Option A — threshold decryption from the FROST group.**
- **Option B — a cluster-wide symmetric key **in the log**.**
- **Option C — an envelope per node:** an X25519 recipient key per node, and `PutSecret`
  carries a sealed copy per node.
- **Option D — an external KMS.**
- **Option E — a cluster-wide data key, delivered on the credential path and held in
  `identity/`.**

## Decision

Chosen: **Option E.**

**The credential path already delivers private key material** — measured:
`Credentials::Issued` carries `intermediate_pem`, the private key of the agent
intermediate, over an mTLS-secured connection to an authenticated node (ADR-0037,
ADR-0043), and `join::store` stores it with `0600`. Sending a symmetric data key the
same way moves **no** trust boundary; it uses one that exists.

**Option A is measured out**, not weighed: FROST signs. A threshold decryption would be
a different procedure (ElGamal/ECIES), with a ceremony of its own, crates of its own and
a group of its own — ADR-0014 explicitly decoupled the signing group from the Raft
membership, a decryption group would be a third set of seats.

**Option B is absurd** and stands here only so that nobody later takes it for obvious:
the log is what is to be protected.

**Option C is the technically finer one and fails on operations.** It works with what is
there and has a price that is not tenable: a **newly admitted node cannot read anything
set before it**. Every node change would therefore be a re-encryption of **every**
secret — and that requires the plaintext only a human has. A join (ADR-0037: "only
trust, no capacity") would become a ceremony.

**Option D contradicts ADR-0002** and puts a foreign component into the path of every
secret — concentration risk per ADR-0023, and in an environment with 4-9 to 5-9 a
dependency nobody controls.

### Determination 1 — one key per cluster, and **never** in the log

It lives in N copies on N disks. In the log lies ciphertext exclusively.

### Determination 2 — two paths, and the difference is measured

**An agent gets it on the join and renew path** (ADR-0037, ADR-0042) — i.e.
**level-driven** (ADR-0010) and not as an event: a node that has lost it gets it back at
the next renewal, and a newly admitted one on joining. With that there is no ceremony
and no re-encryption.

**A `tgd` instance gets it from an operator**, like every other file in `identity/`
that does not arise locally. That stands here because the first draft of this
determination had overlooked it and it came to light while scoping the build: `tgd`
instances do not **join** one another over the credential path — that carries agents.
They are admitted through the Raft membership, and there the key must not travel
(determination 1: never in the log).

**Every** one of them has to hold it nevertheless: only the leader issues (ADR-0077),
and leadership moves. `tgd` never has to decrypt in doing so — `tgctl` seals
(determination 4), the agent opens; `tgd` only passes on.

That an operator puts a **secret** into a data directory is not new in this:
`identity/join-token` is exactly that, since ADR-0037. The manual step belongs in the
operations manual, next to the peer leaves (ADR-0043).

### Determination 3 — AEAD with `ring`, a nonce per value, the nonce beside the ciphertext

Sealing uses `ring::aead` (ChaCha20-Poly1305), the nonce arises from `OsRng` **at
encryption time** and stands next to the ciphertext. Letting it arise at the caller
would be the construction ADR-0014 explicitly rejected for FROST: a nonce used twice
under the same key gives away the plaintext — and the discipline belongs in the
**structure**, not in diligence.

### Determination 4 — `tgctl` encrypts, not `tgd`

The plaintext never reaches the control plane. `tgctl` runs on a node and reads the key
from `<data-dir>/identity/`, as it already finds the admin socket there (ADR-0044) —
which presupposes anyway that whoever reaches it can read the disk.

### Determination 5 — what it protects, and what not

**Protected** is a log or a backup that **leaves** the cluster: the at-rest threat that
ADR-0020's retention obligation creates in the first place. Whoever reads a segment from
the WORM archive gets ciphertext.

**Not protected** is a compromised node. It has to be able to give the plaintext to its
workload — that is not a gap in the procedure but the boundary of the model from
ADR-0016, and it holds for each of the five options.

### Determination 6 — the key is backup material

If **all** nodes lose their disk, all secrets are lost. It belongs backed up like the CA
root (ADR-0014) — operational work, and it stands in the manual instead of in a note.

## Consequences

**Positive**

- ADR-0016 is unblocked, and with it the registry credentials (ADR-0003) and the
  at-rest encryption of the volumes (ADR-0027).
- **Zero new crates**: `ring` lies in `tg-identity`, `tgd` and `tg-proxy`.
- No second custody model: the same place, the same permissions, the same backup
  obligation as for every other key of this system.
- A node change stays a node change.

**Negative**

- **One key for everything.** Whoever has it has every secret — there is no per-workload
  separation at the crypto level. The separation lies in the policy (ADR-0016: deny by
  default like `may_talk`), i.e. in enforcement and not in mathematics.
- **Rotation is a cluster event** and requires setting every value anew. The generation
  machinery from ADR-0055 fits for it, but the re-encryption needs the plaintext and
  therefore a human. **Not decided and not built.**
- **The plaintext lies briefly in `tgctl`** and therefore in the memory of a process on
  a node. Unavoidable: it has to arise somewhere.
- **An operator can read the key.** Whoever reaches the admin socket may do everything
  anyway (ADR-0044) — but it is an extension of what "everything" means.

## Risks & Open Points

- **Rotation** (see above). It is the only determination of ADR-0016 this ADR does not
  reach.
- **Who may set a secret** stays the same question as in ADR-0044: whoever reaches the
  socket may do everything.
- **The key travels on every renewal** over the credential path — every three hours, per
  node. That is more opportunity than a one-off delivery; it is carried by mTLS
  (ADR-0043) and by the fact that the same path carries private key material anyway.
- **A node taken out of the cluster keeps it.** `RemoveNode` takes trust and ordinal,
  not the disk — the same situation as with the node key, and the answer is the same:
  the disk belongs wiped.
- **Two `tgd` instances with different keys do not stand out.** One passes a different
  key to its agents than the other, and what one sealed nobody opens afterwards. It
  would be visible in a metric over the number of distinct keys — the same construction
  as with `tg_cluster_proxy_images` (ADR-0059) and `tg_cluster_dns_zones`. **Not
  built**, and the first person who forgets the manual distribution will need it.

## Related ADRs

- **Changes ADR-0016** — its sentence "with a key from the threshold/air-gapped trust or
  a KMS (ADR-0014)". Everything else about it stays.
- **Applies: ADR-0037/ADR-0042** (the credential path carries it), **ADR-0043** (the
  transport), **ADR-0017** (the permissions on disk), **ADR-0023** (zero new crates).
- **Does not touch ADR-0014:** the root stays in the HSM, the shares stay TPM-sealed.
  This is **not** the CA key, and it is explicitly a different procedure with a
  different purpose.
- **A precondition for ADR-0016**, and thereby for the registry credentials (ADR-0003)
  and the at-rest encryption of the volumes (ADR-0027).
