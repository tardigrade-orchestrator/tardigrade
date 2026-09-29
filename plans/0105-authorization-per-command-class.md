# ADR-0105: Authorization per Command Class

- **Status:** accepted
- **Date:** 2026-09-07
- **Deciders:** Architecture
- **Technical context:** `tgd::admin`, `tg-consensus::command`, `tgctl`

## Context and Problem Statement

Since **ADR-0103** there is a transport that authenticates an operator: the
operator port checks the SPKI against a registration in the log and the role
`operator` in the certificate. What it **cannot** do is distinguish —
measured, `may_administer` is the only check in the admin path, and `admitted`
returns `true` for every registered leaf. Whoever has the access may do
anything.

The same open question stands in **five** ADRs: 0044 ("authorization per
command class"), 0050 (determination 3), 0093, 0095 and 0103 (determination
6). Five times the same question is, in this tree, the sign that a decision is
due — that is how it was with ADR-0057 (three times "may a policy do that?"),
with ADR-0072 (twice "is that a format break?") and with ADR-0043 (four times
"who is my counterpart?").

## Decision Drivers

- **Least privilege applies to the credential, not to the human** (ADR-0017
  draws the same line for workloads).
- **The recovery path must not presuppose what it restores** (ADR-0043,
  ADR-0044).
- **A check one can forget is none** — this tree has measured five times what
  a hand-maintained list costs (`KINDS`, `samples()`, `invariants.rs`, the ADR
  table, the cadences).
- **The policy writes without an actor** (ADR-0057): a check in the state
  machine would break the path on which the leader computes decrees.
- **The log is retained** (ADR-0020): an old entry must continue to mean what
  it meant when it was written.

## The finding that makes the fixed split unsound

ADR-0044 laid down **three** classes: `read` (`Status`, `Projection`) ·
`write` (the command set) · `membership` (`AddLearner`, `ChangeMembership`).
That was coherent when it was written. Measured, it is no longer so, and for
two reasons:

**First: `write` is `admin`.** `EnrolOperator` and `RevokeOperator` entered
the command set with ADR-0103 — three ADRs later. `Write` accepts the
**whole** command set. So whoever holds `write` can register a second
credential with **any** class and revoke every other. A class boundary that
permits that is none.

**Second: the classes covered 4 of 11 calls.** The admin service had four
routes and has eleven. One of them is `RekeyMaterial`, and it hands out
**every ciphertext of every secret** (ADR-0100). It does not belong in `read`:
a credential for a dashboard would thereby hold the entire secret inventory.

**And the justification with which ADR-0103 deferred carries only half the
distance.** It read: *"a class needs a **second** operator to mean anything."*
For separation between two humans that is true. But it leaves out the case
that counts even with **one** human: a credential that may only read — a
monitoring node, a CI run, a dashboard. Today the only way to give them
`Status` is a credential that may also `DeleteVolume`.

## Options Considered

**Where is the check performed?**

- **P1 — In the state machine.** `apply` reads the actor and decides.
- **P2 — At the transport.** The admin service decides before it dispatches.
- **P3 — Both.**

**What does the class hang on?**

- **K1 — On the path.** Every route carries a class.
- **K2 — On the command.** Every variant carries a class.
- **K3 — On both**, depending on what carries the information.

**Where do an operator's classes stand?**

- **C1 — A field on `EnrolOperator`.** They are set at registration; changing
  means registering anew.
- **C2 — A command of its own** `SetOperatorClasses`.
- **C3 — A local file per node**, uid → classes (ADR-0050's H2).

## Decision

### 1. The check is performed at the **transport** (P2)

`apply` stays untouched. The reason is measured and not chosen: the capacity,
the rotation and the tombstone policies write **without** an actor (ADR-0049,
ADR-0057, ADR-0104). A check in the state machine would have to exempt them —
and an exemption in the state machine is one an attacker looks for.

Besides, the check is thereby where it stands **once**: the admin service
already has **one** gate for all eleven routes, with exactly this
justification in the code ("one that forgets it would be open without anyone
noticing").

### 2. The class hangs on the **path and on the command** (K3)

Not out of symmetry, but because the information is distributed differently:

- Ten of the eleven routes are a class in themselves — `Status` is always
  read, `Membership` always membership.
- **`Write` is not.** It takes the whole command set, and the class stands in
  the body. `EnrolOperator` and `DeleteVolume` come over the same path.

So: the path decides, and for `Write` `Command::class()` decides additionally
— an exhaustive `match` without a `_` arm. A new command no longer lets the
file compile until someone names its class. That is the only one of the two
levels the compiler can hold; for the paths a guard that reads the source will
do.

### 3. Five classes, and every boundary lies where the damage jumps

| Class | What it permits | Damage on misuse |
|---|---|---|
| `read` | `Status`, `Projection`, `Lints`, `Document`, `Settings`, `Trust`, `Volumes`, `Secrets` (names only) | disclosure of topology and definitions |
| `secrets` | `RekeyMaterial` | with the data key: **every** secret |
| `write` | the command set **without** operator administration | outage, data loss |
| `membership` | `Membership`, `SetVoters` | loss of the cluster |
| `operators` | `EnrolOperator`, `RevokeOperator` | all of that, **and** persistence |

`secrets` is a class of its own because the damage is of a different order of
magnitude than that of `read`. `operators` is one because otherwise `write`
contains all the others — the finding above.

### 4. The Unix socket keeps **all** classes

It is the way on which an operator gets a cluster going whose identities are
broken (ADR-0044, determination 4). Classifying it would mean making the
recovery path depend on what it restores — the same consideration from which
ADR-0043 keeps the Raft port's peer list local.

Whoever reaches the socket can stop the process and read the disk anyway. The
classes apply to the **operator port**.

### 5. The classes stand on `EnrolOperator` (C1)

That is how ADR-0050 decided it verbatim in H3: *"a command puts `name → spki
→ classes` into the log."* A second command (C2) would be a second fact about
the same operator in two places — and an operator without classes would need a
default that either grants everything (then `EnrolOperator` alone is a back
door) or nothing (then it is useless). A local file (C3) would be a
configuration per node for a cluster-wide fact — the error ADR-0069 measured
for the address plan.

Changing classes means **registering anew**. That is also the rotation path
(ADR-0103: "registering anew replaces").

### 6. An old entry keeps its meaning: **all** classes

`#[serde(default)]` on the field, and the default is the **full** set. That is
not negligence but fidelity to the log: an `EnrolOperator` written before this
ADR **meant** "may do anything" — that was the semantics of that entry, and a
state machine that reads it differently today rewrites the past.

The direction is thus the reverse of that for `capacity` (ADR-0067: "an old
node has no capacity and may not invent any") — and for the same reason: **the
default must mean what the entry meant.**

The price stands in the consequences: an operator who upgrades has no
restriction until they register anew. Hence determination 7.

### 7. There is a read path, and it names the classes

`tgctl operator list` — measured, there was **no** way to see who is
registered. With classes it is not optional: a distribution of rights that one
cannot enumerate is one that one cannot audit (ADR-0020). For an operator with
the full set, the output says expressly that they **may** date from before
this ADR.

## Consequences

**Positive**

- A credential that may only read is possible — with **one** human.
- `write` no longer contains the authority to extend itself.
- The secret inventory no longer hangs on a read permission.
- A new command cannot forget its class (compiler).
- Five ADRs lose their shared open point.

**Negative / costs**

- **A format growth on the command set.** `Command` carries
  `deny_unknown_fields`; an old reader rejects the entry. For commands that is
  intended (`unknown_commands_are_rejected`: whoever half-understands a
  command drifts) and belongs in the same coordinated window as the others
  (ADR-0072, determination 3).
- **Existing registrations stay unrestricted** until someone renews them.
  Visible via `tgctl operator list`, and named in the manual.
- **Two levels of checking** (path and command), so two places at which a new
  route or a new command must be classified. For commands the compiler holds
  it, for routes a guard — not the same strength.
- **The socket stays unclassified.** Whoever reaches it may do anything; that
  is determination 4 and cannot be healed without losing the recovery path.

## Related ADRs

- **ADR-0044** — lays down role and classes and leaves them unbuilt; this ADR
  **changes its split**: `write` loses operator administration, and `secrets`
  is added.
- **ADR-0050** — determinations 1 and 3; C1 follows its H3 verbatim.
- **ADR-0103** — the transport, and determination 6, which is answered here.
- **ADR-0057** — the reason for P2: a policy writes without an actor.
- **ADR-0020** — the reason for determinations 6 and 7.
- **ADR-0100** — `RekeyMaterial`, the reason for the class `secrets`.
