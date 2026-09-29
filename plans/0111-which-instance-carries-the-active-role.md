# ADR-0111: Which Instance Carries the Active Role

- **Status:** accepted
- **Date:** 2026-09-10
- **Decider:** Dana Schlifka
- **Technical context:** `tg-consensus` (`command`, `state`), `tgd`
  (`scheduler`), `tg-model` (`lease`), `tg-store` (`session`), `tg-runtime`
  (`reconcile`), `tgctl`

## Context and Problem Statement

ADR-0064 built the active-role lease and recorded in determination 8: *"Only
`kind="singleWriter"`, only instance 0."* Since then the zero is the only place
that says **which** instance of a single writer may write — as a constant at
three places in the code, not as a fact in the log.

ADR-0011 excludes auto-rebalancing, ADR-0027 pins a single writer with a
writable volume to its node, and ADR-0019 wants workloads decoupled from the
control plane. Together that means: **if the holder fails, nobody takes over
automatically, and that is intended.** Redundancy is a declared replica that an
operator arms — an action, not an automatism.

Only this action does not exist. The lever is missing, and in its place stands
a command that would do exactly the wrong thing.

## Decision Drivers

- **ADR-0011** — declarative-explicit, no auto-rebalancing. A running instance
  is never moved by itself.
- **ADR-0027** — writable means node-pinned; HA runs via a replica with its
  **own** volume, never via volume migration. Moving the placement of instance
  0 would leave the data behind.
- **ADR-0057, determination 3** — a policy may only read inputs that a failure
  does not create. Silence is exactly what a failure produces; that is why
  auto-detach was permanently rejected.
- **ADR-0064** — the leader grants, the node learns; without a valid lease the
  active instance does not start up; the holder fences itself **before** the
  expiry.
- **ADR-0010** — the warm standby is a **running** instance; the doubled
  resources are the stated price.
- **ADR-0020** — the command set is retention-bound substrate. What stands in
  it stands forever; what nobody can issue stands there for nothing.

## Three measured findings

### The first: two commands without a producer

Of the 38 `Command` variants, two are **never constructed** in production code
— every other one has a producer in `tgctl` or `tgd`. They are `RevokeLease`
and `RegisterTrust`. No guard covers this: `command_set.rs` checks wire form,
inventory and the two ADR-0004 halves, none of them **producibility**.

That is the pattern from ADR-0044 — there a fully privileged port without a
client — and the lesson was the same: do not ask whether it is a nuisance, but
what it would do if someone connected a producer.

### The second: `RevokeLease` lifts the fence

Measured against the state machine, with a counter-check — only **one** thing
different:

| Sequence | Outcome | Holder afterwards |
|---|---|---|
| Grant `node-1` (valid until 15 000) → Grant `node-2` at t=1000 | `Rejected(LeaseHeld)` | `node-1` |
| Grant `node-1` → **`RevokeLease`** → Grant `node-2` at t=1000 | `LeaseGranted { epoch: 1 }` | `node-2` |

The fence in `grant_lease` reads the **presence** of a valid lease.
`RevokeLease` removes it without replacement, so the condition is empty
afterwards. The old holder, however, fences itself against its **local clock**
(ADR-0064 determination 7, ADR-0078) — it learns nothing of the revocation that
would make it stop earlier. Between the revocation and `expires_at`, two write.

The existing test `an_epoch_is_never_reused` does not hit the spot: it grants
to the **same** node after the revocation, and that is the case the comment in
`grant_lease` expressly names as harmless.

### The third: the state machine can already do the promotion — it just does not hold

Measured against two real nodes, instance 0 on `node-1`, replica 1 on `node-2`:

| Action | Outcome |
|---|---|
| `GrantLease` to `node-2` at t=1000 (old lease until 15 000) | `Rejected(LeaseHeld { holder: "node-1", epoch: 0 })` |
| `GrantLease` to `node-2` at t=15 000 | `LeaseGranted { epoch: 1 }`, holder `node-2` |
| Scheduler tick at t=16 000, both reporting | `[]` |
| Scheduler tick at t=31 000 | `[GrantLease { node: "node-1" }]` |

`grant_lease` checks class, node and fence — **not** whether the node carries
instance 0. A promotion is therefore already acceptable to the state machine
today. It just does not hold: the scheduler derives the holder from the
placement of instance 0, therefore never renews `node-2`, and takes the role
back to `node-1` after a deadline. **A promotion lives exactly one lease
period.**

The zero stands at three places and nowhere in the log:

| Place | Line |
|---|---|
| `tg_model::lease::role_of` | `if class != SingleWriter \|\| instance != 0` |
| `tgd::scheduler::leases` | `.find(\|(w, instance, _)\| *w == name && *instance == 0)` |
| `tg_runtime::reconcile::active` (metric) | `&& instance == 0` |

## Options Considered

- **A — Re-place instance 0.** "Arming" would mean shifting the placement of
  instance 0 to the other node. Rejected: ADR-0027 pins an instance with a
  writable volume, and moving its assignment would leave the data on the old
  node. That is exactly why ADR-0027 says "replica with its own volume".
- **B — The operator sets the lease themselves** (`tgctl` writes `GrantLease`).
  Rejected: measured, it lives one period, after which the scheduler takes the
  role back. The operator would have to renew themselves — a lease that hangs
  on a human cadence is none.
- **C — `RevokeLease` and grant anew.** Rejected: measured, the revocation
  lifts the fence. It only buys away the waiting time that is precisely the
  promise.
- **D — An automatism:** if the holder is silent long enough, the leader
  promotes the replica. Rejected: the input would be an **absence** (ADR-0057
  determination 3), and it would be auto-rebalancing through the back door
  (ADR-0011).
- **E — The active instance becomes a declared fact in the log**, set by a
  human; the leader derives the holder from its placement.

## Decision

Chosen: **Option E.**

1. **Which instance carries the active role stands in the log.** New command
   `SetActiveInstance { workload, instance }`. Without an entry, **instance 0**
   applies — for any existing cluster nothing changes thereby, and ADR-0064
   determination 8 becomes the default case rather than the only one.

   The reason that it belongs in the log and not in the declaration: it is
   desired state an operator changes during operation, and it must outlast a
   failure. A setting in the XML definition would only take effect at the next
   start (ADR-0070) — that is, precisely not when it is needed.

2. **Promoting is a human's action.** `may_be_policy()` returns **`false`** for
   this command, and that is not caution but ADR-0057 determination 3: the only
   input from which a program would want to derive a promotion is the holder's
   silence — and silence is what a failure produces. The same justification for
   which auto-detach is permanently rejected (ADR-0054, ADR-0057).

3. **The fence stays untouched.** The promotion grants **no** lease; it changes
   only from which placement the leader derives the holder. The next tick then
   grants — and `grant_lease` still rejects with `LeaseHeld` as long as the old
   lease is valid. The waiting time therefore remains, and it is exactly the
   period the cut-off holder needs to fence itself. **An operator can move the
   active role without being able to touch the fence.**

4. **`RevokeLease` is dropped.** It has no producer, and the only task it would
   have — putting the role somewhere else — is fulfilled by determination 1
   without giving up the promise. A command that lifts the fence is not one you
   keep for the day someone connects it.

   The objection from ADR-0020 — the command set is retention-bound, a removed
   command makes old entries unreadable — does **not** carry here: no path ever
   produced a `RevokeLease`, so no log can contain one. That is measured, not
   assumed.

5. **The active instance travels in the slice.** The node needs it to separate
   its two cases: the **designated active** does not start up without a lease
   (ADR-0064 determination 4), the **warm standby** always runs (ADR-0010).
   Today the zero separates them; in future the number from the log. `role_of`
   gets it as a parameter and no longer knows the zero.

   That is one field more in the `NodeSlice`, hence a format break — and per
   **ADR-0072** that goes bundled into the one window, together with the one
   from ADR-0086. Until then half of it stands alone in the state machine; what
   that means for the intermediate state stands in the consequences.

6. **An active instance that does not exist is rejected.** `instance >=
   replicas` is a rejection, and so is an `UpsertWorkload` that lowered
   `replicas` below the set active instance. The silent outcome would otherwise
   be the worst this system knows: the scheduler would find no placement for
   the active instance, would grant nobody a lease, and the workload would fall
   silent — without an error appearing anywhere. `RemoveWorkload` takes the
   entry with it, like lease, generation and edges.

7. **And a guard over producibility.** Every `Command` variant needs a producer
   in production code; a command only tests construct is a promise to nobody.
   The guard carries its exceptions **by name and with a reason** — after this
   ADR there is exactly one: `RegisterTrust`, whose decision is outstanding
   (see open points).

## Consequences

**Positive**

- An operator can arm a replica, and the result holds:
  `tgctl cluster promote <workload> <instance>`.
- The promise of the fence becomes **stronger**, not weaker: after dropping
  `RevokeLease` there is no way left in the whole command set to get rid of a
  valid lease prematurely. The only exit from a lease is its expiry.
- The role change stands in the audit trail with an actor (ADR-0050, ADR-0045)
  — "who switched production over" is the question an auditor asks.
- ADR-0064 determination 8 turns from a constant into a default. The sentence
  "only instance 0" stood at three places in the code and nowhere in the state;
  afterwards it stands at one.

**Negative / costs**

- **One command more in the retention-bound set** — with wire-form pin,
  inventory, class (`Write`, ADR-0105) and policy rule.
- **A format break on the slice**, which waits for the window from ADR-0072.
- **The intermediate state is unclean, and it is named.** As long as the active
  instance does not reach the node, `role_of` gives the displaced instance 0
  without a lease `Role::Wait`, and the reconcile skips it with `continue`: it
  is neither stopped nor restarted. It keeps running but does not serve (its
  sidecar gets no lease, ADR-0066) — and if it crashes, it does not start up
  again. After the window it is an ordinary warm standby.
- **Two truths about "who is active" during this window**: the leader knows it
  from the log, the node infers it from the zero. They agree as long as nobody
  promotes.

**Risks & open points**

- ~~**`RegisterTrust` is not decided.** It is the second command without a
  producer and a different topic: it writes `self.trust` **without** an
  invitation having been redeemed — that is, past the one-time,
  consensus-checked gate from ADR-0037. On top of that it requires
  `self.nodes.contains_key`, while `AdmitNode` enters trust precisely without
  this condition; the comment on `RotateTrust` invokes this condition as a
  reference point. As long as it has no producer it is unreachable; it remains
  the one named exception of the guard from determination 7.~~ — **done:**
  ADR-0112 — `RegisterTrust` becomes inert.
- **The guard reads source code.** It recognizes `Command::X { … }` as a
  construction and `Command::X { .. } =>` as a pattern. Whoever builds a
  variant via an intermediate value or a helper function gets past — the same
  concession as with the guard from ADR-0110.
- **A promotion during a partition takes effect with delay.** The new holder
  gets the lease only when it reports (ADR-0064 determination 2); the old one
  fences itself anyway. That is the promise and not a limitation — but an
  operator who issues the promotion and expects immediate effect sees nothing
  for up to one lease period.
- **Back is a second command**, not a fallback. There is deliberately no
  reversal by time: a returning node does not take over by itself, and the
  epoch is never reused (`next_epoch`; `renew_lease` rejects an expired lease
  with `LeaseExpired`). Whoever wants to go back promotes back.

## Related ADRs

- Depends on: **ADR-0064** (the lease; determination 8 becomes the default),
  **ADR-0011** (no auto-rebalancing), **ADR-0027** (replica with its own volume
  instead of volume migration)
- Applies: **ADR-0057** (what a policy may read — here: nothing), **ADR-0072**
  (the bundled format change), **ADR-0105** (command class), **ADR-0050** (the
  actor in the log)
- Changes: **ADR-0064, determination 8** — "only instance 0" is the default,
  no longer the rule
- Affects: **ADR-0066** (the sidecar enforces the active role locally —
  unchanged, it asks for the lease and not for the instance), **ADR-0010** (the
  warm standby), **ADR-0020** (one command arrives, one leaves)
