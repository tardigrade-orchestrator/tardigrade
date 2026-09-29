# ADR-0080: The readiness of a workload

- **Status:** accepted
- **Date:** 2026-09-04
- **Deciders:** Architecture (Dana Schlifka), Claude Code
- **Technical context:** `tg-net::discovery`, `tg-runtime::reconcile`,
  `tg-agent::network`, `schema/workload.xsd`, ADR-0015, ADR-0013, ADR-0009,
  ADR-0010, ADR-0057, ADR-0060, ADR-0061, ADR-0064, ADR-0070

## Context and Problem Statement

ADR-0015 decides verbatim:

> **Probes:** liveness/readiness/health per workload and per system component.

The second half is built (phase 11b: `probes`, `serve`, liveness and readiness for
`tgd`, `tg-agent` and `tg-proxy`). The **first** is an accepted, unimplemented
decision — and the difference directs work: an open question waits for an ADR, an
unimplemented decision waits for code.

**Measured, "healthy" per workload today means "the container runs."** There is
exactly one source — `ActualStatus::Running` in the node's projection — and it feeds
three consumers:

| Who reads it | What it concludes | What is wrong |
|---|---|---|
| the resolver (ADR-0013) | the address is resolved | a **mute** endpoint is offered |
| the dependency gate (ADR-0061) | a `requires` edge is satisfied | a dependent starts against a target that does not serve |
| the active-role lease (ADR-0064) | the holder reports, so renewal happens | a warm standby does not take over |

ADR-0013 names a mitigation — "client retry and the mTLS handshake catch the rest" —
and it holds for a **dead** endpoint: there an `RST` comes at once. For a process
that runs and does not (any longer) serve its port, nothing comes, and the client
waits into its deadline.

The most frequent case is not the outage but the **start-up**: ADR-0009 orders the
**start** with `After`/`Before`, not readiness, and a dependent legitimately started
per ADR-0061 finds its target starting up. The linter has warned about `Requires`
without `After` since phase 3 — about `After` without readiness nobody warns, because
there is no concept for it.

## Decision

### Determination 1: Readiness is an axis of its own

No fifth `ActualStatus` and no fourth `InstanceState`. The type answers the question
*does it run*; *does it serve* is another.

That is not taste but the finding from ADR-0070: `untouched` feeds four consumers,
and a bucket of its own would have taken the instance out of DNS **and** out of the
report. Here it would be the same — an instance that runs and does not serve has to
keep being reported as `Running`, otherwise the leader reads "never seen" instead of
"stands still", and the reaper (ADR-0058) would have one instance fewer among the
wanted.

An unready instance therefore stands in **both** lists: as `Running` and as unready.

### Determination 2: The probe is a TCP connect to a declared port

`<readiness port="…"/>` in the definition, modelled on `<mesh>`: the element is at
the same time the opt-in, and the port is the only statement.

Rejected:

- **An HTTP GET on a path.** It requires a client in the agent, a second path in the
  definition and a decision about TLS — and that is not harmless: a third-party image
  binds its port in the clear, because the sidecar terminates (ADR-0007). An HTTP
  probe would therefore have to know whether to speak plaintext or TLS, and that
  depends on whether `<mesh>` is declared. Deferrable and deferred.
- **`exec` in the container.** A privileged process starting a program in a container
  is a decision about ADR-0017 (the privilege model) and not about readiness.

What a TCP connect **cannot** do stands in the costs: a server that listens and
answers `500` counts as ready. It separates "binds" from "does not bind", and that is
exactly the start-up case.

### Determination 3: It runs in the instance's namespace, over loopback

Both are measured, not chosen.

**From outside it does not work.** After the mesh redirect (ADR-0060) a connect to
the container's address lands at the **sidecar** — so the probe would measure the
sidecar and not the workload. And the sidecar refuses without the active role
(ADR-0066): a warm standby would appear permanently unready although there is nothing
wrong with it.

**In the namespace over loopback it does work**, and the reason is a kernel property
that stood nowhere until now: `prerouting` does **not** fire on loopback. Measured
against a namespace whose `prerouting` chain redirects *all* TCP to 15006:

```text
connect 127.0.0.1:8080 -> WORKLOAD
```

On this property also rests the sidecar's way to its workload — the inbound chain has
no loopback exception because it **needs** none. It belongs in the tree as a note and
as a witness, otherwise somebody will take it for an oversight on the next reading.

The probe therefore lies in `tg_net::probe` and not in the agent: it is network
knowledge, and the place decides its witness — in the agent it would be
`pub(crate)`, and a harness would have to rebuild its two lines. Two versions are two
opportunities to make them differently strict.

The separate thread that `setns` requires comes by construction:
`tg_syscall::netns::run_in` creates it itself (the finding from 9d —
`Runtime::block_on` panics inside a running runtime).

### Determination 4: Once per reconcile pass, without a period and without a counter

No `period` setting: the reconciliation has a cadence, and a second one would be a
second source for the same question.

No threshold (`failures="3"`): it would require a counter per instance, i.e.
remembered state that a restart loses — edge-driven, against ADR-0010. ADR-0061 gave
the same answer for damping: "a crash that the same pass fixes never counts as a
trigger in the first place."

The result **is** the state. What that costs stands in the consequences.

The connect's deadline is a constant in the code with its justification next to it,
not an operator setting — like `HANDSHAKE_TIMEOUT` (ADR-0007) and the DNS forwarding
deadline (ADR-0041). A connect on loopback answers in microseconds or not at all.

### Determination 5: Without a declared probe a running instance is ready

The default, and explicitly so: anything else would mean every existing definition
falls out of resolution with this cut.

And "no probe declared" is to be distinguished from "probe failed" — the absence of
an entry against an entry with `false`. The same distinction as with
`tg_node_last_report_timestamp_seconds` (ADR-0057) and with the missing time in the
audit digest (phase 11a).

### Determination 6: The effect is resolution — no more

An unready instance is **not resolved** (ADR-0013: only healthy endpoints). That is
the entire effect of this cut.

Explicitly **not**:

- **No restart.** See determination 7.
- **The dependency gate** (ADR-0061) still counts "runs" as active. Switching it to
  this is the obvious continuation and a decision of its own: it holds a dependent
  back, and a misjudgement by the probe then costs a second workload.
- **The active-role lease** (ADR-0064) still hangs on the report. Binding it to the
  probe would mean that a false-negative probe takes a healthy single writer's role
  away — and the standby takes over. That is the most dangerous coupling of all and
  belongs in an ADR of its own.

### Determination 7: No restart on a failed probe

The decision that weighs most, and it goes against the habit of other orchestrators.

Three reasons, and the third is the load-bearing one:

1. **It would be an autonomous action**, and ADR-0010 section 3 enumerates them. A
   restart on an observation would not be on it.
2. **The input would be an absence.** ADR-0057's rule — "a policy may only read
   inputs that an outage does not produce" — is formulated for cluster policies, but
   its reason holds here just as much: an overloaded workload does not answer, and a
   restart makes the overload worse. That is the death spiral in which a probe turns
   a load problem into an outage.
3. **The trigger already exists.** ADR-0071 built `RestartWorkload`, including
   `tgctl cluster restart` and a generation in the log. A human who sees
   `tg_workload_ready 0` has the tool — and afterwards the audit trail says **who**
   restarted (ADR-0050). An autonomous restart would leave nothing there.

The substitute for the autonomous restart is therefore the same as three times
before (ADR-0054 auto-detach, ADR-0057 rotation, ADR-0070 a stale instance):
**visibility**, and a human decides.

### Determination 8: Readiness is node-local until it travels

The resolver is node-local, so this cut needs no path to the leader. That a
**foreign** node does not offer a mute endpoint requires a field in the report
(`RemoteEndpoint.healthy` has existed since ADR-0073, its source today is `states`) —
and that is a format break (ADR-0072) belonging bundled into the same window.

Until then: a node does not resolve its **own** unready instances, and the foreign
ones by the old criterion. That is an honest subset and not a false statement.

## Consequences

**Positive:**

- The start-up case is covered: a workload that does not bind yet is not resolved,
  instead of letting a client run into its deadline.
- Readiness is visible (`tg_workload_ready` per workload), and with that the hanging
  workload is for the first time a finding instead of a riddle.
- Nothing is stopped or started autonomously — this cut's blast radius is one DNS
  answer.
- No new dependency, no new crate; the seam is the `Wiring` trait that stands between
  `tg-runtime` and `tg-net` anyway.

**Negative / Costs:**

- **Without a threshold a single failure bites.** An instance whose port does not
  answer for one pass falls out of resolution for one pass. With a TTL of 5 s (phase
  9a) and an interval of 10 s the window is small, but it is there — and the
  mitigation is ADR-0013's own: a client asks again.
- **A TCP connect is a weak statement.** Whoever wants to distinguish `200` from
  `500` needs an HTTP probe, and that is deferred.
- **The probe costs one thread per running instance per pass.** `run_in` creates it
  and tears it down; at a node's instance count that is defensible, a bound it is not.
- **A probe is a call the workload sees.** A server that logs every connection logs
  one entry per pass from here on.
- **The effect is one-sided until the field travels.** Its own node conceals an
  unready instance, a foreign one offers it — visibly different answers for the same
  name, depending on who asks.

## Risks & Open Points

- **Switching the dependency gate** (ADR-0061) to readiness is the obvious
  continuation and is not decided.
- **Binding the active-role lease** to the probe is the most dangerous coupling and
  is not decided.
- ~~**The field in the report** is missing (determination 8) and is a format break.~~
  — **built**: `NodeReport.unready` travels, the agent fills it from its pass's
  report, the leader takes it into the projection through `report_unready`, and
  `RemoteEndpoint::healthy` computes from it. With that a **foreign** node no longer
  offers the address of an unready instance while its own conceals it — the cost side
  of that determination is gone. The format break counts in `PROTOCOL_FIELDS` and
  belongs in the window from ADR-0072.
- **An HTTP probe** stays open, together with the TLS question that hangs on
  `<mesh>`.
- **Liveness** in the sense of ADR-0015 therefore does not exist, and that is
  determination 7 — what ADR-0015 calls "liveness per workload" is here a human with
  a metric and `tgctl cluster restart`.
- **A workload without a network** (no node network, ADR-0012) has no namespace in
  which a probe could run. It counts as ready, otherwise a missing node network would
  take resolution — which it does not have anyway — from every instance.

## Related ADRs

- **ADR-0015** — it decides probes **per workload**; this ADR redeems half of it.
- **ADR-0013** — the effect lies in resolution.
- **ADR-0060** — from outside the probe cannot measure: the redirect lands at the
  sidecar.
- **ADR-0066** — and that one refuses without the active role.
- **ADR-0010** — once per pass, without a counter and without a period.
- **ADR-0089** — answers the question this ADR leaves open: what a requirement edge
  may know about readiness.
