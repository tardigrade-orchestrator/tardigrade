# ADR-0145: What Is Visible of a Device

- **Status:** accepted
- **Date:** 2026-09-16
- **Decider:** Dana Schlifka
- **Technical context:** `tg-agent` (`devices`), `tg-telemetry` (`names`),
  `docs/OPERATIONS.md`

## Context and Problem Statement

ADR-0143 built ADR-0028: the node reads its CDI inventory, reports it as an
ordinary resource, the planner places, the node assigns, the agent injects. The
**cluster side** is thereby complete — `tg_node_free` and `tg_node_pressure`
(ADR-0127) show devices, because devices are resources.

The **node side** is not. Three things are missing, and all three stand out only
when somebody really uses a device:

1. **Which device holds which instance is said by nobody.** It stands in
   `<data-dir>/devices/assigned` and nowhere else: no metric, no log line, no
   `tgctl`. Whoever asks "which GPU does `inference-0` have?" must go to the
   node and read a file.
2. **A device that disappears from the host does not stand out.** The catalogue
   is read **once at startup** (ADR-0143, determination 7); `edits_for`
   afterwards checks only it. If the card is pulled or the driver unloaded, the
   next instance gets a spec with a node that does not exist — and the failure
   comes from the runtime, without saying what it was.
3. **Whether ADR-0028's promise of generality holds is not established.** It
   says the same seam exposes "FPGAs, SmartNICs or prospectively HSMs"; whether
   anything is to be built for that stands nowhere.

This ADR is deliberately small: it closes the three without changing anything in
ADR-0143.

## Decision Drivers

- **Alpha.** What is buildable without accelerator hardware shall be built; what
  is not shall be **written down** instead of being missing unnoticed.
- **No new label** — the cardinality rule from ADR-0015 was dearly bought
  (ADR-0088), and a device is already a resource.
- **A failure shall name its reason** (the line from ADR-0062 and ADR-0131).

## Decision

### Determination 1 — the assignment becomes visible, and in two different ways

**As a number:** `tg_node_devices_assigned{resource}` — how many devices of a
type are currently assigned, with **the same label and the same value** as in
`tg_node_free` (`resource = "device:nvidia.com/gpu"`). No new label: a device
has been a resource since ADR-0143, and naming the same thing twice would be the
error ADR-0134 cost elsewhere.

With that, beside "how many does this node have" (capacity) and "how many are
still free" (`tg_node_free`, computed by the leader), stands the **node-local
truth**: how many are really assigned. If the two diverge, that is a finding —
and until now nobody could see it.

**As a sentence:** a log line per assignment and per release that names
**instance and device**. That is the answer to "which GPU does `inference-0`
have?", and it belongs in the log and not in a metric: the concrete device name
differs per node and is one per instance — as a label it would be the memory leak
ADR-0015 warns about.

### Determination 2 — a vanished device costs the start, not the node

At **assignment** it is checked whether the device nodes are still there. If one
is missing, the instance is **not started**, and the message names the path.

That is the same direction as in ADR-0143: *"a container that starts up without
its accelerator looks as if it were running."* What is new is only that it
**stands out** before the runtime does — and with a sentence that names the
reason instead of a `mknod` error from youki.

What is **not** checked at every pass is already running instances: what the
kernel once gave a running container this check does not take away from it
(ADR-0019), and a device that disappears under a running process is a hardware
event the process itself notices. The price stands in the consequences.

**The catalogue is still read once at startup.** Re-reading it per pass would be
the larger change — it would concern the inventory and thereby the report
(ADR-0143, determination 7) — and it is not needed for this cut: the check here
touches the disk, not the catalogue.

### Determination 3 — for an HSM or an FPGA there is nothing to build

ADR-0028's promise of generality holds, and that is **established, not built**:
the `kind` is a string from the spec, and nothing in the read path, in the
assignment or in the injection knows the word "GPU".

The evidence has been there since ADR-0143 without anyone calling it that:
**every witness runs against `example.com/probe`** — a type that does not exist,
with device nodes that are `/dev/null` and `/dev/zero`. Had the path GPU
knowledge anywhere, it would have failed on it.

What an HSM would mean beyond that for ADR-0014 — PKCS#11 instead of the TPM
custody from ADR-0140 — is a **separate** decision and expressly not this one.

## Consequences

**Positive**

- The three questions an operator asks at the first real device have an answer:
  *how many are assigned*, *which one does this instance have*, *why does it not
  start*.
- **No new label, no new metric family** — the number lines up with
  `tg_node_free`.
- ADR-0028's bonus sentence is no longer a claim.

**Negative / costs**

- **One `stat` per device node and assignment.** The assignment is idempotent
  and happens once per instance, not per pass.
- **A running instance is not monitored.** If its device disappears, only it
  notices. That is intentional (ADR-0019) and the cost side of determination 2.

**Risks & open points**

- **None of this is measured against real hardware** — as with ADR-0143. What is
  to be done and checked on a machine with an accelerator stands from here in
  the operations manual, so that nobody has to invent it the first time.
- **The number of assigned devices and the leader's computation can diverge**,
  and this ADR makes that visible without treating it: whoever wants to bring
  them together needs the ledger in the report (ADR-0040, determination 7) — a
  decision of its own.

## Related ADRs

- **Supplements ADR-0143** (and thereby ADR-0028) with the node side; changes
  nothing there.
- **ADR-0127** — `tg_node_free`, into whose label the new number lines up.
- **ADR-0015 / ADR-0088** — cardinality and cadence.
- **ADR-0019** — why a running instance is not monitored.
