# ADR-0024: Time Source & Traceable Timestamps

- **Status:** accepted
- **Date:** 2026-08-12
- **Deciders:** Core team

## Context and Problem Statement

REMIT reports and the DORA audit trail (ADR-0020) require accurate, traceable
timestamps. Moreover the consensus/lease mechanism (0005/0010) needs a clean
separation of wall-clock and elapsed-time semantics.

## Decision

- **Traceable UTC time**, synchronized by **PTP** (where hardware timestamping is
  available) or **chrony/NTP** against a documented reference.
- **Monotonic vs. wall clock kept apart:** lease/timeout logic (0010) uses
  monotonic clocks (immune to wall-clock jumps); audit/REMIT timestamps use the
  traceable wall-clock UTC.
- **Timestamps on audit/REMIT records** are traceable to the reference time
  (evidence of the synchronization quality).
- **Clock skew** is an explicit DST test case (ADR-0005/0019).

## Consequences

**Positive**
- Time evidence fit for REMIT/DORA; robust consensus timeouts.

**Negative / Costs**
- PTP presumes suitable hardware/network; chrony as a fallback is less accurate.

**Risks & Open Points**
- The accuracy requirement of the REMIT report (which determines PTP vs. NTP).
- The reference time source and the evidence of its traceability.

## Related ADRs

- Used by: ADR-0020 (audit), ADR-0015 (telemetry). Monotonic for: ADR-0010/0005.
