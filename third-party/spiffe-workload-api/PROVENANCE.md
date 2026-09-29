# Vendored: the SPIFFE Workload API

Upstream: <https://github.com/spiffe/spiffe/blob/main/proto/spiffe/workload/workload.proto>
· Specification: SPIFFE Workload Endpoint / X.509-SVID Profile · Licence: Apache-2.0

Brought in via `cargo xtask proto` (ADR-0035). The generated server stub lies
checked in at `crates/tg-identity/src/workload_api/pb.rs`.

## Why here and not in `schema/`

`schema/` holds **our** definition contract (ADR-0008) — what stands there we
decide. This file is decided by the SPIFFE specification. That is why it
belongs beside `xsd-parser` under `third-party/`: foreign text that we carry
along unchanged, so that the build does not have to fetch it at run time
(ADR-0023: reproducible, no network dependency in the build).

## Unchanged

Both files are the upstream version **byte for byte**. There is no patch, and
there is to be none: a deviation in the contract would be exactly the silent
break of the interop for whose sake ADR-0035 chose this way at all.

`google/protobuf/struct.proto` lies alongside because `workload.proto` imports
it (for the claims in `ValidateJWTSVIDResponse`) and the compiler would
otherwise have to look for it in the include path — which would mean that the
build presupposes a protobuf installation on the machine. That is exactly what
it is not to presuppose.

## What of it is implemented

Only the **X.509 profile** — `FetchX509SVID` and `FetchX509Bundles`. The three
JWT methods answer `UNIMPLEMENTED`; JWT-SVID is expressly deferred in ADR-0025
as option C. The `.proto` stays complete nevertheless: it is the foreign
contract, not our selection from it.
