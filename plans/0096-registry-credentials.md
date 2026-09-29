# ADR-0096: Registry credentials — the consumer is the agent

- **Status:** accepted — the mapping `registry → secret` in consensus, the permission on
  the workload, plaintext only in the agent
- **Date:** 2026-09-06
- **Deciders:** Core team

## Context and Problem Statement

ADR-0016 says: *"**Registry credentials** (ADR-0003) run over the same path."* Since
ADR-0095 the path is half built — a value lies sealed in the log, the permission is
desired state, and the slice carries both to the node whose workloads may read it. What
is missing is the **consumer**: `image::pull` sets `RegistryAuth::Anonymous`, with a
comment waiting for exactly this ADR.

Two things are unclear in this, and the first is a **finding**.

**First: ADR-0016's open point does not concern this case.** That ADR carries *"fix the
delivery mechanism (tmpfs vs. API)"* as an open question and demands "in-memory
delivery — secrets **never** land on the container's persistent disk and **not** in
environment variables". Measured, though, the puller runs **in the agent**:
`tg_runtime::image::pull` is called from `acquire::ensure` and `volume::materialise`,
both in the agent's process, never in a container. A registry credential therefore
reaches **no** container — and the whole question of the delivery mechanism is moot for
this consumer. It stays open for workload secrets, where the secret really has to go
into a container.

**Second: how does a credential find its registry?** A workload can have several
secrets, and `RegistryAuth` wants a user and password or a token. Measured,
`Reference::registry()` returns the host, so there is something a mapping can rest on.

## Decision Drivers

- **Least privilege stays (ADR-0025).** A node should learn only what the workloads
  running on it need — not every credential of the cluster.
- **No schema change if it can be avoided** (ADR-0008 has a process of its own for it).
- **The plaintext must lie nowhere** an auditor finds it: not in the log (ADR-0020
  retains forever), not in the projection, not on disk.
- **`tg-runtime` must not know `tg-identity`.** The edge runs the other way, a second
  would be a cycle.

## Options Considered

**A — one cluster-wide command, without a permission on the workload.**
`SetRegistryCredential { registry, secret }`, and every node gets every credential.
Rejected: that takes least privilege back, and a compromised node would thereby have
access to all the cluster's registries — including those it never pulls from.

**B — the mapping cluster-wide, the permission on the workload.** Chosen.

**C — the mapping in the definition** (`<image pull-secret="…">`). One action less, but
the same registry access stands in every definition pulling from that registry — and
changing the credential would be a change to every affected workload. Plus a schema
change with the process from ADR-0008. Rejected.

## Decision

1. **The mapping is cluster-wide, the permission is on the workload.** A new command
   `SetRegistryCredential { registry, secret }` (and `ClearRegistryCredential
   { registry }`) says **which** secret applies to a registry; `AllowSecret <workload>
   <secret>` says **who** may read it. A credential without a permission for the pulling
   workload has no effect.

   The reason for the split is that they are two different facts: which secret belongs
   to a registry is a statement about the **registry** and holds cluster-wide once; who
   may use it is a statement about a **workload** and belongs under the same rule as
   every other permission.

2. **The slice carries only mappings whose secret this node has anyway.** A complete
   list would be a directory of the cluster's private registries — and that is
   information a node does not need.

3. **The format is explicit, not guessed.** A registry credential's plaintext is one
   line:

   ```
   basic <user>:<password>
   bearer <token>
   ```

   The first word names the form. Without it a password without a user name would be
   indistinguishable from a token, and the choice would fall on a character in the value
   — exactly the kind of implicit coupling this tree otherwise rejects. With `basic` the
   **first** colon separates: a registry user name contains none, a password may.

4. **The plaintext lives in the agent and nowhere else.** It arises at opening, is handed
   to `RegistryAuth` and falls afterwards. It is explicitly **not** written to disk —
   unlike the edges and the egress permissions, which need a file because their consumer
   runs in a container. For an agent-local consumer there is no reason to let the secret
   see the filesystem.

5. **The seam is a trait with one method**, supplied by the agent:

   ```rust
   pub trait Credentials {
       fn for_registry(&self, registry: &str, workload: &str) -> Option<RegistryAuth>;
   }
   ```

   `Context` gains a `credentials: Option<&dyn Credentials>` — the same construction and
   the same reason as `workload_api` (ADR-0081): the agent has the data key,
   `tg-runtime` must not know `tg-identity`. Without the setting the pull is anonymous,
   i.e. exactly as today.

6. **A credential that is unreadable or cannot be opened means anonymous**, not
   "failure". The pull then fails at the registry with its own message (`401`), and that
   is the more precise information: it says the registry refused the credential, rather
   than that we could not read one. Both are reported.

7. **The permission is checked on every pull**, not remembered at startup. A
   `RevokeSecret` therefore takes effect at the next pull — level-triggered like
   everything else (ADR-0010). A running container is unaffected: its image lies in the
   store.

## Consequences

**Positive**

- A private image is pullable, and with that the gap ADR-0095 opened is closed.
- The plaintext of a registry credential exists only as a value in a function. No tmpfs,
  no mount, no file, no environment variable.
- Least privilege without effort: a node sees the credentials of the workloads running
  on it — because the slice from ADR-0095 already filters that way.

**Negative / Costs**

- **Two actions per registry access** (`secret put` plus `cluster registry`), and a
  third per workload (`secret allow`). The price of the split from determination 1.
- **A format break on the slice** — the ninth, and it goes into the same bundled window
  (ADR-0072, determination 3).
- **The line format from determination 3 is a convention** an operator has to observe; a
  value without a leading word is refused and the pull runs anonymously.

**Risks & Open Points**

- **The rotation of a registry credential** takes effect at the next pull, not at once.
  For a `pullPolicy="always"` that is the next start, for a cached image arbitrarily
  late.
- ~~**`ClearRegistryCredential` does not check** whether a workload still pulls from that
  registry — unlike `RemoveSecret`, which refuses an open permission. The difference is
  justified: which registry a workload uses stands in its image string, and parsing that
  would be a second source for a fact the puller reads anyway. The consequence is a pull
  that runs anonymously and fails at the registry — visible, not silent.~~ — **done:
  ADR-0125**, and two sentences in it had to be corrected.

  **"Visible, not silent"** — measured, the pull fails only the next time, i.e. with
  `pullPolicy="always"` at the next start and otherwise arbitrarily late; and a failed
  reconciliation drags every dependent along per ADR-0061. Between the action and the
  effect lie, in case of doubt, weeks.

  **"A second source"** — correctly seen and with the wrong conclusion: instead of not
  parsing, from ADR-0125 exactly **one** place parses
  (`tg_model::egress::registry_of`), and the puller delegates there; a differential
  witness holds it against `oci_client::Reference::registry()`.

  The command is nevertheless not refused — unlike conjectured here, the two cases are
  **not** symmetric: `RemoveSecret` prevents a dangling reference, here a valid state
  would arise, and a prohibition would take away the legitimate path. The command is
  **answered** (ADR-0048).

  And while measuring, a second finding came out that weighs more: the registry host was
  normalized **nowhere** — a capital letter on either side meant anonymous, and
  silently.
- ~~**The second consumer of a secret was unguarded.**~~ — **found while re-measuring
  the point above, and fixed.** `SetRegistryCredential` refuses a mapping onto a secret
  that does not exist — with the justification that a mapping into the void would look
  to an operator like one that holds. Measured, `RemoveSecret` let exactly that state
  **arise**:

  ```text
  RemoveSecret despite a registry mapping: Applied
  mappings afterwards: [("registry.example.com", "reg")]
  secret still there? false
  ```

  So ingest refused to **create** the mapping into the void and permitted it to
  **arise**. `RemoveSecret` guarded `secret_grants` and not `registry_credentials`. It
  now refuses both, with a variant of its own (`SecretUsedByRegistry`): in `SecretInUse`
  stands a **workload**, and writing a registry into that field would be an untruth in
  the data.
- **No witness at a real private registry.** What is checked is that the puller gets the
  expected `RegistryAuth`; that a registry accepts it would need a test registry — the
  same open spot as with the layer order (ADR-0003).
- ~~**For workload secrets ADR-0016's question stays open** (tmpfs vs. API). It has
  become **smaller** through this ADR, not answered.~~ — **done:** ADR-0098 — tmpfs,
  filled by the agent.

## Related ADRs

- Applies: **ADR-0016** (registry credentials over the same path), **ADR-0095** (the data
  key and the sealed value), **ADR-0003** (image distribution).
- Inherits the filtering: **ADR-0040** (the slice per node), **ADR-0025** (deny by
  default).
- The seam's construction: **ADR-0081** (`workload_api` in the `Context`).
- Format break: **ADR-0072** (the bundled window).
- Retention: **ADR-0020** (ciphertext stands in the log).
