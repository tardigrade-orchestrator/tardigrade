# Tardigrade Operations Manual

What an operator needs to know to run Tardigrade — collected from the ADRs and
the measured findings in `plans/PLAN.md`. **Every statement here is backed at
its source**; this document decides nothing.

It exists because the plan refers eleven times to an "operations manual" that
did not exist. What lives only in the code or in a 7000-line plan is lost in
operation — the most recently found case was a **required** switch that no
usage text mentioned.

---

## 1. Prerequisites

| What | Why | Source |
|---|---|---|
| **Linux, cgroup v2** | The orchestrator runs v2; v1 is not up for debate. | ADR-0003 |
| **`youki` or `crun` in `PATH`** | The OCI runtime. `youki` first, `crun` as fallback. | ADR-0003 |
| **`nft`** | The rule set goes through the `nft` program as a separate process, not through a library. | ADR-0038 |
| **`losetup`, `mkfs.ext4`, `mount`, `umount`, `resize2fs`** | Persistent volumes. Invoked, not linked — the same boundary as with `nft`. | Phase 10b |
| **WireGuard module** | The underlay. Without it the node stays outside the mesh; it keeps running. | ADR-0039 |
| **Enough descriptors (`LimitNOFILE`)** | The agent holds one per connected workload (the SVID stream stays open), one per open DNS forward, plus netlink, `nft` and the session. If they run out, **no listener accepts any more** — each then waits and reports it (section 3) rather than ending. The right number is not decided; the default of 1024 is tight. How close it is, `tg_process_open_fds` and `tg_process_max_fds` will tell you. | Phase 9c |
| **`CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_MKNOD`** | Network namespaces, mounts, whiteouts while unpacking. Without `CAP_MKNOD` unpacking **fails** rather than skipping whiteouts. | ADR-0017, ADR-0052 |

### The host packet filter must let the node through

On a host with default-deny INPUT (say `firewalld` with `reject with icmpx
admin-prohibited`) a container **cannot reach the node's services** — and this
orchestrator's rule set can do nothing about it: in netfilter all base chains
of a hook run, and an `accept` in one does not override a `reject` in another.

Chiefly affected is the **node-local resolver** (ADR-0013). It has to be
opened up, the same way `nft` itself is a prerequisite.

> Measured in phase 9b.

### One data directory per node

`tgd` places its cluster leaf at `<data-dir>/identity/node.leaf.pem` and reads
peer leaves from `<data-dir>/peers/<id>.pem`. Two processes on one directory
overwrite each other.

- Default for `tgd`: `/var/lib/tardigrade/control-plane`
- Default for `tg-agent`: `/var/lib/tardigrade`

**Both refuse a second start**, each in its own way:

| | |
|---|---|
| `tgd` | `redb` locks the Raft store — "Database already open" |
| `tg-agent` | `flock` on `<data-dir>/agent.lock` |

The message names the directory. Both locks hang off the open descriptor, not
off a file with a PID in it: after a `kill -9` the kernel releases them and the
restart comes up. There is **nothing to clean up** — the lock file stays behind
and is empty.

> ADR-0043.

---

### The cluster ports now notice when someone is gone (ADR-0128)

**New as of this state.** The client in the agent always had an HTTP/2
keepalive; **no server** had one. A peer that vanishes without a `FIN` — a
partition, a node that loses power — thus kept its connection open: `tgd` only
sends when the log moves, so TCP noticed nothing either. On a **quiet** cluster
the detection time was unbounded.

The Raft port, the session port and the credential port now ping at the cadence
of the reporting period (`Lease/3`, i.e. 5 s) and give up after two — the same
number as the client, from the same source. The **admin socket** deliberately
gets none: on a Unix socket there is no partition.

**What it costs.** A node whose runtime blocks — a long apply, a large
snapshot — answers no pings either; its connections drop and are immediately
rebuilt. The price is one handshake per blockage lasting longer than two
reporting periods.

**What it does not do.** Clear away a node that reads too **slowly**. Its pings
are answered by `hyper` and not by its application — and that is right: whoever
is working does not get cleared away (ADR-0019). A stuck but living node thus
remains the open point from ADR-0040.

### The content store cleans up after itself (ADR-0126)

**New as of this state.** The store under `<data-dir>/content/` used to grow
linearly and never shrink: every tag ever pulled kept its blob, its unpacked
layer and its record. Measured, that is 52.6 MB for five tags of a 5 MB
layer — and a disk filling up is an outage from housekeeping nobody could do.

Two things change:

- **`content/blobs/` is gone.** The downloaded blob is **verified** against its
  digest (the check at the trust boundary to the registry, ADR-0023) and no
  longer stored. Measured, nobody read it on the production path, and it saved
  no pull — it was half the store. An existing directory is cleared by the
  first pass.
- **The reconciler releases what the desired state no longer names.** No tool,
  no schedule, no deadline: the same second direction of the same reconcile
  with which it also clears away containers (ADR-0058).

**What it costs.** A workload that comes back after the desired state stopped
naming it in the meantime needs the registry — and a rollback to the previous
image tag pulls afresh. Whoever does not want that does not take the workload
out of the desired state.

**When it does not run.** Three guards hold it back, and each costs only a
deferral until the next pass:

| Situation | Reason |
|---|---|
| empty desired state that nobody has confirmed | "nothing wanted" and "nothing heard yet" look the same (ADR-0058) |
| an **isolated** entry (unreadable document, duplicate name, cycle) | it names no reference, its layers would look unreachable (ADR-0062) |
| a **bundle** the desired state does not name | the release from ADR-0119 did not get through; removing layers underneath a mount would be the damage from ADR-0122 |

The third one appears in the node's log (`Content-GC verschoben`). Whether it
runs at all is told by `tg_content_reclaimed_bytes_total` and
`tg_content_reclaimed_layers_total` — without them a disk that stops shrinking
would be indistinguishable from a GC that never runs.

### The data directory belongs to the service alone (ADR-0115)

Both processes set the permissions of their data directory **explicitly** to
`0700` at startup — the root and the subdirectories they create themselves
(`desired/`, `network/`, `volumes/`, `content/`, `bundles/`, `sockets/`).
Nothing is left to the caller's umask.

**This is a behavioural change.** Until ADR-0115 `desired/`, `network/` and
`volumes/` were created with `create_dir_all` and the umask, i.e. normally
`0755` — and with that **every account on the machine** read the node's desired
state, the `may_talk` edges, the egress permissions, the WireGuard peers
including their endpoints, and the cluster's address plan:

```text
$ runuser -u nobody -- cat /var/lib/tardigrade/desired/api.xml
<?xml version="1.0" encoding="UTF-8"?><tg:workloads …
```

What follows from that:

- **A tool that looked into the data directory as non-root sees nothing any
  more.** A monitoring script counting `desired/`, a backup running as its own
  user: both need `root` from here on — or another way (`tgctl cluster show`,
  the Prometheus endpoint).
- **The containers notice nothing.** What is sealed is the **directory**, not
  the file: the three files the sidecar reads from `network/` are bind-mounted
  and keep their permissions — a bind mount does not hang off the host's parent
  path. The same construction as with the workload API socket (directory
  `0700`, socket `0666`).
- **The mode is set at every start**, including for a directory that already
  exists, and also when someone changed it deliberately. A security property
  you can switch off once is one that is eventually switched off.
- **If the mode cannot be set, the node runs anyway** and reports it. A node
  that fails to start over a permission bit takes its workloads' connections
  with it (ADR-0019).
- **`runtime/` is not touched.** That is where the OCI runtime keeps its books;
  it creates the directory itself with `0700` (measured), and resetting it
  would be a reach across the boundary from ADR-0003.

**This protects nothing against `root`, and it is not meant to.** Whoever can
write the files is `root` — and `root` reads `identity/secrets.key` on the same
disk and replaces the binary anyway. A MAC over the entries would be a lock
with its key hanging next to it (ADR-0115, decision 4; the same argument as
ADR-0044). The next layer would be mandatory access control on the machine
(SELinux, AppArmor) — that is not part of this system.

> ADR-0115, ADR-0017, ADR-0019.

---

### Time synchronisation, binding for single writers

The active-role lease (ADR-0064) applies against the **wall clock**:
`expires_at` is formed by the leader, and the comparison is against the node's
local time. From that follows a precondition (ADR-0078):

> **Clock skew between node and leader < 3 s** (the safety margin from
> ADR-0076).

If a node's clock lags further **behind**, it holds the active role while the
leader hands it on — two writers on one volume, and that is exactly what the
lease prevents. If it runs **ahead**, the node fences too early: its single
writers stand still until the clock is right.

With `chrony` or PTP (ADR-0024) the condition is met with room to spare;
without time synchronisation it is not. **Replicated workloads are
unaffected** — they have no active role.

Where to look: `tg_lease_clock_skew_seconds` (section 5). A grotesque skew
(more than a whole lease, i.e. 15 s) is no longer believed: the instance
fences, and the log names the reason.

## 2. Commissioning

### 2.1 The control plane

Five nodes, quorum three, across at least three failure domains (ADR-0031).

```
tgd --id 1 --node tgd-1 \
    --listen 127.0.0.1:7001 \
    --cluster-listen 0.0.0.0:7002 \
    --node-listen 0.0.0.0:7003 \
    --peer 1=https://… --peer 2=https://… … \
    --init --init-voters 1,2,3,4,5
```

- `--init` **exactly once in the life of a cluster**.
- `--peer` points at the **cluster port** (`--cluster-listen`), not at
  `--listen`.
- The signing material lives under `<data-dir>/signing/` (`ca.pem`,
  `bundle.pem`, plus **either** the signing group — `share` and `group` —
  **or** `ca.key.pem`). If both are missing, the node runs **without** a
  SPIFFE server.

**Distribute the peer leaves.** Every `tgd` writes its leaf to
`<data-dir>/identity/node.leaf.pem`. It belongs on every other node at
`peers/<id>.pem`, and on the agent at `identity/control-plane.pem`. Without
that no handshake comes about.

**On the agent it is all the leaves, concatenated** — the file is a list, not a
certificate:

```bash
cat node1.leaf.pem node2.leaf.pem node3.leaf.pem     node4.leaf.pem node5.leaf.pem > <data-dir>/identity/control-plane.pem
```

The reason is ADR-0077: the agent talks to the **leader**, and which node that
is changes. With only one node's leaf the handshake to any other fails with
`invalid peer certificate: UnknownIssuer` — and a leader change then cuts the
node off from its desired state.

> ADR-0043, ADR-0077.

### The signing group (ADR-0014, ADR-0097)

**The difference this is about:** if `signing/ca.key.pem` lies on a node, that
node holds the **full CA key**. Whoever takes it over issues every SVID of this
cluster. With the group that file does not exist — the key is spread over five
seats, three of which sign together, and a stolen node yields **one share below
the threshold**.

Whether a node runs it is told by `tg_identity_signer{kind="group"|"local"}`.
`local` is the fallback and is reported as a warning at startup.

**What a seat needs:**

| File | Content |
|---|---|
| `signing/share` | its own share (`0600`) |
| `signing/group` | the group public key |
| `signing/ca.pem` | the CA certificate over the group key |
| `signing/bundle.pem` | the anchor (the same certificate) |
| `signers/<seat>.pem` | the cluster leaf of **every** seat |

`signing/ca.key.pem` then does **not** exist, and that is the property: it is
readable from the absence of a file.

**The share lies sealed (ADR-0140).** If `/dev/tpmrm0` is there, the node binds
`signing/share` to its TPM at first start — with no manual step, and with a
counter-check before replacing anything. `tg_identity_signer_share_sealed` says
whether it worked; the alert rule sits at four out of five seats, because at
three the threshold t = 3 is only just covered.

The prerequisite is `tpm2-tools` on every node with a seat — invoked, not
linked, like `nft` and `cryptsetup`.

**A host update has no consequences.** There is no PCR policy, so firmware,
boot loader, kernel and `dbx` change nothing. Three other events cost the
share, and none of them is an update:

- **"Clear TPM"** in the BIOS or `tpm2_clear` — a new seed.
- **Mainboard replacement.**
- **VM restore without the vTPM state.** It belongs to the backup of a
  control-plane VM; without it the node comes back and its seat does not.

Each of those is an **RTS case** (`tgctl signer repair`, ADR-0108) and not a
restart. Share gone does not mean CA gone — with five seats at t = 3, two
losses are carried.

**Two settings per node:**

```bash
tgd … --signer-listen 0.0.0.0:7004       --signer 2=https://tgd-2:7004       --signer 3=https://tgd-3:7004       --signer 4=https://tgd-4:7004       --signer 5=https://tgd-5:7004
```

- **Its own seat does not belong in the list.** Which seat this process holds
  is in the share; it is run locally.
- **Without `--signer-listen` a node with group material does not start.** A
  seat nobody can reach lowers the number of available ones below the
  threshold — and that would otherwise only show at the first minting.
- **Seat and Raft id are independent** (ADR-0014). A node with Raft id 1 can
  hold seat 4, and a change of seat is not a membership change.

**Distribute the signer leaves.** The same file as for the peers
(`identity/node.leaf.pem`), but a different place and a different name: it
belongs on **every** seat at `signers/<seat>.pem`, where `<seat>` is the seat
number of the node the leaf belongs to. A seat whose leaf is missing gets no
commitment and no share — and runs no signer port itself, because it lacks the
channel to the others.

**One leaf, one seat.** Two files carrying the leaf of the **same** node are
the obvious copying mistake here, and both seats are then refused — with a
message naming the name and both seat numbers. That is the stricter choice and
the right one: taking one of the two would mean the other looks admitted and
does not get through the handshake, and **which** one would be decided by the
order in which the files are read. You can check with
`tg_identity_signer_seats` — the number says how many seats can really identify
themselves, and without the bar it counted both.

**The ceremony.** The DKG is deliberately **not** a tool: every seat generates
its share on its own machine, and the three rounds go over a channel a human
has set up. For a local run there is `cargo xtask threshold` (it names the
target directory in its output); **this process sees all five shares** and is
therefore, for the duration of its run, the full key. It produces dev material
and does not carry a cluster.

**The ceremony's trust domain must be the cluster's.** It goes into the group's
CA certificate; hard-coded, every ceremony carried `cluster.local`, including
for a cluster with a different one — and nobody could
change it. The run now takes it as a setting, with `cluster.local` as default:

```
cargo xtask threshold --domain acme.internal
```

**A dead seat is not replaced.** It becomes visible
(`tg_identity_signer_seats`), and the replacement is an action: RTS (ADR-0014)
restores a seat's share from t others without changing the group. This does not
happen automatically — the input would be an **absence**, and a failure must
not produce a decree (ADR-0057).

**Refreshing the shares (ADR-0107).** New shares, **the same** group key:
certificates, chains and the intermediate from the root remain valid
afterwards. That is the answer to a share that has fallen into the wrong
hands — RTS restores a *lost* one, it does not invalidate it.

```
tgctl cluster signer-refresh
```

- **On a node that holds a seat** — not on the leader: the group is decoupled
  from the Raft membership. A node without a seat refuses it and says so.
- **All five seats must be reachable**, otherwise it does not run — the path
  with fewer would *shrink* the group (from "tolerates two failures" it would
  become "none", and nothing about it would be visible).

  Two cases, and they report differently: a seat for which **no access is
  configured** (`--signer` missing or the leaf not in place) shows up **before**
  round 1 and the message names the number; a seat that is configured and
  **does not answer** shows up in round 1 with "seat N did not answer".
  The group stays unchanged in **both** cases — in the second one because the
  started run is cleared away at every seat, not because it would not have
  started.
- **During the change every seat holds two generations**, so that there is no
  window in which the group does not sign. The **old one is discarded** as soon
  as all five have reported that the new one is on their disk (ADR-0107,
  decision 6) — and only then does the refresh take effect: as long as it lies
  there, t seats can keep signing in it, and a leaked share remains valid. If a
  seat is unreachable when reporting, it stays; a second run catches up.
- **How many generations a seat holds is at its endpoint**
  (`tg_identity_signer_epochs`, plus `tg_identity_signer_epoch` for the
  newest). After a completed refresh it is **one** — more means an old one is
  still lying around.

**Check before and after.** Both questions around a refresh cannot be answered
without this command — can it run here, and is it through:

```
tgctl cluster signer
```

- **Seat, shape, accesses, admissions** — the input of the pre-flight check. A
  missing access is the case that shows up **before** round 1.
- **The generations.** One means: through. Two mean: the old one is still
  there, and a leaked share remains valid (decision 6).
- **The fingerprint of the group key** — eight hex characters, **not** a key.
  It ought to be the same on all five seats; a seat with a foreign group starts
  without complaint and contributes to no signature. The same number is at the
  endpoint as `tg_identity_signer_group_info`, with an alert rule on it.
- **The accesses count the node's own seat** — five, while `--signer` names
  only the other four: the node's own share is one of the three commitments.
- **Class `read`** (ADR-0105) — unlike the refresh next to it.
- **The generation stands alone on stdout.** `tgctl cluster signer-refresh >
  generation` is the number.
- **Class `secrets`** (ADR-0105) — the same as `cluster secret rekey`.

> ADR-0014, ADR-0097, ADR-0107.

**Restoring a lost share.** A seat whose `share` is gone — a replaced disk, a
lost TPM binding — fetches it back from `t` others without the group key
changing:

```bash
# on the node of the affected seat
tgctl signer repair 5 \
  --helper 1=http://tgd-1:9443 \
  --helper 2=http://tgd-2:9443 \
  --helper 3=http://tgd-3:9443
systemctl restart tgd
```

Six things about this, and each has a reason:

- **`tgd` does not repair itself.** The client puts material in place, `tgd`
  reads it at **startup** — the same role as `cargo xtask threshold` in the
  ceremony; a repair state inside the process is rejected (ADR-0108,
  decision 7). The command needs **no** admin socket: the signing group is
  decoupled from consensus (ADR-0014).

  **The process does keep running, though** — measured: without group material
  it reports `--signer-listen without group material` as a warning, does not open
  the signer port and issues nothing. Hence `restart` and not `start`: a
  `start` on a running process does nothing, and the seat would stay empty.
  With a lost **TPM binding** (ADR-0140) this is the normal case — the file is
  there, it just does not open any more.
- **At least `t` helpers**, and the threshold comes from the **group key**
  (`min_signers`) and not from a setting. With fewer it is refused **before**
  the first call: `repair_share_part3` does not count the sigmas and with too
  few delivers a share that looks valid and is wrong.
- **The helpers must be running.** Each of them checks at the signer port that
  the caller is who it claims to be (ADR-0097) — and that it is the
  **affected** seat: a sigma goes only to it (decision 3).
- **Its own seat does not belong under `--helper`.** Whoever has the share does
  not need it; a mistyped `--helper 5=…` ends up at itself and is refused.
- **The group key must be in place**, the share need not — that *is* the repair
  case. It is the yardstick: the check is against the `verifying_share`
  **before** anything is written (decision 6).
- **The newest generation is repaired.** A helper derives its deltas from its
  newest share; if an older group key lies at the affected seat, the check
  fails — loudly, and then a refresh is the answer and not a repair.
- **The restored share lies sealed immediately** (ADR-0140). The client builds
  its custody itself; on a node with a TPM an envelope is in place afterwards,
  and no second step is needed.

> ADR-0108, ADR-0140.

**Distributing the data key.** It is **one** cluster-wide and belongs on
**every** `tgd` node:

```bash
tgctl secret keygen > /tmp/secrets.key          # once, on one node
# and then onto every tgd node:
install -m 600 /tmp/secrets.key <data-dir>/identity/secrets.key
```

Three things about this, and each has a reason:

- **`tgd` does not create it.** A `tgd` that created it on demand would create
  a **different** one on every node — and what one had sealed nobody would open
  afterwards, without anything appearing anywhere. If it is missing, `tgd` says
  so at startup (`no data key`), and on that cluster there are then
  no secrets.
- **An agent gets it by itself**, over the same path as its agent
  intermediate — which is a private key anyway. It is **not** distributed by
  hand.
- **It is backup material.** If it is lost on all nodes, all secrets are lost;
  it belongs in a backup like the CA root.
- **A divergence is visible, but latent.** Every `tgd` reports the
  **fingerprint** of its key (`tg_identity_data_key_info`), and the alert rule
  counts the distinct ones. What matters is the timing: all agents get the
  **leader's** key (ADR-0077), so a follower with the wrong one does not show
  up in operation — and strikes at the next leader change.

> ADR-0095.

**Storing a secret.** Sealing happens at the **client**, not in the cluster —
the plaintext never reaches the control plane, and what is in the log is a
ciphertext (ADR-0095, decision 4). Without `identity/secrets.key` next to
`tgctl` nothing is submitted, and the message says how it comes about.

```bash
pass show s3/key | tgctl cluster secret put s3-key -   # `-` reads from stdin
tgctl cluster secret allow api s3-key                  # who may read it
```

- **Storing and allowing are two actions.** A `put` that allowed straight away
  would turn a typo in the workload name into a permission nobody decreed —
  and deny-by-default means the permission is the explicit action (ADR-0025).
- **A secret is at most 64 KiB.** Ample for everything ADR-0016 calls a secret
  (a password, a token, a key, a PEM bundle with thirty certificates) and
  chosen so that **sixteen** full ones fit into a container's tmpfs — measured
  against real bytes, the seventeenth fails. Whoever needs more puts a file
  into a shared volume (ADR-0027) and the secret for it here.

  The refusal happens at the **client**, with both numbers in the message.
  Whoever writes past the client (`AdminClient` directly — per ADR-0044
  whoever reaches the socket may do so) puts a larger value into the log; it
  stays there **forever** (ADR-0020), and the agent then refuses it on
  delivery. The container does not start in that case (ADR-0098, decision 7),
  and the message names the reason instead of a `No space left on device`.
- **A secret that someone may still read is not deleted.** The same direction
  as with a volume that a workload still declares (ADR-0027):
  `tgctl cluster secret revoke <workload> <name>` comes first.
- **`tgctl cluster secret rm` is not destructive in the sense of ADR-0027** and
  therefore requires no `--yes`: what is lost is a value the operator has at
  its source anyway — unlike a volume whose content a workload produced.
- **A withdrawn workload takes its permissions with it.** The value stays; a
  permission inherited by a later workload of the same name would be an open
  door with no room behind it (the same consideration as with egress).

**A registry credential cannot end in whitespace.** The value is one line
(`basic <user>:<password>` or `bearer <token>`, ADR-0096), and it is
**trimmed** — otherwise every password placed from a file or from `stdin`
would carry a line ending, and the registry would refuse with `401`. Leading
whitespace **after** the colon, by contrast, is preserved. Whoever has a
password ending in a space cannot store it here; all other secrets are
unaffected — the trim applies only to the credential line.

**A secret in a container.** What a workload may read lies under
`/run/tardigrade/secrets/<name>` — one file per secret, read-only.

```bash
printf '%s' "$PASSWORT" | tgctl cluster secret put db-passwort -
tgctl cluster secret allow api db-passwort
```

An unmodified third-party image thus reads a file. It needs no client, no
library and no protocol (ADR-0098) — which is precisely why the path is a
mount and not a service with mTLS.

- **The mount *is* the authorisation.** A container sees exactly those secrets
  for which `secret allow` names **its** name; there is no call anybody could
  forge. Filtered twice: the slice carries only the secrets of this node's
  workloads, and the agent mounts only its own into each container.
- **It is a tmpfs.** The plaintext lies in RAM — not in the environment, not on
  the container's disk and not on the node's.
- **A rotation needs no restart.** The agent rewrites the files on every pass;
  a `secret put` reaches a running container within one round trip, a `secret
  revoke` takes its file away. **Whether a workload uses the new value is its
  own affair:** whoever reads the file at startup does not see the rotation.
  Whoever wants to force it decrees a restart
  (`tgctl cluster restart <workload> <generation>`).
- **No permission, no directory.** A workload without secrets gets no mount —
  an empty one would be the same to it and one mount more.
- **Without a data key a workload with secrets does not start.** A workload
  that comes up without its password looks as if it were running and only
  shows up at the first access. The other workloads keep being reconciled.
- **The sidecar gets none.** It enters its workload's namespace, but its rootfs
  is its own; registry credentials are read by the agent.
- **A secret name must be a single ordinary path component**
  (`[a-z][a-z0-9.-]{0,62}`) — it becomes the file name, and a `../` would be a
  path escape as root. The refusal happens on submission; an entry from before
  this check is skipped on the node and reported.
- **What is audited is the delivery, not the reading.** The log holds
  `PutSecret` and `AllowSecret` (ADR-0020); that a workload opened a file is
  seen by nobody. A read audit would require a service — and with it a client
  inside the workload.

> ADR-0016, ADR-0095, ADR-0098.

**Pulling from a private registry.** The plaintext of a registry credential
**never** leaves the agent — the puller runs inside it, not inside a container
(ADR-0096, decision 4). So it needs no tmpfs mount and no file.

```bash
printf 'basic robot:%s' "$PASSWORT" | tgctl cluster secret put reg-key -
tgctl cluster registry registry.example.com reg-key   # which secret applies
tgctl cluster secret allow api reg-key                # who may use it
```

- **The first word names the form.** `basic <user>:<password>` or `bearer
  <token>` — without it a password without a user name would be
  indistinguishable from a token. With `basic` the **first** colon separates; a
  password may contain some.
- **Two facts, two actions.** Which secret belongs to a registry holds
  cluster-wide once; who may use it is a statement about a workload — and
  without `secret allow` the assignment has no effect.
- **The order when cleaning up is fixed**: first release the assignment, then
  remove the secret. A `tgctl cluster secret rm reg-key` that a registry still
  points at is **refused** and names the way (ADR-0096):

  ```text
  the registry mapping for 'registry.example.com' points at the secret
  'reg-key' — `tgctl cluster registry rm registry.example.com` first
  ```

  The reason is the same one for which an assignment to an **unknown** secret
  is not created in the first place: an assignment into the void looks like one
  that carries. The pull would afterwards run anonymously and fail at the
  registry — with `pullPolicy="always"` at the next start, with a cached image
  arbitrarily late and far from the cause.

- **`tgctl cluster registry rm` is not refused — it answers** (ADR-0125).
  Unlike with the secret, no contradiction arises here: "this registry is
  pulled from anonymously" is the normal case for every public one, and a
  registry that has become public should be releasable. Who pulls from it is
  therefore in the **answer**:

  ```text
  ein Workload zieht ab jetzt anonym aus 'registry.example.com': api
  ```
  The note travels with the answer and not in the log — it is a transient
  statement, and an auditor would otherwise read warnings five years from now
  that have long been fixed (ADR-0048). If nobody pulls from this registry,
  nothing is there. **Whoever discards it in a script does not see it** — and
  notices the consequence only at the next pull: `401`, a failed reconcile,
  and with it every dependent (ADR-0061).

- **The spelling of the host does not matter** (ADR-0125). A registry host is a
  DNS name; `tgctl cluster registry REGISTRY.example.com reg-key` and the
  reference `registry.example.com/api:1` find each other. **Before this state
  they did not**: what was written was stored, and the lookup was exact — one
  capital letter on either side meant anonymous, and silently. An entry from
  that time carries immediately; the agent lowercases it on reading.

  **The reverse does not hold**: releasing an assignment while workloads pull
  from that registry is allowed. Which registry a workload uses is in its image
  string, and parsing that would be a second source for a fact the puller reads
  anyway.
- **A node learns only the assignments whose secret reaches it.** The complete
  list would be a directory of the cluster's private registries.
- **Every failure means anonymous**, not abort: no assignment, no permission,
  no data key, a line without a leading word. The pull then fails at the
  registry with its own message (`401`) — and that is the more precise
  information. The agent reports the reason alongside.
- **After a restart the node pulls anonymously** until the first slice arrives.
  The credentials live in memory and not on disk: the data key lies there, and
  a ciphertext next to it is plaintext.
- **`registry rm` does not check** whether anybody still pulls from that
  registry — unlike `secret rm`. Which registry a workload uses is in its image
  string.

> ADR-0096.

### 2.2 Admitting a node

```
tgctl node invite <name> > join-token
```

The token appears **only** if the cluster applied the invitation, and it stands
alone on standard output — the redirection above yields exactly the file the
agent redeems (`<data-dir>/identity/join-token`).

`tgctl` reaches **its** node, not the cluster; the invitation belongs on the
leader. If the node is not leading, the call aborts and names it.

> ADR-0037, ADR-0044.

**What is admitted is trust, not capacity.** An admitted node is not yet a
registered one: `AdmitNode` creates no inventory entry. Without
`tgctl node upsert` it gets no capacity and therefore no placement.

> ADR-0037.

### 2.3 Starting the agent

```
tg-agent --node <name> \
         --control-plane http://<node-1>:7001 \
         --control-plane http://<node-2>:7001 \
         --control-plane http://<node-3>:7001 \
         --node-session  http://<node-1>:7003 \
         --node-session  http://<node-2>:7003 \
         --node-session  http://<node-3>:7003 \
         --cluster-cidr 10.42.0.0/16 \
         --underlay-endpoint <reachable from outside>:51820 \
         --proxy-image <registry>/tg-proxy:<generation>
```

- **`--node-session` is required.** Without it the node gets *no slice*: no
  workloads, no edges, no active-role lease. Since ADR-0043 it sits on a port
  of its own and cannot be guessed from `--control-plane`.
- **Both settings are repeatable, and all nodes belong in them** (ADR-0077).
  Both paths go to the **leader**; a follower only refers onwards, and the
  referral carries an id, not an address. With **one** address the node lost
  its desired state permanently after every leader change: no more withdrawals
  (ADR-0025), every single writer fenced (ADR-0064), tombstones left lying
  (ADR-0042) — and after twelve hours no accepted SVID any more (ADR-0014).
  Measured on two real nodes: twenty-five seconds, no slice.

  With the list the agent moves on to the next entry — on a referral **without**
  waiting. The anchors belong with it: `control-plane.pem` must contain the
  leaves of all the nodes named (see 2.1).
- **Only an operator knows `--underlay-endpoint`.** Behind NAT, behind a load
  balancer or on a machine with several addresses it cannot be guessed. Without
  the setting the agent announces **nothing** — and a guessed address in the
  log would be worse than none.
- **`--pin-sidecar-shards` is off, and that is the default on purpose**
  (ADR-0114, decision 3). Measured, pinning the sidecar shards brings **no**
  tail advantage, and whoever is the only one nailed down can no longer evade a
  busy core — a sidecar's neighbour is its **own workload** (ADR-0059: same
  node, same namespace).

  The setting makes sense on a node that has **partitioned** its CPUs for the
  sidecars (`cpuset.cpus` on their cgroup; `cpu.max` stays deliberately out per
  ADR-0086 — the one limits *where*, the other *how much*, and a quota is
  exactly the price the tail goal must not pay). Pinning then goes round-robin
  over the cores `sched_getaffinity` returns, that is, over what the cgroup
  grants — not over the machine's core count.

  The sidecar reports at startup what it sees: `shards`, `pinned` and the list
  `cores`. If a single core is listed, the setting does nothing — then the
  cgroup is the cause and not the switch. Whoever sets it should have
  `cargo xtask bench` on their own installation next to it: the gain is
  attainable and not proven.
- **Without `--proxy-image` there is no mesh** on this node: no sidecars, no
  delegations. For a local run `cargo xtask image` builds an image into the
  content store of a data directory and names the reference; in operation it
  comes from a build pipeline (ADR-0059). What it must contain is fixed:
  `tg-proxy` at `/usr/local/bin/tg-proxy`, the directories of the three mount
  points, a writable `/tmp` — and it must be able to run under a **foreign** id
  (65532, ADR-0060).
- **`--cluster-cidr` is the value *before* the first slice.** If an address plan
  exists in the cluster (`tgctl cluster network`, ADR-0069), **that** one
  applies — for the bridge and the container addresses too, not only for the
  tunnel. The setting carries only the fresh node that has not yet received a
  slice. A typo in it is **not** replaced by the default: the node comes up
  without a network and reports the reason. That is the better half — a node
  with the *wrong* network builds routes and rules that look plausible and
  point into the void.
- **An address plan that changes later reaches the bridge only at the agent's
  next start.** The tunnel follows immediately; while the two diverge it
  permits a range the node's own containers do not use. The agent reports the
  change — whoever sees it restarts the agent (the containers keep running
  meanwhile, ADR-0019).
- The node name becomes a SPIFFE id; an FQDN is not one. What is taken is the
  **first label**, lowercased. Two machines `web01.fra` and `web01.ams` thus
  yield the same name — that shows up at the handshake, because the keys
  differ, and not silently.

> ADR-0039, ADR-0040, ADR-0042, ADR-0043, ADR-0059.

### 2.4 The cluster network and capacity

```
tgctl cluster network 10.42.0.0/16 24
tgctl node upsert <name> --site fra --hall h1 --rack r3 \
      --resource cpu-millicores=8000 --resource memory-bytes=…
```

Or, instead of fixed numbers, a **policy** that derives from what the node
reports it has:

```
tgctl node policy --rule cpu-millicores:percent=80,subtract=2000
```

**What the node reports is told by `tgctl cluster nodes`** — and, separately,
what the scheduler calculates with:

**What holds cluster-wide is told by `tgctl cluster settings`** — four
settings, all four written over the admin socket:

| Setting | Who sets it | Without it |
|---|---|---|
| address plan | `tgctl cluster network <cidr> <prefix>` | every node calculates with **its** `--cluster-cidr`, and two nodes arrive at different subnets |
| sidecar overhead | `tgctl cluster sidecar-overhead --resource <name=number>` | the scheduler books mesh members without their sidecar's consumption |
| capacity policy | `tgctl node policy --rule <name:percent=…>` | a reported capacity does not become usable (no rule, no capacity) |
| rotation policy | `tgctl node rotation --rotate-every <kind>=<days>` | nothing rotates by itself |

**Important for both policies: they are replaced, not extended.** Whoever wants
to add a second resource or key kind must send the existing rules along —
otherwise they fall away. So read `tgctl cluster settings` first, then write.

**Which generation a rotation gets depends on the policy.** `tgctl node rotate
<node> <kind> <generation>` requires a number, and the cluster accepts only one
**higher** than the current (ADR-0055). Automatic rotation (ADR-0057) computes
its generation from the calendar — `(day + offset) / period` — and likewise
writes only what is higher. **A hand-decreed number above that calculation thus
switches the policy off**, for that node and that kind, until the calendar
catches up.

Measured in September 2026: with a period of 90 days the calendar wants
generation **230**, with 365 days **56** — and these numbers **grow with the
clock** (`(day + offset) / period`), so they are an order of magnitude and not
a statement about today. A decreed `1000` would, at 90 days, not be overtaken
for roughly **190 years**. The right number is therefore "one more than the
current one" and not a round one: `tgctl cluster nodes` shows the current one,
`tgctl cluster settings` the period. `tgctl node rotate` warns when a decree
overtakes the calendar — the warning does **not** stop the command.

**Who may be a node is told by `tgctl cluster trust`.** The key is the
credential (ADR-0037, ADR-0043) — the list shows, per node, its SPKI, its
ordinal, its underlay announcement, and below that the **open invitations**
with their deadline. Three cases in which it is the answer:

- **after `tgctl node revoke-trust`**: the node must have disappeared from the
  list — that is the effect of the security action;
- **after a rotation** (`tgctl node rotate …`): the SPKI must be the new one,
  and only a comparison shows that;
- **when a node gets no tunnel**: if it says `nichts angekuendigt`, its
  `--underlay-endpoint` is missing — and the fault is not in the network.

The **hash of the invitation** is deliberately not shown: it is the verifier of
a bearer secret, and the token itself is gone after `tgctl node invite`.

**What has been deleted is told by `tgctl cluster volumes`.** `DeleteVolume` is
the only destructive command (ADR-0027) and the **decision**, not the deed: the
node carries it out when it sees the tombstone in the slice (ADR-0042). If a
tombstone is still there, a node has not performed the deletion — three causes
are measured: it is gone, its report does not reach the leader, or its
tombstone list is unreadable.

And the **total** is the number that matters: a tombstone travels in every
slice and every snapshot until it is carried out. **There is no deadline, and
that is a decision** (ADR-0104): if the instruction expired, the volume would
stay behind on a node that was away for a week, while the cluster considers it
deleted. The same number is at the endpoint as
`tg_cluster_volume_tombstones`, with the rule
`TardigradeTombstoneNotExecuted`; section 3 names the way out.

**And `tgctl cluster nodes` names the ordinal** (line `ordinal:`). From it
follows a node's subnet and thus every route, every nftables rule and every
`AllowedIP` — with a network problem the first number that counts. A node that
is only registered (`tgctl node upsert`) and not admitted (`tgctl node invite`
→ join) has **none**: the number comes into being at admission.

```
  capacity:   cpu-millicores=6000  (reserved: cpu-millicores=1000)
  measured:   cpu-millicores=8000 memory-bytes=33554432
```

The upper line is **desired** (what is in the log and what the scheduler
takes), the lower one **observed** (what the node counts itself, ADR-0049). A
policy calculates on the lower one; whoever writes it without seeing it writes
blind. `measured:   nothing (no report)` means "nothing heard yet" and not
"nothing" — a node without a session reports no numbers. And an empty `capacity:`
means the scheduler places nothing there that demands resources.

`--site/--hall/--rack` are **mandatory with no default**: a node that silently
ends up in `site=""` lies in the same failure domain as every other one without
a setting, and anti-affinity would be ineffective for both.

The address plan is **checked before it goes into the log**: an unreadable
CIDR, a prefix from which no subnet follows, and a network that no longer fits
the ordinals already handed out are refused. `/16` with `/24` per node carries
**256 nodes**; widening is possible at any time, narrowing only above the
ordinals handed out. If the address space is full, no more nodes are admitted —
and a failure frees no ordinal, only `tgctl node remove`.

What a **sidecar** costs in resources is a setting of its own — the scheduler
adds it to every mesh member:

```
tgctl cluster sidecar-overhead --resource cpu-millicores=100 \
      --resource memory-bytes=67108864
```

Without it the reserve from ADR-0047 is too optimistic by the sidecars' share.

> ADR-0011, ADR-0034, ADR-0049, ADR-0067, ADR-0069.

---

## 3. Running operation

| Intent | Command |
|---|---|
| Workload into the cluster | `tgctl cluster apply <file.xml>` |
| Workload **locally only** (node without a cluster) | `tgctl apply <file.xml>` |
| Withdraw a workload | `tgctl cluster remove <name>` |
| See what the cluster knows | `tgctl cluster show` (edges, **egress**, placement, active role, generation, state per instance), `tgctl cluster nodes` |
| **Retrieve** a definition | `tgctl cluster get <workload> > api.xml` |
| See **what holds cluster-wide** | `tgctl cluster settings` (address plan, sidecar overhead, capacity and rotation policy) |
| See **who may be a node** | `tgctl cluster trust` (key, ordinal, underlay, open invitations) |
| See **what has been deleted** | `tgctl cluster volumes` (tombstones per node, with total) |
| Hints about the desired set | `tgctl cluster lint` |
| Allow/revoke a connection | `tgctl cluster allow\|revoke <from> <to>` |
| Way out | `tgctl cluster allow-egress\|revoke-egress <workload> <name:port[/transport]>` |
| Store/withdraw a secret | `tgctl cluster secret put\|rm <name> [<file>\|-]`, `tgctl cluster secret allow\|revoke <workload> <name>` |
| Registry access | `tgctl cluster registry <host> <secret>`, `tgctl cluster registry rm <host>` |
| See **which secrets exist** | `tgctl cluster secrets` (names, readers, registry assignments — **without the values**) |
| Empty a node | `tgctl node cordon\|drain\|uncordon <name>` |
| Node out of the data plane | `tgctl node detach\|attach <name>` |
| Change keys | `tgctl node rotate <name> identity\|underlay <generation>` |
| Delete a volume | `tgctl cluster delete-volume <name> <node> --yes` |
| See the voters | `tgctl cluster members` |
| Node into the control plane | `tgctl cluster learner <id>`, then `tgctl cluster voters <id>,…` |
| Verify the audit chain | `tgctl audit [<file>] [--anchor <hex>]` |

This table is a **selection** — the intents one has daily. The complete list of
all commands and all switches of the four programs stands in
`docs/COMMANDS.md`; that it is complete is guarded, this table's brevity is
deliberate.

### `apply` and `cluster apply` are two targets

`tgctl apply` writes the **node-local** desired state — the path from phase 2,
for a node without a cluster. `tgctl cluster apply` writes into **consensus**.

On a node with a session the local `apply` is an action that the next slice
**undoes**: it removes what it does not name, and the sweeper then ends the
container. `tgctl` says so:

```text
warning: this node is steered by the cluster (an applied slice lies there).
... For the cluster way: tgctl cluster apply <file>
```

It is not refused: whoever has lost the cluster and has to run something
locally should be able to.

> ADR-0040, ADR-0058.

### A complete definition

Every element the schema knows, in one file. It goes through as it stands —
parsed, dependency graph built, zero lints, volume and placement rules held:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<workloads xmlns="urn:tardigrade:workload:v1">

  <workload name="db" kind="service" class="single-writer">
    <image reference="registry.example.com/postgres:16"
           pullPolicy="if-not-present"/>
    <resources>
      <cpu millicores="2000"/>
      <memory bytes="4294967296"/>
    </resources>
    <readiness port="5432"/>
    <volumes>
      <volume name="db-data" path="/var/lib/postgresql/data"
              mode="readWrite" size="21474836480"/>
    </volumes>
    <placement replicas="2" spread="rack"/>
  </workload>

  <workload name="migrate" kind="job">
    <image reference="registry.example.com/api:1.4.2" pullPolicy="always"/>
    <command>
      <arg>/usr/local/bin/api</arg>
      <arg>migrate</arg>
    </command>
    <resources>
      <cpu millicores="500"/>
      <memory bytes="268435456"/>
    </resources>
    <dependencies>
      <after ref="db"/>
      <requires ref="db"/>
      <before ref="api"/>
    </dependencies>
  </workload>

  <workload name="api" kind="service">
    <image reference="registry.example.com/api:1.4.2" pullPolicy="always"/>
    <command>
      <arg>/usr/local/bin/api</arg>
      <arg>serve</arg>
      <arg>0.0.0.0:8080</arg>
    </command>
    <resources>
      <cpu millicores="500"/>
      <memory bytes="536870912"/>
    </resources>
    <mesh port="8080" udp="8080"/>
    <readiness port="8080" path="/healthz"/>
    <volumes>
      <volume name="tariffs" path="/srv/tariffs" mode="readOnly"
              source="registry.example.com/tariffs:2026-09"/>
    </volumes>
    <placement replicas="3" spread="rack">
      <domain level="site" value="fra"/>
    </placement>
    <dependencies>
      <after ref="db"/>
      <requires ref="db"/>
    </dependencies>
  </workload>

  <workload name="inference" kind="service">
    <image reference="registry.example.com/inference:0.9"/>
    <resources>
      <cpu millicores="4000"/>
      <memory bytes="17179869184"/>
    </resources>
    <mesh port="9000"/>
    <readiness port="9000"/>
    <devices>
      <device kind="nvidia.com/gpu" count="1"/>
    </devices>
    <placement>
      <domain level="rack" value="r7"/>
    </placement>
    <dependencies>
      <after ref="api"/>
      <wants ref="api"/>
    </dependencies>
  </workload>

  <workload name="nightly-report" kind="job">
    <image reference="registry.example.com/report:1.0"/>
    <command>
      <arg>/usr/local/bin/report</arg>
      <arg>nightly</arg>
    </command>
    <resources>
      <cpu millicores="1000"/>
      <memory bytes="1073741824"/>
    </resources>
    <volumes>
      <volume name="reports" path="/srv/reports"
              mode="readWrite" size="10737418240"/>
    </volumes>
    <placement>
      <pin node="node-3"/>
    </placement>
    <dependencies>
      <after ref="db"/>
      <bindsTo ref="db"/>
    </dependencies>
  </workload>

</workloads>
```

Read as a deployment: `db` is the single writer with a volume of its own per
instance, `migrate` runs before `api` comes up, `api` is in the mesh and reads
reference data, `inference` asks for a GPU, and `nightly-report` is nailed to
one node because it writes.

| Element | What it settles | ADR |
|---|---|---|
| `image` | reference and pull policy | 0003 |
| `command` | entrypoint **and** cmd, as a list — there is no shell that splits it | 0003 |
| `resources` | the CPU quota and the memory limit of the container | 0003 |
| `mesh` | the opt-in itself; `port` is TCP, `udp` are QUIC datagrams | 0025, 0142 |
| `readiness` | a TCP connect, with `path` an HTTP `GET` | 0080, 0102 |
| `volumes` | `readWrite` exclusive with `size`, `readOnly` shared with `source` | 0027 |
| `devices` | the CDI *kind* and how many — no device name | 0143 |
| `placement` | `replicas`, `spread`, `domain`, `pin` | 0011, 0034 |
| `dependencies` | ordering (`after`/`before`) and requirement (`requires`/`wants`/`bindsTo`) | 0009 |

**The arguments carry no leading `--` here, and that is on purpose.** They
are the container's own, but `the_handbook_only_names_flags_that_exist` in
`crates/tgctl/tests/handbook.rs` reads every token beginning with two dashes
as an orchestrator switch and demands that a binary know it. It cannot tell
the two apart, so the example stays clear of the form.

**The element order is binding.** The schema is a sequence, not a choice: a
`<mesh>` behind `<placement>` is not read as misplaced but as unexpected, and
the message names the position rather than the intent.

**One file, but not one entry.** `tgctl cluster apply` sends one
`UpsertWorkload` per workload (ADR-0004). If the third is refused, the first
two stand in the log — `tgctl` therefore names what it no longer sent.

Five things this example stays clear of, each of which costs an apply:

- **A `ref` that stands in no file.** The graph is built **before** the first
  write (ADR-0009), and a foreign target is refused there. That a node later
  tolerates an edge across its own boundary (ADR-0061) is a different
  question: the file is checked as a set.
- **`<conflicts>` against something that is also wanted** is refused at ingest
  (ADR-0061). Inside one file that is by definition the case, so the edge does
  not appear here.
- **`class="single-writer"` with one instance.** The lint
  `SingleWriterWithoutStandby` fires: that has the lease's cost and none of its
  benefit. Two instances, each with its own volume, is the HA path from
  ADR-0027 — volume migration is not one.
- **A volume with both `size` and `source`, or with neither.** `readWrite`
  carries the size, `readOnly` the provenance; what is written is not
  distributed, and what is distributed has the size of its content.
- **`<pin>` with `replicas` above one.** A pin names one node, and the
  contradiction is refused at ingest. A writable volume pins on its own —
  without anyone writing `<pin>`.

> ADR-0008 (the schema and its subset: `schema/README.md`), ADR-0009,
> ADR-0011, ADR-0025, ADR-0027, ADR-0080, ADR-0143.

### Replacing a control-plane node

Five nodes (ADR-0031) carry the loss of two. If one fails permanently, it
belongs replaced — and that is **not** something the cluster does by itself:
the membership is a log entry, not a configuration value.

The order is mandatory, and every step has its reason:

1. **Make the new node reachable — on all the others.** Its address into
   **every** `--peer`, its leaf into **every** `peers/<id>.pem`, and the others'
   leaves over to it (ADR-0043). Without that no handshake comes about, and
   replication fails silently — visible only at
   `tg_raft_rpc_failures_total{peer="<id>"}`.

   **These are two manual steps, and whoever forgets the second is told so at
   the next start of a node:**

   ```text
   WARN named peers without a leaf: the handshake to them fails (ADR-0043).
        Every node's leaf belongs as <id>.pem in this directory
        ids="[4]" dir=/var/lib/tardigrade/tgd-1/peers
   ```

   The message names the **id**, not just a number. It appears at startup; a
   running node says nothing afterwards, because it reads the list there once
   (a revocation on the Raft port is an operational action anyway: change the
   list, restart the process).

   **The same on the agent**, there for `control-plane.pem`:

   ```text
   WARN 1 named control-plane nodes have no anchor: the handshake fails
        there. The leaves of all nodes belong concatenated in this file
        endpoints=3 anchors=2 file=control-plane.pem
   ```

   Here it is a **number** and not an id, and that is a boundary: the anchors
   are keyed by node name, the endpoints are addresses — which node sits behind
   an address is revealed only by the handshake.

2. **Start it**, with the same `--peer` list and **without** `--init`: the
   membership already exists, and a second `--init` would be a statement about
   a state that is there.

3. **Admit it as a learner** — on the leader:

   ```bash
   tgctl cluster learner 6
   ```

   The call **waits** until the node has caught up. That is the point of the
   step: whoever skips it takes a voter into the quorum that knows nothing yet
   — the quorum grows, the number of nodes that can answer stays the same.

   **If step 1 is missing** — the address in **this** process's `--peer` — the
   call is refused immediately and names the id. Without this check it
   succeeded (measured: `Changed`), and the next step promoted a node that
   will never answer.

   **How it catches up is told by `tgctl cluster members` beforehand:**

   ```text
   catch-up: from the log (it is complete, nothing was deleted)
   catch-up: by snapshot (log deleted up to 40, snapshot up to 45)
   catch-up: NOT POSSIBLE -- log deleted up to 40, and there is no snapshot
   ```

   The third situation is the one that counts: if compaction has run and no
   snapshot is in place, a new node **cannot** catch up at all — then
   `--snapshot-every` is to be checked before the learner is admitted.

4. **Set the voters** — the **complete** set:

   ```bash
   tgctl cluster members                 # first see who they are
   tgctl cluster voters 1,2,3,4,6        # then set (5 drops out)
   ```

   Not an increment but a state: a delta would be a read-modify-write, and two
   operators would lose each other silently. The change runs as joint consensus
   — both majorities must agree — and that is exactly what holds the quorum
   across the change.

5. **Bring the addresses up to date on all nodes — including where nothing
   happens.** The membership is in the log, the address in **every** process's
   configuration. Whoever forgets one does not notice until precisely that one
   takes leadership. Every node therefore reports it itself:

   ```
   WARN voters without an address in --peer: missing=[6]
   ```

   and `tg_raft_peers_missing` carries the number. `0` is the normal case.

6. **Bring the agents up to date.** `--control-plane` and `--node-session` are
   lists (ADR-0077), and the new node is in none of them: as long as that very
   node leads, the cluster is unreachable for an agent without that entry. Plus
   its leaf in `identity/control-plane.pem` (see 2.1).

**All membership commands go to the leader.** The admin socket is node-local
(ADR-0044); on a follower `tgctl` says who leads and aborts.

#### A switch onto a dead majority has no way back

That is the one dead end of this procedure, and it is not sloppiness in the
tool but a property of Raft:

* `change_membership` needs **quorum** — the majority of the set currently in
  force, **and** that of the future one.
* `--init` does not help: it is only for a **fresh** log and is refused on an
  existing one (`not allowed to initialize due to current raft state`).

So whoever switches onto a set whose majority does not answer cannot take the
change back afterwards. The admin socket is the recovery path (ADR-0044) — but
the command on it needs exactly the quorum that is then missing.

**Therefore `cluster members` states whom the leader reaches:**

```text
node 1 (leads)
voters: 1 2 3 4(silent) 5(silent)
```

And `cluster voters` says so when the named majority would be silent:

```text
warning: of 3 named voters the leader reaches 1, the quorum would be 2.
         Silent: 4 5. A change to that has no way back: a further one needs
         quorum, and --init is refused when a log already exists.
```

**Warned, not refused.** A node can be silent this second and
present the next, and an operator who is in the middle of fixing an outage must
not hang on a snapshot in time.

Two limits of that information belong with it:

* **Only the leader knows.** On a follower the replication view is empty;
  `tgctl` says there that `(silent)` only means "unknown" — and the command ends
  with the pointer to the leader anyway.
* **A control plane that does not state it is not read as silent.** A node
  always puts its own id in, so an empty list is structurally impossible.
  `tgctl` therefore reads it as "this version does not say" and reports it:

  ```text
  hint: this control plane does not name reachability -- (silent) then never
        appears.
  ```

**If the majority really is gone**, the only way left is over the state: secure
the log of the surviving nodes (`tgd --audit-export`, see 3.4), clear away the
data directories of the dead nodes and create the cluster anew with `--init`.
That is a rebuild with data carried over and not a membership change; it
belongs practised before it is needed.

> ADR-0005, ADR-0031, ADR-0043, ADR-0044, ADR-0077.

### What goes along when a workload is withdrawn

`RemoveWorkload` takes the placement, the lease, the `may_talk` edges **and**
the egress permissions with it. The definition is brought back by another
`cluster apply` — **the permissions are not**, because they are in no XML.

> ADR-0025, ADR-0041.

### A sidecar is drained, not torn down

When a mesh member is withdrawn or moved, its sidecar gets `SIGTERM` and
**stops accepting new connections**; running ones are carried to their end.
Only after that does the process end.

Two things follow from that for operation:

- **A stop can take as long as the longest running connection.** The sweeper's
  grace period (10 s) is the upper bound — after that it is removed hard, and
  then the remaining connections break. A workload with long-lived streams is
  thus the case in which a tear-down still occurs.
- **Before, it was always a tear-down.** `tg-proxy` is PID 1 in its container,
  and there the kernel does not apply the default handling of a signal without
  an installed handler: the sidecar survived `SIGTERM`, sat out the deadline
  and was removed. Whoever is used to stop times of ten seconds in the log sees
  them from here on only with genuinely long connections.

The other processes do **not** listen for signals: `tgd` and `tg-agent` are
ended by the supervisor. For them that is inconsequential — running containers
survive it (ADR-0019), and the agent rebuilds its state at startup.

### A drain costs one grace period, not N

All containers the desired state no longer names get their `SIGTERM`
**together**; the ten seconds run for all of them at once. Measured on two
containers that ignore their `SIGTERM`: 20.15 s sequentially against 11 s
together.

Two things follow from that:

- **A node clearing away a hundred containers sends a hundred `SIGTERM` in one
  go.** That is the intent, and on a full node it is load that used to be
  spread out.
- **`reaped` is no longer in the order of the state directory.** It never
  carried a statement; whoever read it read something other than what they
  thought.

**And the self-fence does not wait for that.** It is the first thing in the
pass, before the clearing away and before every start: it takes an instance's
write right away, and its deadline was set by the leader. Until now it sat
behind — a single hanging container delayed it by the full grace period, and
the safety margin the lease calculates with is three seconds.

> ADR-0129, ADR-0064, ADR-0058.

### Volumes

A writable volume survives the withdrawal of its workload and disappears
**only** through `delete-volume`. That is intentional: `cluster remove`
therefore requires no confirmation, `delete-volume` very much does.

The declared size takes effect **at the start of an instance**, before the
mount. A running container is not stopped for it; an enlargement therefore
takes effect with a delay. Shrinking never happens — a size that is too small
is rejected and reported, and the volume keeps its size.

> ADR-0027, ADR-0063.

---

**A deletion stays an instruction until it is carried out.**
`cluster delete-volume` puts a **tombstone** into the state; the node receives
it in the slice and deletes. Afterwards it reports the completion, and the
leader clears the instruction away.

There is **no deadline** for that, and that is a decision: a node that was away
for a week carries the deletion out on its return. If the instruction expired,
the volume would stay behind there while the cluster considers it deleted.

A tombstone that **stays** therefore means: this node has not performed the
deletion. To check:

```bash
tgctl cluster volumes
```

If the node is permanently gone, `tgctl node remove <name>` takes it out along
with its tombstones — and with them the instruction nobody can carry out any
more. **The volume on its disk is untouched by that.**

Four causes are measured: the node is permanently gone, its **report** does not
reach the leader, its tombstone list is **unreadable** — then its log says
`tombstones unreadable` — or the name was a **typo**.

The last case is stated on submission:

```text
warning: 'node-typpo' is not admitted. The tombstone will never be carried
         out there, and it stays in the state until
         `tgctl node remove node-typpo` takes it away.
```

**Warned and not refused**, and the reason is not caution: the same check in
the cluster would cost more than a format change. `DeleteVolume` has been in
the log since phase 10b, and the log is retained (ADR-0020) — two nodes of
different versions would derive different states from the same entry, one with
a tombstone and one without. With the snapshot the same check is free
(ADR-0099), because the command was new.

The number is at the leader's endpoint as `tg_cluster_volume_tombstones`, and
the rule `TardigradeTombstoneNotExecuted` sits on it (one hour: carrying it
out takes seconds).

> ADR-0042, ADR-0104.

### Audit

The log is the audit substrate and is **not** deleted. `--audit-rotate` closes
segments so that they can be moved into the WORM archive — nobody gets at a
permanently open file without a race.

**Explicitly nothing is deleted.** Rotation closes segments, it clears none
away. That is not a leftover but the decision: what lies here is evidence
nobody has yet pushed into the WORM archive, and a deadline or an upper bound
would hit it **precisely when** the export is not running (ADR-0132, the same
inversion as with the tombstones in ADR-0104).

**How much it becomes is computable.** Measured:

| Quantity | Value |
|---|---|
| one record | 414 bytes |
| one lease renewal per single-writer workload | every 9.1 s (ADR-0064) |
| from that, per workload | ~9,500 records/day, 3.7 MiB/day, **1.34 GiB/year** |
| one segment of the default size (100,000) | 39.5 MiB, full after 10.5 days |

The renewal of the active-role lease is thus the largest item in the audit
trail — it has to be consensus-backed (ADR-0064), so it is in the log, and the
log is the substrate (ADR-0020). That is the price of provability and not an
oversight.

**What the node reports about it:** `tg_audit_bytes` (everything, the open file
included) and `tg_audit_segments` (only the sealed ones — that is, what can be
moved away). If the second number keeps rising, nobody is moving anything away
any more. Without these two the first signal was an `apply` that could no
longer write — and that **halts the node** (by intent: a cluster that keeps
running while its audit trail develops holes is the worse outcome).

Two things follow from that for planning: the data directory carries the
archive **and** the Raft log on the same disk, and `--audit-rotate` limits not
only the movability but also the startup — the check when opening costs a
measured 1.18 s with a full segment.

A rotated segment begins in the middle of the chain: `tgctl audit --anchor
<hex>` with the head of the previous segment. Without `--anchor` the check
would certify every segment as being the first.

> ADR-0020, "Segments one can move away".

---

**Moving a segment into the WORM archive.** The whole procedure, measured
against a real archive:

```bash
# 1. What is there? Closed segments first, the running one last.
tgctl audit
#   Segmente:    3
#                audit-1.0001.jsonl (3)
#                audit-1.0002.jsonl (3)
#                audit-1.jsonl (1)
#   Kopf:        e7592a77…
#   Kette: traegt

# 2. Note the head of the segment that is to go — it becomes the anchor of the rest.
tgctl audit <data-dir>/audit-1.0001.jsonl
#   Kopf:        47516334…

# 3. Only then move it.
mv <data-dir>/audit-1.0001.jsonl /pfad/ins/worm/

# 4. The rest carries only **with** that anchor.
tgctl audit --anchor 47516334…
#   Segmente:    2
#   Kette: traegt
```

**Only the running segment is never missing in step 1** — it is called
`audit-<id>.jsonl` without a number, and it is **not** moved: `tgd` appends to
it.

**Without `--anchor` the rest refuses itself**, and that is the guarantee and
not a fault:

```text
tgctl: Audit-Archiv …/audit-1.0002.jsonl:
       WrongAnchor { expected: "000…0", found: "4751…" }
```

A remainder that begins in the middle of the chain does **not** verify against
GENESIS — otherwise the check would certify every remainder as being the
beginning. The anchor therefore belongs **next to** the moved segment in the
archive, otherwise the rest can no longer be verified later.

**What the chain catches and what it does not.** A segment removed
**entirely** from the middle leaves an index jump and a foreign anchor — both
show up. Only the **last** segment remains truncatable; against that only the
head comparison against a running replica helps. `tgctl audit` says so itself
at the end of every run.

**How long a segment stays in the archive is not decided by this system.**
ADR-0020 names no deadline, and it is a regulatory setting per installation
(REMIT/DORA). What is promised here: nothing is deleted, and what is closed can
be moved without a race and recomputed afterwards.

---

**Pulling a segment out of the log.** ADR-0020 requires the export before
compaction, and it is the only way to a verifiable segment when the archive is
missing or can no longer be continued:

```bash
systemctl stop tardigrade-tgd
tgd --id 1 --data-dir <data-dir> --peer 1=http://127.0.0.1:1 \
    --audit-export > segment.jsonl
tgctl audit segment.jsonl
```

**Why `tgd` and not `tgctl`** (ADR-0137): the log is locked exclusively, so the
command only runs with the service stopped anyway — and whoever owns the store
reads it. As of this step the CLI carries neither `openraft` nor `redb` for it
(307 instead of 368 crates in the bill of materials). **Nothing changes about
the procedure.** `--peer` is a formality here: `tgd` requires the setting, but
the one-shot mode builds no connection.

Three things about this, and all three count:

- **Only with `tgd` stopped.** `redb` lets exactly one process at the log; if
  the service is running, the command ends with a note to that effect.
- **Without `--audit-from` the export begins at what is still there** — behind
  the last index compaction deleted. An explicit range before that is
  **refused** and not truncated: measured, the log returns an empty list for
  deleted indices and no error, a truncated segment **verifies** (its chain is
  gapless in itself), and an auditor would take an incomplete proof for a
  complete one. Where the boundary lies is told by `tgctl cluster members`
  (line `aufholen:`) — and the error message names it too.
- **It is not a repair.** The log carries commands, not results — the segment
  lacks the **verdicts**, and its digests are therefore different from those of
  the lost archive. It is a proof about the log's content, not the continuation
  of the old chain.
- **A damaged archive keeps `tgd` from starting** (that is intentional:
  otherwise the next start would sign the forgery). The way out is to set the
  damaged segment aside as evidence, pull the export and then begin a new
  chain — not to delete the file silently.

### A changed declaration takes effect at the next start

`tgctl cluster apply` files the intent. A **running** container is not touched
by it — no new image tag, no new command, no new resources (ADR-0070). The
reason is ADR-0019: a setting somebody has just typed must not cost a running
workload.

It is visible at `tg_workload_stale` and, with `tg-agent --once`, in the
message "run from an older declaration".

**How a change takes effect** (ADR-0071): with a **decree**. It is a monotone
number in the log — the node restarts an instance whose bundle carries a lower
one.

```bash
tgctl cluster show                               # which generation applies?
tgctl cluster apply api.xml                      # file the intent
tgctl cluster restart api 1 --instance 0         # restart instance 0
# … check: tgctl cluster show
tgctl cluster restart api 1 --instance 1         # then the next one
```

`tgctl cluster show` names the decreed generations (`generation: 2
(individually: 1=5)`); without a decree the line is not there. The **effective** generation of
an instance is the maximum of both levels — which is why the output shows both
and not one computed number.

- **The number comes from you**, not from a "current + 1": two operators
  decreeing at the same time would otherwise both arrive at the same one, and
  one would lose out silently. Backwards is rejected, equal is already done.
- **Without `--instance` all instances restart.** With `replicas > 1` that is
  an outage — there is **no health gate per workload** (see section 4), so the
  system cannot choose the order itself. It is up to you.
- **The restart is a stop with a grace period** (10 s) and a start from the
  current declaration. Whether the new generation comes up is told by `tgctl
  cluster show` — the decree does not wait for it.
- **The action is in the log**, with an actor (ADR-0050) and in the audit
  archive (ADR-0020). A restart by hand is not.

The two old ways still work: `tgctl node drain <node>` moves the instances
(not those with a writable volume — they are node-pinned), and the container
can be ended by hand with the OCI runtime (its state directory is
`<data-dir>/runtime`).

**Not covered:** a moving tag. What is compared is the **declaration**, not the
resolved image — whoever runs `:latest` with `pullPolicy="always"` gets no
information from this number (ADR-0070, decision 3).

> ADR-0070, ADR-0071, ADR-0019, ADR-0063.

---

### A listener that cannot accept
```text
WARN does not accept -- waiting  error=Too many open files (os error 24)
```

The process is short of descriptors (or buffers, or memory). The listener
**does not end** and does not spin either: it waits half a second and tries
again — so at most two messages per second. The remedy is `LimitNOFILE`, not a
restart.

That holds for every port of this system: the resolver (UDP and TCP), mesh,
egress, the telemetry endpoint, the three cluster ports, the workload API
socket and the admin socket. Until now the resolver ended at this point
**silently**, and every container on the node lost name resolution until the
agent restarted.

> ADR-0013, ADR-0019, ADR-0022.

### A single writer that runs and does not answer

The one incident this system **deliberately** does not fix by itself.

If a single writer holds the active role and its probe does not answer, it
stays that way until a human acts: the lease hangs off the **node's report**
and not off the probe. The warm standby next to it does not take over.

That is a choice and not an omission. A change of role lets the standby come up
on **its own** volume — a writable volume is not moved (ADR-0027) — and thus on
a different set of data. A false-negative probe, and an overloaded workload
does not answer, would thereby trigger a data split; two overloaded instances
would flap until neither works any more.

It is reported by `TardigradeActiveRoleWithoutReadiness` (`critical`). The
remedy:

```
tgctl cluster restart <workload> <generation>
```

**A restart does not take the instance's role away** — it stays instance 0, the
lease runs on, and it comes back with the same volume. That is the difference
from a change of role, and in almost all cases it is what is meant.

If the standby really is to take over, the way is a different one and
explicit: withdraw the workload, check the volume, declare it anew. There is no
button for it, and that is intended.

> ADR-0101, ADR-0064, ADR-0080, ADR-0027.

---

### What is audited about a secret — and what is not

An auditor asks this question, and the answer is **not** "every access":

| Event | Where it is |
|---|---|
| Who stored a secret | log (`put_secret`) with actor, permanently (ADR-0020, ADR-0050) |
| Who **may** read it | log (`allow_secret` / `revoke_secret`) |
| That a container **received** it | the node's log: `Secrets zugestellt`, with container, workload and **names** |
| That a revoked value **disappeared** | the node's log: `widerrufenes Secret entfernt` |
| That the workload **read** the file | **nowhere** |

The last row is the consequence of ADR-0098: a secret arrives as a file in a
tmpfs, and a `read(2)` produces no event this system sees. A read audit would
require a service with mTLS — and with it a workload that can speak it; and
that is exactly what ADR-0007 rules out (*"transparent mTLS even for
third-party images"*).

**The values never contain a plaintext** — neither in the log (the ciphertext
lies there, ADR-0095) nor in a log line.

Among its consequences ADR-0016 says *"every secret access is
identity-bound and audited"*. **Identity-bound** holds, and more strongly
than meant there: the mount *is* the authorisation, per container (ADR-0098).
**Audited** holds for the delivery and not for the reading — the sentence is
too strong in that half, and that belongs said before somebody passes it on as
a promise.

> ADR-0016, ADR-0095, ADR-0098.

### Rotating the data key

**When.** Three occasions, and the first is the one easily overlooked:

| Occasion | Why |
|---|---|
| **A node was removed** | `RemoveNode` takes trust and ordinal — **not the disk**. `identity/secrets.key` lies on it |
| A key has gone missing | the same, only without the node |
| On a schedule | an operational setting; this system knows no cadence |

The first weighs more than it looks, and that is measured: the **ciphertext is
in the log** and therefore in the audit archive, which is retained and moved
into the WORM archive (ADR-0020). Whoever has the disk of a removed node **and**
a copy of a segment reads every secret from that key's period of validity. The
disk therefore belongs erased — and as long as it lies somewhere, the key
belongs rotated.

`tgctl node remove` says so, but only if there are any secrets at all: a
warning that always appears is overlooked precisely where it counts.

**What a rotation does not heal:** the old ciphertext stays in the log. Whoever
ever gets hold of the superseded key reads the values of its period of
validity — that is the flip side of a log with a retention obligation
(ADR-0020) and not a gap. A secret that really is compromised belongs changed
at its issuer, not merely resealed.

---

All the cluster's secrets are sealed with **one** key (ADR-0095). Rotating it
means resealing every value — and that is a procedure with five steps, three of
which a human performs on every node.

The reason for the order is the one trap in it: with **one** key there would
inevitably be a moment in which the cluster holds the new one and the values
still carry the old — then nobody opens anything, and **every container with
secrets stops starting**. Therefore, during a rotation, the cluster holds two:
one for sealing, **both** for opening.

```
# 1. Generate the new key
tgctl secret keygen > /tmp/neu.key

# 2. On EVERY tgd node: the old one alongside, the new one in its place
cp <data-dir>/identity/secrets.key <data-dir>/identity/secrets.key.previous
cp /tmp/neu.key <data-dir>/identity/secrets.key
chmod 600 <data-dir>/identity/secrets.key*
#    ... and restart the process

# 3. Wait until EVERY node carries the new key -- or restart the agents
#    so that they fetch it right away:
#    count(count by (fingerprint) (tg_identity_data_key_info)) == 1

# 4. Rekey
tgctl cluster secret rekey

# 5. Wait until tg_cluster_secrets_previous reads zero

# 6. On EVERY tgd node remove the old one
rm <data-dir>/identity/secrets.key.previous
#    ... and restart the process
```

**Step 3 is the one people overlook.** The agents get the key ring over the
credential path, so **up to three hours** after step 2 (ADR-0095). Whoever
rekeys before that has values in the log that some of the nodes cannot open —
and then: **running containers stay untouched**, but every **start** of a
container with secrets fails (`secret '…' cannot be opened`, ADR-0098
decision 7). A crashed workload thus stays down, a decreed restart generation
has no effect, and a placement onto such a node does not come up.

Where to look: `tg_identity_data_key_info` — `tgd` **and** agents report it,
and `count(count by (fingerprint) (…))` is `1` exactly when they all agree. A
restart of an agent fetches the key ring immediately.

**Step 5 is not decoration.** Whoever removes `secrets.key.previous` before the
number is zero makes every value that has not been rekeyed **unreadable** — and
the container that needs it stops starting. The alert rule
`TardigradeRotationStalled` catches a rotation that is not through after
six hours.

**And step 6 is the one people forget.** `tg_cluster_secrets_previous` stands
**only** as long as the file lies on a node — so a zero means "everything is
rekeyed, and the old key is still lying there anyway". That is a **security**
leftover and not a functional one: whoever ever gets hold of the file reads
every ciphertext of its period of validity out of the log, and that is retained
(ADR-0020). Reported by `TardigradeRetiredKeyStillPresent`. The
**agents** clear their copy
by themselves: if the key is missing from their next answer, they remove it —
the manual step applies to the `tgd` nodes.

Two things about this:

- **The agents get both keys by themselves**, with their next renewal — at the
  latest after three hours, and a restart fetches them right away. If the
  superseded one is missing from the answer, the agent **removes** its copy:
  its absence is the statement "the rotation is finished".
- **During step 2 two `tgd` report different keys.** That is expected, and
  `TardigradeDataKeysDiverge` therefore has a generous
  deadline — but it means: step 2 belongs done on all nodes in quick
  succession.

> ADR-0100, ADR-0095, ADR-0016.

---

### Snapshot and restore of a volume

For a single-instance workload with a writable volume, snapshot/restore is
**the** recovery path and not an addition: the volume is node-pinned, and if
the node fails the workload is **not** started elsewhere — the scheduler
refuses, because it would otherwise silently give up the data.

An operator decrees a snapshot through the log:

```
tgctl cluster snapshot-volume daten-0 node-3 1
```

The number is a **generation**, monotone. The node compares it with its mark
and creates the snapshot as soon as the next slice reaches it; if it was away
just then, it catches up on its return. Backwards is rejected, equal is already
done.

**Four things about this belong in mind before relying on it:**

- **The snapshot is crash-consistent, not application-consistent.** The file
  system in the volume is frozen for the duration of the copy, the journal is
  flushed — the snapshot looks like a clean power cut. A database in the middle
  of a transaction rolls back when opened. Whoever needs more makes their own
  dump and sends it out over the egress path.
- **It blocks writers for the duration of the copy.** On a host with reflink
  (xfs with `reflink=1`, btrfs) that is milliseconds — measured 74 ms for
  512 MiB, and the copy occupies **zero** additional blocks. Without reflink it
  is a real copy, and the blockage grows with the size. The file system of the
  data directory thus decides whether a snapshot is bearable in running
  operation.
- **It lies locally**, under `<data-dir>/volumes/<name>/snapshots/<generation>`,
  on the same disk as the volume. That by itself is not yet DR. What the
  orchestrator provides is the consistent point-in-time state as a **closed
  file**; getting it into the archive is operational work — the orchestrator
  provides no object store.

- **If the agent is ended during the copy, the volume stays frozen** — and that
  is more than a blockage: a writer on a frozen file system sits in the **D
  state** and is therefore **unkillable** (measured: `SIGKILL` does not reach
  it, only thawing lets it continue). A signal does not reach the release, so
  the **start** heals it: the agent thaws every mounted volume as it comes up
  and says so if one really was frozen. By hand it works the same way:
  `fsfreeze` with the thaw switch on `<data-dir>/volumes/<name>/mnt`. The call
  is harmless when nothing is frozen (`EINVAL`).

How many generations remain is set by `--keep-snapshots` on the agent (default
3, `0` means all). The oldest are cleared away, and **the number is the only
limit** — there is no deadline, and that is a decision (ADR-0104): a snapshot
comes into being only because a human decreed it (ADR-0099 explicitly rejects a
cadence), and an age limit would thereby delete the oldest recovery point an
operator deliberately kept. Where a generation goes beyond that is archive work
as with the audit segment.

Restoring happens **on the node**, not through the cluster:

```
tgctl restore-volume daten-0 1 --yes
```

The difference is intentional. A snapshot is additive; a restore overwrites. A
decree in the log would be level-triggered and would take hold again on every
loss of the mark — it would then overwrite what the application has written
since the snapshot. And a recovery path should not hang off the cluster.

The restore requires an **unmounted** volume: first stop the workload
(`tgctl cluster remove` or `tgctl node drain`), then restore. What it
overwrites it secures beforehand as a generation of its own — that is the only
trace it leaves, because it is in **no** log.

> ADR-0099, ADR-0027, ADR-0020 (deadlines), ADR-0044.

---

## 4. What is **not** enforced

### A container runs as the node's `root`

ADR-0017 names three defaults as "on by default": user namespace, seccomp,
no-new-privs. Measured, **one** of them is on.

| Default | State |
|---|---|
| `noNewPrivileges` | on — a setuid binary in the image gains no rights |
| capabilities | narrow: `AUDIT_WRITE`, `KILL`, `NET_BIND_SERVICE` |
| masked and read-only paths | set (`/proc/kcore`, `/proc/sys`, …) |
| **seccomp** | on since ADR-0090 — see "Hardening the containers" |
| **user namespace** | **off**, except with `--userns-base` (ADR-0091) |

The last row is the operationally important one. Without the setting `uid 0` in
the container **is** `uid 0` on the node: the isolation then rests on
namespaces, capabilities, seccomp and the mounts, **not** on a user id. Whoever
runs an image with `USER 0` and mounts a volume writes there with the node's
rights.

Why the setting is necessary and not the default is in ADR-0091: with
**youki** — the default runtime from ADR-0003 — a container of this system gets
no user namespace. Measured, even the bind mount of the rootfs fails
(`EACCES`), because youki performs it from inside the new namespace.

Without `--userns-base`:

- Prefer images with a user id of their own. The sidecar shows how: it runs as
  `65532`.
- Do not put a volume on a directory whose content the node itself needs.

### A decreed change swaps the rootfs (ADR-0120)

`tgctl cluster restart <workload> <generation>` after a changed declaration
**remounts** the rootfs — with the layers of the image the declaration now
names — and discards the ephemeral volume (`upper`) in the process.

**Until ADR-0120 it did not**, and that is a correction and not an extension:
`build` took the existing mount, and that carries the old layers. A changed
image thus reached the `config.json` and **not** the file system — the
container ran with the new command line and the old content. A security update
in a base image **never** arrived at the workload.

- **The `upper` goes along, and that belongs to it.** A writable layer from
  image A over image B lays itself over exactly those files the old container
  once touched — the new version would be invisible there.
- **An unchanged declaration keeps both.** A restart after a crash runs on the
  same layers; there is nothing to correct, and the traces of the crash remain.
- **A moving tag stays invisible.** Whoever runs `:latest` does not change
  their declaration — then nothing is remounted either (ADR-0070, open point).
  Whoever wants the swap names a version or a digest.
- **It takes longer** when a lot lies in the `upper`: discarding it is a
  `remove_dir_all`. It affects the decreed change, not the restart after a
  crash.

> ADR-0120, ADR-0070, ADR-0071, ADR-0027.

---

### A withdrawn workload loses its scratch area

If an operator withdraws a workload (`tgctl cluster remove <name>`, or the node
loses the assignment), the reconciler clears away — and since **ADR-0119** the
**bundle** belongs to that: `bundles/<workload>/rootfs` is unmounted, the
directory removed.

- **The `upper` is gone, and that is the guarantee.** It is the ephemeral
  volume (ADR-0027) that dies with the container. Until ADR-0119 it survived
  it — and a name that later came back onto the same node inherited its
  predecessor's writable layer.
- **This is a behavioural change.** Whoever used `remove` and `apply` as a
  detour for a restart gets an empty `upper` from now on. For a restart there
  is the direct way: `tgctl cluster restart <workload> <generation>`
  (ADR-0071).
- **Persistent volumes are not affected.** They lie under `volumes/`, have a
  life cycle of their own and are removed only with
  `tgctl cluster delete-volume` (ADR-0027, ADR-0042).
- **A fence does not clear away.** A fenced instance stays desired; its rootfs
  stays in place (ADR-0064).
- **A container that would not end keeps its bundle.** Unmounting its rootfs
  while it runs would be the worse outcome. The next pass tries again.

> ADR-0119, ADR-0058, ADR-0027.

---

### The cgroups under `/tardigrade`

Every container gets a cgroup under `/sys/fs/cgroup/tardigrade/<id>` —
**specified and not left to the runtime**, because ADR-0006 bound the identity
to it and `youki` would otherwise create `/:youki:tg-api`.

- **The roof stays.** `/sys/fs/cgroup/tardigrade` comes into being with the
  first container and does not disappear again. That is not a leftover: it
  belongs to the node, not to a run.
- **The children are cleared away by the normal path.** On stopping, the
  reconciler deletes the container through the OCI runtime, and that removes
  the cgroup with it — measured across five container tests, none was left
  behind.
- **An abnormal ending can leave an empty one behind**: a killed process, a
  runtime that does not manage the deletion. It costs little and accumulates.
  Clearing it away is an `rmdir` and fails as long as a process is still in it:

  ```sh
  for c in /sys/fs/cgroup/tardigrade/tg-*; do rmdir "$c" 2>/dev/null; done
  ```

  The orchestrator does **not** do this by itself. A sweep that removes empty
  cgroups would also hit those a runtime has just created and not yet filled —
  and would thereby take a start with it instead of a leftover.

> ADR-0006, ADR-0118.

---

### The sidecar gets a memory limit and no CPU quota

A declared workload gets its limits from `<resources>`. Its **derived
sidecar** has no declaration — it comes into being on the node (ADR-0059) — and
its limit therefore comes from the **overhead per mesh instance**
(`tgctl cluster sidecar-overhead`, ADR-0067). What the scheduler books is from
here on also enforced by the kernel (ADR-0086).

- **Only the memory.** The overhead is generic and can name `cpu-millicores`;
  what is enforced is **exactly one** entry. A CFS quota on a proxy produces
  throttling pauses — precisely the standstill against which ADR-0022 built
  thread-per-core. With the CPU the damage is slowness, with memory it is loss:
  a sidecar under the OOM killer takes **all** its node's workloads with it
  (ADR-0019).

  **Measured since then, and the result is sharper than the reasoning**
  (ADR-0086, ADR-0114): a quota is **a cliff, not a slope**. As long as it does
  not bite it costs nothing — up to 100 % of demand nothing is
  distinguishable from unthrottled. When it bites, p99.9 jumps by a **factor of
  70 to 120** (0.66 ms to 47–81 ms), while the median stays almost untouched.
  The height is the CFS period: whoever is throttled waits for the next one.

  **What follows from that for an operator**: setting a quota by hand on a
  sidecar's cgroup is not a small precaution. It looks good in every test as
  long as it does not bite, and costs two orders of magnitude at the tail on
  the first day of load peaks — where nobody is looking, because median and p99
  stay calm.
- **No overhead, no limit.** That is the default from ADR-0067 and at the same
  time the behaviour from before this step. Whoever wants it sets it:
  `tgctl cluster sidecar-overhead --resource memory-bytes=67108864`.
- **It takes effect at the sidecar's next start**, like every changed
  declaration (ADR-0070). Whoever wants it immediately decrees a restart
  (`tgctl cluster restart <workload> <generation>`) — that reaches the
  sidecar too (ADR-0085).
- **And next to it the per-node reserve helps** (`tgctl node upsert --reserve`,
  ADR-0047): it is coarse, but it keeps free air that no workload books.

These points are decided and lie with the operator:

- **Revocation on the Raft port is an operational action**, not a consensus
  command: change the peer list, restart the process. Intentional — a recovery
  of consensus must not presuppose it. (ADR-0043)
### `--trust-domain` belongs on **all** processes

It is the first component of every SPIFFE id (ADR-0006) and must be the same
cluster-wide: `tgd`, `tg-agent` — and the **sidecar** gets it, as of this step,
from the agent's setting. Before that, the derived command line did not carry
it (ADR-0059 fixes it, an operator does not reach it by hand), so the sidecar
took its own default `cluster.local` and ended with

```
no anchor for cluster.local
```

A cluster with a different trust domain could therefore run **no** mesh
workload. Whoever runs their own domain and has sidecars running should let
their containers restart once
(`tgctl cluster restart <workload> <generation>`) so that the new command line
takes hold.

### The zone has a length limit (RFC 1035)

The same arithmetic one layer further: a query is `<workload>.<zone>`, and a
DNS name may be **253 bytes** long. `--dns-domain` is checked on its own — a
zone of 251 bytes is valid, and afterwards **nothing** resolves any more,
because every query breaks the 253. The agent says so at startup:

```
WARN in this zone only a workload name of at most 1 character resolves;
     longer ones yield a query over 253 bytes and thereby NXDOMAIN
```

With the default `tardigrade.internal` (19 bytes) the zone carries the whole
name facet; no warning appears then. **Fail-soft:** the node network keeps
running — bridge, addresses and rule set stand, and a container reaches its
neighbours over the address. What is missing is resolution.

And when **nothing at all** fits any more (a zone of 252 bytes or more), it is
no longer a `WARN`:

```
ERROR this zone leaves room for no name -- **nothing** resolves
```

#### Why the zone is a per-node setting (ADR-0106)

It is the same string cluster-wide and nevertheless is **not** in consensus —
unlike the cluster CIDR (ADR-0069). The reason is measured: the resolver zone
and the `search` line in the container come from the **same** setting, so a
node is consistent in itself, and a container that addresses its dependency by
the **bare name** resolves on every node.

Two things follow from that for operation:

- **A zone change is possible in a rolling fashion** — node by node, without a
  maintenance window. A running container keeps its old `resolv.conf` until its
  next start (`tgctl cluster restart <workload> <generation>`).
- **A divergence costs exactly the fully qualified names.** Whoever has
  `api.tardigrade.internal` in a workload configuration instead of `api` finds
  their target on one node and not on the other. `tg_cluster_dns_zones` says
  that there is more than one; `tgctl cluster nodes` says which.

**No** log entry says who changed it — the zone does not go through consensus
(ADR-0106, costs).

### The data directory has a length limit (ADR-0081)

Every instance gets a Unix socket of its own under
`<data-dir>/sockets/tg-<workload>-<instance>.sock`, and a Unix socket path may
be **107 bytes** long — `sun_path` holds 108 (measured).

From that follows a budget: with a workload name the schema allows (63
characters), **24 bytes** remain for `--data-dir`.

| `--data-dir` | Bytes | maximum name |
|---|---|---|
| `/var/lib/tardigrade` | 19 | 68 — fits entirely (the facet is 63) |
| `/var/lib/tardigrade/node-1` | 26 | **61** |
| `/srv/tardigrade/data` | 20 | 67 — fits entirely |

**The same limit applies to the admin socket** (`<data-dir>/admin-<id>.sock`,
ADR-0044) — and there it bites much later: the name is short, leaving **94
bytes** for `--data-dir` (with `--id 1`; a twenty-digit id
costs 19 of them). Whoever keeps within the workload socket's budget keeps
within this one automatically.

On a node that runs **only** `tgd` the workload budget does not exist, though,
and then the admin socket is the only limit. `tgd` then does not come up and
says what the cause is:

```
tgd ended: the admin socket '/…/admin-1.sock' is 108 bytes long, the limit
is 107 (sun_path); choose a shorter --data-dir: 94 bytes remain for it
```

Without this bar all that stood there was `path must be shorter than SUN_LEN` —
the message from `std`, without a path, without a number, without a remedy.
**There is no warning level here** as with the per-instance socket: the path is
fully determined by the data directory and the id, so the question is binary.

**The second row is the obvious one**, because ADR-0043 requires a data
directory **per node** — and it breaks the limit already with a name the schema
allows. The agent says so at startup:

```
WARN with this data directory only a workload name of at most 56 characters
     fits into the socket path; longer ones get no socket, and their containers
     do not start (ADR-0081)
```

Whoever skips the line sees it at the first start of a workload named too
long — there with the same number and the same levers. **The container then
does not start** (ADR-0081, decision 4: no socket, no identity).

Two levers, and the first is the better one: a **shorter** data directory (the
node number need not be in the path — two nodes do not share a disk anyway), or
shorter workload names.

- **The admin socket does not authorise.** Whoever reaches it (`0700`) may do
  everything: write workloads, cordon nodes, delete volumes. That is decided
  and not open (ADR-0105, decision 4): it is the recovery path. Over the
  **operator port** the five classes apply — see "What an enrolment may do".
  (ADR-0044, ADR-0050, ADR-0103, ADR-0105)
- **A node key is valid on the cluster port indefinitely.** Rotation there is
  replacement. (ADR-0043)
- **No thresholds.** The alert rules lie in `docs/alerts.yml` and are loadable —
  **direction** and **`for:` duration** are in them, the first from the ADRs,
  the second computed from this system's cadences. What is missing are the
  **thresholds**: whether 80 % of the descriptors or one second of clock skew
  are the right numbers for *this* installation is told only by its operation.
  They stand at starting values and are named as such. (Phase 11b, ADR-0015)
- **No auto-detach.** A node that goes silent is not detached — a failure must
  not produce a decree. Detaching is done by a human;
  `tg_node_last_report_timestamp_seconds` makes the silence visible. (ADR-0057)
- **`--no-quorum` on the agent changes nothing today.** Measured, **every**
  action an agent checks at the autonomy boundary is autonomous: the
  quorum-bound decisions from ADR-0010 all lie with the leader — the scheduler
  places, the leader grants leases, mutations go through the log. The switch is
  thus prepared and without effect; a test demands attention as soon as that
  changes. (ADR-0010, ADR-0011)
- **No fencing against a lying node.** The active role is enforced locally; that
  protects against a detached, honest node, not against a compromised one.
  (ADR-0066)

---

### Liveness and readiness

`/livez` and `/readyz` at the telemetry endpoint. The separation is the one
from ADR-0019 and more important than it looks: **loss of quorum makes a node
not-ready, not dead.** If liveness hung off the quorum, a partition would hit
the whole minority side with restarts — and with them the workloads that are
supposed to keep running.

`/livez` names every observed loop along with its idle time:

```
ok
raft: 0s
scheduler: 0s
```

`scheduler` is the loop that writes placements and **renews** the active-role
leases. If it stands still, the single writers fence within 15 s; that is why
it is observed and a restart is the right answer.

> ADR-0015, ADR-0019, ADR-0064.

---

### The workload API sockets

Every container gets **its own** socket under
`<data-dir>/sockets/<container-id>.sock`, mounted into it as
`/run/tardigrade/workload-api.sock` (ADR-0081). The socket **is** the
attestation: whoever reached it is inside that container.

**The directory must be `0700` and owned by `root`** — the separation rests on
that. The sockets in it carry `0666` so that a sidecar reaches them under its
own id (ADR-0060); what separates is the directory plus the bind mount that
bypasses it. The agent sets both itself; whoever changes the permissions by
hand opens every workload identity to every local user.

**The kernel floor has thereby fallen away.** Until ADR-0081 the attestation
required `SO_PEERPIDFD` (Linux 6.5), and below that **no workload got an SVID**
— the default kernels of widespread long-term distributions are below it. The
identity path now runs on every kernel with cgroup v2.

**What `root` can do:** dial a socket directly and thereby fetch that
instance's SVID. That is not a new boundary — `root` reads the agent
intermediate under `<data-dir>/identity/` and mints for itself (the same
argument as with the admin socket, ADR-0044). For everybody else the directory
is the boundary.

### An operator over the network

Without `--operator-listen` everything stays as it was: administration goes
over `<data-dir>/admin-<id>.sock`, and whoever reaches the socket may do
everything (ADR-0044). **The socket remains afterwards too** — it is the
recovery path and hangs off no cluster.

With the port it goes over the network (ADR-0103). The order:

```
# 1. The operator generates their key pair -- on THEIR machine.
tgctl operator keygen > dana.key.pem        # two lines: key + spki:
chmod 600 dana.key.pem

# 2. Somebody with shell access enrols it -- over the socket.
#    --class is mandatory (ADR-0105); there are five:
#    read, secrets, write, membership, operators
tgctl operator enrol dana <the spki line without the prefix> --class read,write

# 3. The anchors: the cluster leaves of all tgd nodes, concatenated.
cat node-1.leaf.pem node-2.leaf.pem ... > anchors.pem

# 4. And the port must be running -- on every node that can become leader.
tgd ... --operator-listen 0.0.0.0:7005
```

After that every command of the verb groups `cluster` and `node` takes the four
settings:

```
tgctl --peer 10.0.0.1:7005 --operator dana       --operator-key dana.key.pem --anchors anchors.pem       cluster show
```

| | Socket | `--peer` |
|---|---|---|
| What is recognised | the **uid** (`SO_PEERCRED`) | the name in the **certificate** |
| What is in the audit trail | `uid:0` | `operator:dana` |
| Prerequisite | shell on the node, `0700` | an enrolment in the log |
| Recovery | **yes**, hangs off no cluster | no, needs the log |

### What an enrolment may do — the five classes (ADR-0105)

`--class` is **mandatory** and has no default: a default would be a decision
you did not make.

| Class | Allows | Damage if misused |
|---|---|---|
| `read` | `cluster show/nodes/settings/lint/get/volumes/secrets`, `audit` read paths | disclosure of topology and definitions |
| `secrets` | `cluster secret rekey` (fetches the ciphertexts) | **with the data key: every secret** |
| `write` | the command set — `apply`, `remove`, `allow`, `restart`, `node upsert`, … | outage, data loss |
| `membership` | `cluster membership learner/voters` | loss of the cluster |
| `operators` | `operator enrol/revoke` | all of the above, **and** persistence |

**One class contains no other.** Whoever wants to read and write gets both:
`--class read,write`. A monitoring node gets `--class read` alone — that is the
case for which the classes exist even with **one** human.

**`operators` is the most dangerous**, and that is why it is one of its own:
`Write` takes the whole command set, so without this separation a holder of
`write` could enrol a second identity with every class. Hand it out as
sparingly as `root`.

Who holds what is told by:

```
tgctl operator list
```

**After the upgrade nothing is restricted at first.** An entry written before
ADR-0105 carried no `classes` field and **meant** "may do everything" — the
default must mean what the entry meant (ADR-0020). For an operator with the
full set, `tgctl operator list` explicitly adds that this can be the default of
an old entry. Restricting means **enrolling anew** — the same command with
`--class`.

**The socket stays unclassified** (ADR-0105, decision 4). Whoever reaches it
may do everything; classifying it would mean making the recovery path depend on
what it recovers — and whoever has shell access and `0700` can halt the process
and read the disk anyway.

**Four things one can forget:**

- **The three settings belong together.** `--peer` without `--operator`,
  `--operator-key` or `--anchors` is **refused** and does not fall back to the
  socket — a command that silently hits the local node writes somewhere other
  than intended.
- **The port must be running on the leader.** A follower answers with the
  referral, and `tgctl` aborts (the same `ForwardTo` as on the socket). Whoever
  does not want to guess gives `--peer` for the node that is currently leading.
- **A revocation takes effect on the next request.** The classes are read from
  the log on **every** request, so a revoked enrolment holds nothing from then
  on — every path and every command is refused. The connection itself stays
  open, and a restart of `tgd` **gains nothing** by it: it takes away the
  recovery path for its duration in order to close a connection that has no
  authority left anyway. (ADR-0103 decision 5 still names the restart as a
  remedy — it is superseded by ADR-0105.)
- **The name stays in the log forever** (ADR-0020). Whoever does not want that
  takes a pseudonym and keeps the mapping elsewhere.

### What a node mounts

Three kinds, and an operator looking for leftovers needs all three:

| Where | What | Who clears it |
|---|---|---|
| `<data-dir>/bundles/<name>/rootfs` | overlayfs per workload name | stays mounted (ADR-0058) |
| `<data-dir>/volumes/<name>/…` | ext4 over a loop device per volume | the reconcile while clearing away |
| `<data-dir>/secrets/<container>` | tmpfs per container, `mode=700` | the reconcile while clearing away (ADR-0098) |

The third is the newest and the one overlooked when searching:
`grep tmpfs /proc/mounts` finds it, `grep overlay` does not. It holds
plaintext, which is why the agent unmounts it **immediately** and not lazily.

### What is shipped — the bill of materials

`docs/sbom.cdx.json` is the product's bill of materials (CycloneDX 1.5,
ADR-0134): **387 components**, the normal dependency closure of the four
shipping units for `x86_64-unknown-linux-gnu`.

```bash
# what is inside tgd?
jq -r '[.dependencies[] | select(.ref=="pkg:cargo/tgd@0.1.0")] | .[].dependsOn[]' \
   docs/sbom.cdx.json

# which licences occur?
jq -r '.components[].licenses[0].expression' docs/sbom.cdx.json | sort | uniq -c
```

Four things an auditor wants to know:

- **It is smaller than `Cargo.lock`** — 387 against 494 packages. The rest are
  development and build dependencies and packages for foreign platforms; they
  are not shipped.
- **Programs that are invoked instead of linked are not in it**: `nft`,
  `losetup`, `mkfs.ext4`, `resize2fs`, `cryptsetup`, `fsfreeze` as well as youki
  or crun. They are operational prerequisites and are in section 1.
- **All components name a licence** — including our own fifteen: the product is
  under **Apache-2.0** (ADR-0139), the text lies as `LICENSE` in the root. The
  licence and rights holder of the product itself are **above** the list, in
  `metadata.component`: `jq '.metadata.component' docs/sbom.cdx.json`. Until
  then they stood there as `NOASSERTION`, and that was an open decision and not
  an oversight of the tool.
- **There is no `NOTICE`, and that is intentional.** None of the 372 foreign
  components brings one; our own would be a redistribution obligation we invent
  and pass on to every recipient (Apache-2.0 §4d).

It is **undated and sorted**, so byte-identical on every run — and
`cargo xtask sbom --check` runs in the gate so that a new dependency appears in
the diff of a pull request and not in an artefact somebody produces later.

> ADR-0134, ADR-0023.

### How the shipping build is made

```bash
cargo xtask release
```

That is the build whose product is shipped — **not** `cargo build --release`.
The difference is not a convenience.

Absolute paths of the build machine in the finished binary:

| Unit | `cargo build --release` | `cargo xtask release` |
|---|---|---|
| `tgd` | 633 | 0 |
| `tg-agent` | 823 | 0 |
| `tgctl` | 492 | 0 |
| `tg-proxy` | 407 | 0 |

They are the `file!()` locations of the `panic!` sites **in the dependencies**.
They have two consequences: a panic prints the build machine's home directory
in operation into a stream ADR-0020 retains — and two build machines with
different user accounts yield different binaries. `strip = true` does not clear
them away; they are not debug data.

The run maps `$CARGO_HOME` onto `/cargo`, builds the four units into
`target/release-build/release/`, **then verifies its own product** and names
the digests:

```text
tgd       1ed0ed0dfddfa68516330aee096dcedd23fad773d90b303d64db1f00e5e7d554  16568456 Bytes
…
```

One line per unit, SHA-256 over the file. **These numbers are here as a form,
not as a target value** — they change with every dependency and with every
patch version of the toolchain. What is compared is two runs, not one run and a
manual.

The panic sites stay readable — crate, version, file and line survive, only the
machine goes:

```text
/cargo/registry/src/index.crates.io-…/openraft-0.9.25/src/config/config.rs
```

What a second build needs in order to produce the same digests is checked in:
`rust-toolchain.toml` (the version is pinned) and `Cargo.lock`. **The digests
themselves are not in the repo** — they hang off the toolchain's patch version
and off every dependency change and would be wrong the day after their commit.
Reproducibility is a statement about two runs, not about a number in a file.

Measured as equal: different source path, different target directory, different
`CARGO_HOME`, different time of day. Not measured: two different machines.

The run is **not** in the gate — it builds release and takes roughly three
minutes, the same situation as with `cargo xtask bench`.

> ADR-0138, ADR-0023, ADR-0082.

### What "healthy" means here

**Without a declared probe a running container counts as healthy.** With a
probe (ADR-0080) it counts as healthy when it runs **and** serves its port:

```xml
<workload name="api" kind="service">
  <image reference="registry.example.com/api:1.0"/>
  <mesh port="8080"/>
  <readiness port="8080"/>
</workload>
```

The element comes **after** `<mesh>` (the order in the schema is binding). No
period and no threshold: it is asked once per reconcile, and the result is the
state.

**With `path` it becomes an HTTP `GET`** (ADR-0102):

```xml
  <readiness port="8080" path="/healthz"/>
```

| | without `path` | with `path` |
|---|---|---|
| What is asked | a TCP connect | `GET <path> HTTP/1.1` |
| Ready means | somebody is listening | status **`2xx`** |
| A process that binds and **does not answer** | **ready** | not ready |

The last row is the reason to set `path`: a workload that opens its port and
then loads an index counts as ready from the first moment without it — and the
resolver offers its address while it cannot answer anything yet.

**What the HTTP probe does not do:**

- **No redirects.** `3xx` means not ready; a login page at `/healthz` is not an
  answer to "are you ready".
- **No TLS.** It runs in the namespace over loopback and reaches the workload in
  the clear — with `<mesh>` too, because the sidecar terminates in front of it.
  A workload that serves its port with TLS **itself** is therefore not
  measurable; for it the probe stays without `path`.
- **No HTTP/2 in the clear.** A server that speaks only `h2c` does not answer an
  HTTP/1.1 `GET` and appears not ready.
- **No headers and no body.** What is sent is `Host:` and `Connection: close`;
  what is read is the **status line** and at most 64 bytes.

The path must begin with `/` and must contain no whitespace (the schema rejects
both); a query in it is allowed (`/healthz?verbose=0`).

**What a failed probe brings about — and what it does not:**

| | |
|---|---|
| The instance is **not resolved** | yes (ADR-0013), from **foreign** nodes too |
| The container is restarted | **no** (ADR-0080, decision 7) |
| Dependents are held back | **no** — a `requires` edge still counts "running" (ADR-0061) |
| A warm standby takes over | **no** — the lease hangs off the report (ADR-0064) |

**No autonomous restart, and that is decided:** an overloaded workload does not
answer, and a restart makes the overload worse. Whoever wants to restart takes
`tgctl cluster restart <workload> <generation>` — then the audit trail says
**who** it was (ADR-0050).

**Where to look**, with `tgctl cluster show`: an instance that is not ready gets
a line of its own (`unbereit: 0`) and stays in `beobachtet` as `running` — it
runs, it merely does not serve. The **reason** is named by the node's log
("refused" means "does not bind", "timeout" means "hangs").

**The probe is a TCP connect**, not HTTP: a server that listens and answers
`500` counts as ready. It separates "binds" from "does not bind", and that is
the start-up case — `<dependencies><after/>` orders the **start**, not the
readiness.

**Without a probe the three consequences from before remain**, and for a
workload that can go silent that is precisely the reason to declare one:

- **The resolver offers its address** (ADR-0013). The ADR names mTLS and retry
  as mitigation: a dead endpoint fails at connection setup. A *silent* one does
  not fail — it merely does not answer.
- **A `requires` edge counts as satisfied** (ADR-0061).
- **A warm standby does not take over** (ADR-0010).

**There is no liveness per workload in the sense of ADR-0015** — what the ADR
calls that is, here, a human with `tg_workload_ready` and `tgctl cluster
restart`.

## 5. Metrics that deserve an alert rule

The rules themselves lie in **`docs/alerts.yml`** — loadable for Prometheus,
with a rationale per rule. They are a **starting point**: the directions are in
the ADRs, the `for:` durations are computed from this system's cadences, and
the thresholds belong to operations. Metrics without a rule are at the end of
the file, each with the reason.


All on `/metrics` of the respective process (default loopback,
`--telemetry-addr off` switches it off). **The thresholds are not decided.**

**Which process reported a number is told by its global label** — and it is not
called the same everywhere:

| Process | Label |
|---|---|
| `tgd`, `tg-agent` | `node="<name>"` — the node name from `--node` |
| `tg-proxy` | `workload="<name>"` |

A sidecar runs in the container and **cannot** know the node name (ADR-0059); a
`tg_proxy_*` rule therefore names `{{ $labels.workload }}`. Until this state
all three filled a label `node` — `tgd` with its **Raft id**, the sidecar with
the **workload** — and an alert text `{{ $labels.node }}` named something
different depending on the process. Whoever built their own rules or dashboards
on `node="<id>"` moves them to the name; the affected rules in
`docs/alerts.yml` have been.

**Gauges expire after 15 minutes, counters do not** (ADR-0088). That is the
reason an alert about a withdrawn workload falls silent instead of staying:
`tg_workload_ready{workload="api"} 0` disappears a quarter of an hour after
`tgctl cluster remove api`, and `TardigradeSingleWriterWithoutActiveRole`
(`critical`) stops firing. Before, that could be achieved only with a restart
of the process.

Two consequences for operation:

- **The scrape interval must be under 15 minutes.** Above it, series that are
  refreshed in the scrape lapse (`tg_task_alive`,
  `tg_raft_rpc_deadline_seconds`, `tg_raft_peers_missing`,
  `tg_identity_intermediate_expires_at_timestamp_seconds`) — and monitoring
  that does not ask for a quarter of an hour is not monitoring anything anyway.
- **A missing time series is a statement.** It means "nobody has set this for 15
  minutes" and not "everything is fine". Where that means something it is in
  the table below; `up == 0` remains the signal for a process that no longer
  answers at all.

And one consequence that follows from it: `tg_volume_size_bytes` and
`tg_volume_declared_bytes` have since been reported in **every** reconcile
pass, not only at the start of an instance. A volume nobody declares any more
thus disappears from monitoring by itself — and a volume not yet created does
not appear at all: the declared number alone would be half of a pair.

| Metric | What it says |
|---|---|
| `tg_proxy_active_role_expires_at_timestamp_seconds` | **Point in time** up to which this sidecar serves its active role. `0` means "no role" — the normal state for a warm standby. If the value is **greater than 0** and has passed, the sidecar refuses in both directions (ADR-0066), while `tg_workload_active_role` on the node may still say `1`: the one is set by the agent from the lease, the other by the sidecar from the file. |
| `tg_task_alive` | Is the named task still alive — `1` or `0`, one label per task. Since ADR-0082 a panic costs its task and not the node; since **ADR-0116** it is **restarted** afterwards (backoff 1 s to 1 min, no giving up). A task that **returns** or is cancelled deliberately does not come back — it has decided it is finished. Observed are the agent's four long-lived ones (`identity-refresh`, `cluster-session`, `resolver-udp`, `resolver-tcp`) and the projection follower in `tgd` (`projection`). The reason is in the node's log. The **zero stays** as long as the process runs — it is repeated in the scrape (ADR-0088) so that the alert does not dissolve itself after a quarter of an hour. |
| `tg_container_memory_bytes` | What a container currently occupies (ADR-0118), labels `workload` and `replica`. Read from `memory.current` of the cgroup under `/tardigrade/<container-id>` — the path **we** specify and not the runtime (ADR-0006). **This is the number the overhead ought to be based on** (`tgctl cluster sidecar-overhead`, ADR-0067): it stands at zero and is otherwise guessed, and since ADR-0086 the kernel enforces it as a memory limit — an underestimate is from then on no longer imprecise but the OOM killer. |
| `tg_container_cpu_seconds_total` | CPU time consumed by a container (ADR-0118), the same labels, from `cpu.stat`. A **counter**: the cgroup keeps a sum, not a utilisation — what to look at is the rate. It jumps to zero on restart, because the container gets a new cgroup; `rate()` recognises that. |
| `tg_task_restarts_total` | How often a task was restarted (ADR-0116), one label per task. **It is the actual reporter**, now that `tg_task_alive` returns to `1`: a single restart is a transient panic and heals, a growing rate means the task does not come up — and then what it does fails proportionally in every window. A restart is not a repair. |
| `tg_workload_restarts_total` | How often a workload was restarted **because it was not running**. A decree (`tgctl cluster restart`) does not count — it is a human's decision. A single restart is normal; the **rate** is the signal: a workload that restarts in every pass does not come up. The reconcile has **not** failed in that case (`tg_workload_failures_total` stays quiet) — the container ends itself, and the reason is in **its** log, not in the node's. |
| `tg_node_last_report_timestamp_seconds` | **Point in time** of the last report. The age is computed by the rule. |
| `tg_raft_leader` | `1` on the leader, `0` otherwise — set in the scrape. |
| `tg_node_slice_lag` | How far a node lags behind the log — in slices. Temporarily positive is normal (up to five seconds until the next report); **permanently** positive means: it receives slices and does not apply them. Its report keeps coming, so `tg_node_last_report_timestamp_seconds` says something fresh — this number is the only one at which it shows. Check with `tgctl cluster nodes` (line `angewandt:`). |
| `tg_identity_challenges_total{outcome="unknown"}` | Somebody is asking for nonces for names the cluster does not know. A real node asks every three hours and counts as `stored`; a series here is something else. The port requires no client certificate (ADR-0043), so it is reachable by anyone who reaches it. |
| `tg_node_isolated_entries` | A node cannot place entries of its desired state — an unreadable document, a duplicated name, a cycle (ADR-0062). The workload keeps running if it was running, but is not reconciled. Which ones they are is told by `tgctl cluster nodes` (line `isoliert:`). |
| `tg_volume_size_bytes` / `tg_volume_declared_bytes` | Two raw numbers per volume; the difference is computed by the rule. Declared larger than actual means: an enlargement is pending **or** it failed. If it is pending, the instance is stale at the same time (`tg_workload_stale`); if it failed, **only** this difference is there. Declared smaller means: a shrink was rejected — shrinking never happens (ADR-0027). |
| `tg_raft_rpc_seconds` / `tg_raft_rpc_failures_total` / `tg_raft_rpc_deadline_seconds` | The runtime of replication, the failed calls and the deadline against which both are to be read. **`openraft` uses `heartbeat_interval` at the same time as the deadline of the replication call** (ADR-0033): a link that is slower **never** replicates — and quietly, because the remaining nodes hold the quorum. The rule: `tg_raft_rpc_seconds{quantile="0.99"} > on (node) group_left () (tg_raft_rpc_deadline_seconds / 3)` (this used to read `histogram_quantile(...)` — measured, the exporter renders a **summary** with `quantile` labels and no buckets, and `histogram_quantile` needs `le`: the rule would **never** have fired). If instead the counter rises while nothing arrives, the link is not slow but closed. |
| `tg_node_attached` | `0` = detached. One label per node, no sum. |
| `tg_workload_active_role` | `0` = a single writer does not hold its active role. |
| `tg_scheduler_domain_absorbs` | `0` = the failure of this domain could not be absorbed. |
| `tg_scheduler_domain_at_risk` / `…_elsewhere` | The numbers behind it, per resource. `elsewhere / at_risk` already responds at 1.5 instead of waiting for the jump from 1 to 0. |
| `tg_cluster_proxy_images` | `> 1` = two nodes run different sidecar versions. |
| `tg_cluster_dns_zones` | How many DNS zones the cluster serves. `1` = uniform; more means `--dns-domain` is diverging. A bare name still resolves (every container asks its own resolver); a workload with a **fully qualified** name then finds its target on one node and not on the other. Which one deviates: `tgctl cluster nodes`. |
| `tg_cluster_userns_postures` | Whether **every** node maps container ids (ADR-0091). `1` = uniform (all or none), `2` = divergence: at least one node runs unhardened, and there `uid 0` in the container **is** `uid 0` on the node. What is counted is the **posture**, not the range — different ranges are not an error. Which one: `tgctl cluster nodes`, line `userns`. |
| `tg_identity_intermediate_expires_at_timestamp_seconds` | If it expires, **all** the node's workloads lose their identity at the same time. |
| `tg_proxy_svid_expires_at_timestamp_seconds` | The same for a sidecar. |
| `tg_proxy_policy_refreshed_at_timestamp_seconds` | When a sidecar last adopted its edge state. Fail-static means: stale still applies — the alert rule forms `time() - value`. |
| `tg_proxy_egress_refreshed_at_timestamp_seconds` | When a sidecar last adopted its egress permissions. An old state keeps a **withdrawn** permission to the outside alive. |
| `tg_lease_clock_skew_seconds` | How far this node lies behind the leader's clock **at least**. The active role rests on the skew being smaller than three seconds (ADR-0078); above that there are two writers. A **lower bound** — it fluctuates by up to three seconds and underestimates, so it is good for the rough skew and not for the limit itself. One label per workload. |
| `tg_workload_failures_total` | Failed reconciles per workload and **class** (`pull`, `mount`, `volume`, `runtime`, …). It answers **where** to look; the **text** is in the node's log (`Abgleich gescheitert`) and not in the cluster — it names names from a payload, and a label from that would be unbounded. `tgctl cluster show` names them in the line `gescheitert:`. |
| `tg_workload_stale` | `1` = the declaration was changed, and the running container is still the old one. It takes effect at the **next start** (section 3); the restart is an action. One label per workload. |
| `tg_node_pressure` / `tg_node_free` | How full a node is and what there is still room for (ADR-0127). The pressure is the utilisation of the **scarcest** resource, `0` to `1`, computed over the **plannable** capacity — the reserve from ADR-0047 is subtracted. It is the same number by which the planner sorts its candidates (ADR-0109); it **decides nothing** (no auto-rebalancing, ADR-0011). Until this state the first signal of a full cluster was a failed placement: a node at 99 % reported the same as one at 1 %. Only the leader reports it — only it plans. `tg_node_free` alongside, because the pressure is the maximum over the resources and does not name the scarcest one. |
| `tg_content_reclaimed_bytes_total` / `tg_content_reclaimed_layers_total` | What the content GC released (ADR-0126). No label — there is one store per node. They are above all the **counter-check against silence**: the GC does not run when one of its three guards takes hold, and those are the cases in which something *else* is wrong. If the counter stands still while the disk grows, the node's log names the reason (`Content-GC verschoben`). |
| `tg_container_memory_peak_bytes` | The **peak** memory per container (ADR-0123), from `memory.peak`. That is the number from which the memory limit is set — not `tg_container_memory_bytes`: that is an instantaneous value, and a scrape every 15 s does not see a spike between two measurements. Measured on a real cgroup: 204.1 MiB peak against 0.5 MiB half a second later, **factor 425**. It rises and does not fall while the container runs; on restart it begins again (fresh cgroup). Under Linux 5.19 the line is missing — that is not an operational prerequisite, just one time series fewer. |
| `tg_workload_unclear_total` | Passes in which the node **could not read** an instance's state (ADR-0122) — the runtime answered and it did not understand, or it did not answer at all. Then **nothing** is touched: not started, not stopped, not cleared away. The instance is also **not resolved** (ADR-0013) and explicitly does **not** count as failed — a `failed` would drag every dependent along (ADR-0061). A single wobble is nothing; the **rate** is the signal (`TardigradeStateUnknown`). The reason is in the node's log (`Zustand unbekannt`). **As long as it counts, this workload does not restart, even if it is dead** — that is the deliberate choice, because the opposite error measurably unmounted the rootfs underneath a running container and deleted its ephemeral volume. |
| `tg_workload_ready` / `tg_workload_probed` | how many instances answer their readiness probe, and how many were **asked** (ADR-0080). Two raw numbers; the comparison is made by the rule. `ready == 0` is the total outage, `ready < probed` the partial one — and that is the warning one wants beforehand. Both lines appear only for workloads with a declared probe and count only **running** instances: one that is not running at all is not probed and appears in `tg_workload_restarts_total`. Across nodes `sum by (workload)` — with `spread=rack` the instances lie on different ones. |
| `tg_workload_placed` / `tg_workload_replicas` | how many instances of a workload have a **node**, and how many the declaration demands (ADR-0011, ADR-0034). Two raw numbers; `placed < replicas` means: at least one instance is not placed. Only the **leader** sets them. The most frequent cause is more `replicas` than failure domains at the level from `spread` — the unsatisfiable is rejected and not softened, and the rejection is in the leader's log. Which instance number is missing is told by `tgctl cluster show`. |
| `tg_dns_answers_total` | How the node-local resolver answered, per outcome (`noerror`, `nodata`, `nxdomain`, `refused`, `forwarded`, `malformed`, `notimplemented`, `dropped`). For the most expensive case in operation: a workload that does not reach its target. `refused` is the **normal case** for every name outside the zone without an egress permission (ADR-0041) — what is notable is a rate that changes, not its height. If `dropped` rises, unreadable packets are arriving. |
| `tg_process_open_fds` / `tg_process_max_fds` | Open descriptors and the **soft** limit. If they run out, **no listener accepts any more** (section 3) — the alert rule forms the distance instead of waiting for the first message. It is taken in the scrape, so it cannot go stale; on **complete** exhaustion the scrape itself fails, and then `up == 0` is the signal. |
| `tg_cluster_ordinals_used` / `tg_cluster_ordinals_capacity` | How many node subnets are handed out and how many there are. If the address space is full, **no more nodes are admitted** (ADR-0069) — the alert rule forms the distance. Without an address plan set, neither of them appears. |

**Not ready is `503`, not `500`.** Loss of quorum makes a node not-ready, **not
dead** — if liveness hung off the quorum, a partition would hit the whole
minority side with restarts.

> ADR-0015, ADR-0019, phase 11b.

---

### Hardening the containers (ADR-0017, ADR-0090)

Every container gets a **seccomp profile**: a denylist with `ALLOW` as the
default, that is, *what is not on it runs*. Blocked are, among others, `bpf`
(invariant 1), kernel modules, mounts, the kernel keyring and the **host's
clock** — on which the audit trail's timestamps and every active-role lease's
deadline depend. A blocked call yields `EPERM`; the process is not killed.

If a workload legitimately needs a blocked call, there is only
`tg-agent --no-seccomp` — and the setting applies to **all** containers on that
node. Startup reports it with `WARN`; whoever sets it should plan the node
accordingly.

**A rejection is silent, and that is not a negligence of this system.** There
is **no metric** for how often a container fails at the barrier: measured,
`SCMP_ACT_ERRNO` produces nothing the agent could read — after a real case
`dmesg` is empty and the audit log contains zero `SECCOMP` records.

The kernel **could** report it (`/proc/sys/kernel/seccomp/actions_logged`
contains `errno`, and the OCI specification knows the filter flag
`SECCOMP_FILTER_FLAG_LOG`), but whether the record arrives is decided by the
**machine's audit rule**, and that belongs to the operator. Widespread
distributions ship `-a never,task` — which discards task records, `SECCOMP`
included. A metric on it would be mute on a default installation.

**What an operator can do when they have a suspicion:**

```bash
auditctl -l                       # does it say '-a never,task'?
auditctl -D                       # clear the rules (until reboot)
ausearch -m SECCOMP -ts recent    # after that the rejections appear
```

Without a running `auditd` the same records are in `dmesg`. The path is a
**diagnosis**, not a permanent configuration: task records are a lot of traffic
on a node with many containers.

How else to recognise the case: the container dies at start-up, so
`tg_workload_restarts_total` grows, and its own log names `EPERM` or "Operation
not permitted" at the point where it makes the call.

#### The user namespace (ADR-0091)

`tg-agent --userns-base 100000` maps `0..65535` in the container onto
`100000..165535` on the node. **uid 0 in the container is afterwards no longer
uid 0 on the node** — an escape ends up as an unprivileged id.

Four things belong to commissioning:

1. **crun must be in the `PATH`.** With youki the agent does **not** start; it
   says so at startup and names the runtimes that can do it. That is the only
   place in this system where a missing hardening prevents the start — it is,
   because an operator explicitly asked for it.
2. **The range must be free.** It lies above the node's accounts (lower bound
   65536) and is 65536 ids wide. Two nodes may have different ranges.
3. **An existing node needs a manual step.** Layers already unpacked belong to
   `root` and are **not** touched; likewise the content of existing volumes.
   Whoever switches over immediately chowns `<data-dir>/content/layers` and the
   volumes once themselves — recursively, to `<base>` — or clears away the
   layer part of the store and has it fetched again.
4. **Backups need the ids.** What lies in volumes and in the layer store
   belongs to `<base>` afterwards. The tool must preserve the numeric ids —
   with `tar` the switch for it is called "numeric-owner", `rsync` needs its
   archive mode. Restoring without the ids makes the data unreadable for the
   container.

Changing the range is the same manual step as point 3.

**Whether every node maps is visible.** `tg_cluster_userns_postures` counts the
**posture** and not the range — different ranges are not an error. `1` means
uniform, `2` is the finding: at least one node runs unhardened next to hardened
ones. **Which one** is told by `tgctl cluster nodes` in the line `userns`. The
alert rule waits an hour, because a rolling roll-out of the hardening looks
exactly the same.


**Leader-owned metrics need `tg_raft_leader`.** `tg_node_*`, `tg_cluster_*` and
`tg_scheduler_domain_*` are set only by the leader — and a stepped-down one
keeps its series for up to **fifteen minutes** (ADR-0088), frozen. Whoever
writes their own rule on them joins with
`and on(instance) (tg_raft_leader == 1)` as soon as it aggregates over
instances or waits for less than fifteen minutes. Without that it fires after
**every** leader change on the stepped-down one's series. The head of
`docs/alerts.yml` says so, and a test holds it fast.

## 6. Behavioural changes that concern an upgrade

- **Time series now disappear when their subject is gone** (ADR-0088). Until
  now every process held every series until its end; from here on a **gauge**
  expires 15 minutes after its last update. Counters are unaffected.

  **What that improves:** an alert about a withdrawn workload falls silent.
  `tg_workload_ready{workload="api"} 0` stayed after `tgctl cluster remove api`
  until the agent restarted, and `TardigradeSingleWriterWithoutActiveRole`
  (`critical`) fired permanently for something an operator did deliberately.

  **What to check:** a **scrape interval over 15 minutes** now lets series
  lapse that it did not before. And a dashboard expecting a series "forever" —
  say the last known state of a deleted workload — no longer finds it. Whoever
  sees a gap where a zero used to be reads from here on "nobody has set this
  for 15 minutes".

- **`--interval 0` no longer applies.** It used to be accepted, and the loop
  then ran without a pause. What a pass does by now makes that expensive: it
  asks the runtime **per instance** for its state, probes the readiness (one
  thread and one connect per instance, ADR-0080), writes files and **reports to
  the leader** — so load on the node and in the cluster. From here on the
  default stands (10 s), and the agent says so at startup. Whoever wants
  exactly one pass takes `--once`.

- **The default node name now comes from the kernel, not from `$HOSTNAME`.**
  That was the promise ("default: the hostname") and measurably not the
  practice: `$HOSTNAME` is set by the **shell**, and a service under systemd
  does not get it —

  ```text
  printenv HOSTNAME     (in a systemd unit)       -> exit 1
  ```

  — with which `tgd` and `tg-agent` as a service fell back to the name
  **`node`**. The name is in the URI SAN of the cluster leaf and is bound to an
  invitation (ADR-0043, ADR-0037).

  **What to do:** whoever runs as a service without `--node` was called `node`
  until now and is called `<first label of the hostname>` from here on. The
  enrolment in the log, however, is on the **old** name — the node would get
  "not invited" and therefore no slice. Two ways:

  ```bash
  # either nail the old name down
  tg-agent --node node ...
  # or invite anew under the new name
  tgctl node invite web01 > join-token
  ```

  In a cluster with more than one node the old state cannot have carried
  anyway: five nodes that all call themselves `node` share one id. **Set
  `--node` explicitly** — then the question is moot.

- **The sidecar drops a connection that does not identify itself.** Ten seconds
  after connection setup — inbound, outbound and in egress. A legitimate TLS
  handshake needs far under a second; what is hit are peers that **never**
  complete the setup. Before, the sidecar held them indefinitely: measured, a
  hundred out of a hundred, and each cost a descriptor of the process. If an
  endpoint runs with an extremely slow handshake (an HSM in the chain, say), it
  shows up from here on.
- **A lease from a far-advanced clock is no longer carried.** If it reaches
  more than 30 s into this node's future, the instance fences (ADR-0078).
  Before, every value was believed — and a node with a clock set back held the
  active role for arbitrarily long while the leader handed it on. What is hit
  are machines **without** time synchronisation (section 1).
- **A document with content after `</workloads>` is refused.** Before
  everything after it was **silently discarded** — including a second complete
  document: whoever concatenated two definitions (`cat a.xml b.xml > all.xml`)
  got the workloads of the first and not a word about those of the second.
  `tgctl cluster apply` reported "taken", and half was missing.

  What XML allows there remains allowed: comments, processing instructions and
  whitespace. What is hit are concatenated files — those belong in **two**
  calls, because an upsert carries one workload (ADR-0004).
- **A panic in a task no longer ends the process** (ADR-0082). Until now the
  release profile carried `panic = "abort"`: a panic anywhere — in a readiness
  probe, in one of the four sidecar shards, in a renewal task — took the whole
  node with it, loudly and immediately, and a supervisor restarted it. From
  here on the **task** dies, and the node keeps running.

  That is the intent (a partial failure is not a total failure) and it has a
  price: **a degraded process is harder to spot than a dead one.** Whoever
  relied on a crash being visible looks from here on at two things:

  - `/livez` — the watchdog covers three loops: the reconcile in the agent, the
    scheduler and the Raft loop (section 4).
  - The log. A task that has died **reports itself**, and nobody restarts it:
    `a task of the shard has ended`, `a readiness probe panicked`, `the writer
    thread panicked`. The most expensive case is the identity
    renewal — if it dies, every handshake of this node fails twelve hours later
    (ADR-0014).
- **An arithmetic error is from here on a panic instead of a wrong number**
  (ADR-0082). The release profile carries `overflow-checks = true`. Measured,
  `1000u64 - 2000u64` previously yielded **18446744073709550616** — a free
  capacity of 18 exabytes where a deficit stands. After the line above, such an
  error costs its task, not the node.
- **The binaries are larger.** Measured +12.4 % across all four (43.8 →
  49.2 MB); the sidecar 6.6 → 7.5 MB. That is the price of the two lines above.
- **`tgctl cluster restart <workload> <generation>` now restarts the sidecar
  too** (ADR-0085).
  Before, the decree reached only the workload, and its sidecar kept running
  with the old command line — with a change of class to `single-writer` that
  meant: the workload runs as a single writer, and its sidecar does **not**
  rein it in (ADR-0066).

  The price: a decree from here on also tears down the mTLS connections running
  through that sidecar. It is drained in the process and not torn down
  (ADR-0058). And a sidecar whose bundle stems from an older version restarts
  **once** after the upgrade — provided a generation was ever decreed for its
  workload.

  A change that concerns **only** the sidecar — a swapped `--proxy-image`, a
  different `<mesh port>` — still needs a decree for the workload:
  `tgctl cluster restart <workload> <generation>`.
- **The `class` of a placed workload can no longer be changed** (ADR-0117). The
  upsert is rejected and names the way:

  ```text
  the class of a placed workload does not change (replicated ->
  single-writer): … first issue `tgctl cluster remove api`, then declare it
  anew
  ```

  Why the rejection and not the late effect: measured, the change got through
  in **both** directions, and immediately afterwards the cluster granted an
  active-role lease — while the running sidecar had never got its
  `--single-writer` (its command line stems from the document at start time,
  ADR-0059). The cluster thus carried an active role that **nobody** enforced,
  and every display was green. The opposite direction is the availability case:
  no more lease, but a sidecar that keeps reining in — the workload goes silent.

  **What the way costs:** an interruption. Between `remove` and the new `apply`
  the workload is wanted nowhere, and the sweeper ends it (ADR-0058). The
  volume survives (deletion happens only with `tgctl cluster delete-volume`,
  ADR-0027); a decreed active instance goes with it and belongs set again
  afterwards (`tgctl cluster promote`).

  **Without a placement the change goes through.** Whoever corrects a class
  seconds after the first `apply` gets away with it — nothing is running.
- **A workload must not be called `<x>-proxy` while `<x>` takes part in the
  mesh** (ADR-0084). The sidecar of `<x>` would be called that (ADR-0059), and
  both cannot bear the same name. The cluster rejects such a pair; `tgctl
  cluster apply` does so beforehand, before half the file is in the log.

  A pair that got into the log **before** this change stays there. The node
  then isolates `<x>` — it keeps running but is no longer reconciled — and
  reports it via `tg_node_isolated_entries` (`TardigradeBrokenDeclaration`).
  Before, the same pair cost **every** pass of the node: nothing was started,
  nothing cleared away and no single writer fenced. Cleaning up is done with
  `tgctl cluster remove`.
- **`tgctl` and `tgd` belong to one build** (ADR-0083). The admin protocol
  rejects a message with an unknown field — in **both** directions. Before,
  everything unknown was silently discarded, and the dangerous case was a
  decree: a `blocking` that an old `tgd` does not know let `tgctl cluster
  learner` return immediately, and an operator promoted a node that had caught
  up on nothing.

  A divergence reports itself from here on as `invalid_argument` with the name
  of the field. What is hit is whoever copied one of the two binaries on its
  own — and that is the better answer than a silently truncated `cluster
  status` in the recovery case.
- **Format breaks.** Five changes to the wire format require a **coordinated**
  switch: credential path (ADR-0042, ADR-0046, ADR-0055), log envelope
  (ADR-0050) and the slice (ADR-0064). A node with old and one with new
  behaviour talk past each other.
- **And one change to the state machine likewise** (ADR-0112). A withdrawn
  command — `clear_placement` and `register_trust` — is from here on
  **rejected** instead of applied. It stays readable, so every node comes up
  with an old log; what changes is its **effect**. Two nodes of different
  versions therefore build different states from the same log, and that is not
  a rolling update.

  Exactly one case is affected: a log in which a `register_trust` was
  **applied**. Its producer existed only between `07e4304` and `351bc87`
  (ADR-0055 replaced it with `rotate_trust`), so within this tree's development
  history. If a log did carry it, the node concerned would lose its trust when
  replaying — to be fixed with a new invitation (`tgctl node invite`).
- **And every extension of the session messages likewise.** This used to read
  "extensions with `serde(default)` are **not** breaks" — that is measurably
  **wrong**. `serde(default)` covers one direction: a **new** reader tolerates a
  missing field. The other direction it does not cover: `NodeSlice`, `Instance`
  and `NodeReport` carry `deny_unknown_fields`, and an **old** reader rejects a
  message with an unknown field (measured: "unknown field `stale`").

  The fields `isolated` (ADR-0062), `failures` (ADR-0015) and `unready`
  (ADR-0080) in the report belong with it — they came with this state and are
  the same case. Likewise `active_instances` on the slice (ADR-0111): which
  instance of a single writer carries the active role. A node at an old state
  does not know the field and rejects the whole slice.

  In practice that means: **control plane and nodes belong updated together**,
  and both orders break on their own. New `tgd` first → old nodes discard the
  slice and get no desired state any more. New nodes first → the old `tgd`
  discards the report, and with it the renewal of the active-role lease ends
  (ADR-0064): a single writer fences after fifteen seconds. Running containers
  keep running in both cases (ADR-0019).

  **That is decided and not negligence** (ADR-0072): whoever does not fully
  understand an instruction does not carry it out partially — the slice carries
  tombstones (ADR-0042), leases (ADR-0064) and generations (ADR-0071), and "I
  did not understand something and passed over it" is not a state an auditor
  can reconstruct.

**How many breaks are in the bundle?** Measured, **23 fields** on the three
strict types (`NodeSlice`, `Instance`, `NodeReport`) — every
`#[serde(default)]` field there is exactly one: the default covers "new reader,
old field missing", the strictness rejects "old reader, new field".

The number is a **lower bound**: format changes that add no field are not
counted — the egress entry went from a triple to a quadruple (ADR-0092), and an
array with one element more is likewise a break.

*(Two guards keep the number honest, and they report one after the other:
whoever adds a field first makes the counter in `tg-store` red — it holds the
count against `session::PROTOCOL_FIELDS`, the number that also appears at the
Prometheus endpoint. Whoever supplies the constant afterwards then makes the
manual guard red, and then the number here belongs updated. Next to it the plan
sections carry ordinals — "the sixth format break" — and those have measurably
**drifted**: two places claim "sixth", two "seventh", "tenth" and "eleventh"
nobody. What applies is the measured number.)*

**And the number applies to one transport, not to the cluster.** Strict are
**three**, and they break differently:

| Transport | Strictness | How it breaks |
|---|---|---|
| session (`NodeSlice`, `Instance`, `NodeReport`) | ADR-0072 | 22 fields with `serde(default)` — **one** direction each |
| admin service (11 types) | ADR-0083 | `tgctl` and `tgd` are **one build** — settled with the package |
| **signer port** (19 types) | ADR-0072/0097 | **no** `serde(default)` — every extension breaks in **both** directions |

The signer port is the sharpest, and it must go into the **same** window:
shares and commitments go over it, and a seat that half-understands a message
hands out a nonce belonging to something else (ADR-0014). Measured on
`CommitRequest.epoch` (ADR-0107):

```
neue Nachricht -> alter Leser:  unknown field `epoch`
alte Nachricht -> neuer Leser:  missing field `epoch`
```

ADR-0107 introduced **two** such fields there (`CommitRequest.epoch`,
`RefreshFinishResponse.persisted`). The ten new calls next to them are, by
contrast, **additive**: an old process does not know the paths and answers
`Unimplemented`.

*(A guard here too: `every_signer_message_is_strict` reads the source. It
checks the strictness, not the number of breaks — that is not mechanically
countable at the signer port, because a mandatory field cannot be
distinguished from one that has always been there.)*

### 6.1 The maintenance window for a format change

A format change is **not a rolling update**. The five nodes from ADR-0031 carry
the failure of *one* node; a divergence in the format they do not carry.

1. Announce it: for the duration of the window nobody renews an active-role
   lease. **Single writers stand still**, replicated workloads do not.
2. Replace and restart all `tgd`.
3. Replace and restart all `tg-agent`.
4. Check whether **all** have switched over:

   ```promql
   count(count_values("fields", tg_process_protocol_fields))
   ```

   `1` means uniform, `2` means mid-way. Only after that is the rest worth
   doing: `tgctl cluster nodes` — every node must report again (`letzter
   Bericht`), and `tg_workload_active_role` must be `1` again for every single
   writer.

**What the window costs:** the time between the first restart and the last.
Running containers run through, the network stays, SVIDs keep rotating (the
agent mints locally, ADR-0006) — what is missing is the desired state. Single
writers come back **by themselves** as soon as the session stands again; no
intervention is needed.

**How long the recovery takes is measured** (one node, restart of the control
plane in the middle of operation):

| What | Measured | What it consists of |
|---|---|---|
| `tgd` leads again | 25 ms | process start |
| the node reports again | 5.1 s | the reporting period |
| the active role's deadline moves | 7.6 s | the renewal only in the second half |

The third number is a **cadence and not a downtime**: in this run the single
writer did not lose its role at all. So the recovery is seconds — **the window
is as long as the replacement takes.** If it exceeds the lease deadline of
fifteen seconds, the single writers fence and come back afterwards with a new
epoch. That, too, needs no intervention.

With five nodes the election comes on top (ADR-0033); that is not measured.

**The trap: "one node first, just to try it out."** That is exactly what
breaks. That one node gets no more slices, its containers keep running, and in
the cluster's view it looks like a silent node —
`tg_node_last_report_timestamp_seconds` grows without anybody finding a network
fault. Both sides report it by now: the agent "session ended" with the
reason, the server "the session's inbound is unreadable" with the node name
(ADR-0072). Whoever sees one of those lines looks for a divergence and not for
a cable.

**And `tg_process_protocol_fields` is the only piece of information that
survives the divergence.** Every other question to the cluster — `tgctl cluster
nodes`, the report, the slice — goes over exactly the format that is currently
broken; mid-way **every** node is quiet, so a forgotten one looks like a
waiting one. The number is at the Prometheus endpoint of **every** process, so
it gets through without the session, and `up`/`instance` names the one lagging
behind. If it stays at `2` for longer than half an hour,
`TardigradeProtocolVersionsDiverge` reports it.

It is a **counted** number and not a maintained version (the number of default
fields on the three strict types), and the reason is the direction of the
error: whoever forgets to raise a version number reports "all the same" while
two versions are running — a false all-clear, and that is the more expensive
one. It is thus a **lower bound**: a format change without a new field it does
not count.

> ADR-0072, ADR-0031, ADR-0064.

- **No sidecar, no egress** and **no sidecar, no mesh.** Existing definitions
  without `<mesh>` lose their way out; a mesh member without a running sidecar
  is no longer reachable. (ADR-0041, ADR-0060)
- **A single writer without a lease no longer comes up** and is not reached
  over the mesh. Without a reachable leader that means: after expiry it stands
  still. (ADR-0064, ADR-0066)
- **`--interval` no longer influences the fence** (ADR-0076). Until this state
  it went into the holder's safety margin, and with the **default** of ten
  seconds a healthy single writer counted as fenced two-thirds of the time: its
  container was stopped and started again. Whoever lowered the interval because
  of this behaviour can put it back — the reconcile now wakes by itself close
  to the fence threshold. A large `--interval` thus slows the reconcile and
  **not** the fence.
- **An arrived slice triggers a reconcile.** Before, it waited for the next
  pass — with `--interval 60` a single writer took up its long-granted role
  only a minute later.
- **A dependent whose `requires` target fails is stopped.** Until ADR-0061 it
  kept running.
- **Egress permissions carry a transport** (ADR-0092).
  `tgctl cluster allow-egress <w> <name:port[/transport]>` takes `tcp`
  (default), `quic` or `udp` — the third since the second cut, see **(3)**
  below. The transport belongs to the **key**: whoever allowed `quic` has not
  allowed `tcp` — and an HTTP/3 client that falls back to TCP needs both lines.
  Existing permissions are unaffected; they meant `tcp` and still do.
  **The QUIC path carries** (ADR-0094): the sidecar opens a UDP listener per
  allowed port, the rule set in the namespace redirects exactly those ports
  there, and the port comes from the **kernel** — not from the permission list.
  Two things belong in the manual with it:
  **(1)** A new `quic` permission takes effect **without a restart**: the
  listener opens within a minute, and the redirection is reconciled on every
  pass (queried, set only on deviation). Until both stand, the datagrams die at
  the dropping rule from ADR-0074 — visible at its counter
  (`nft list table inet tardigrade`), not at a metric.
  **(2)** A port that does not bind means **no egress over that port**
  (fail-closed). The case is in the sidecar's log
  (`the QUIC listener cannot be opened`).
  **(2a)** **A QUIC datagram over 2048 bytes is dropped** (ADR-0121). The
  overlay MTU is 1420 and the way to the endpoint lies on the node network;
  2048 covers both. On a network with jumbo frames where an endpoint sends
  larger datagrams the flow ends — **visibly**, with a reason in the sidecar's
  log (`the endpoint sends more than ... bytes`), and not silently truncated.
  Passing it on truncated would tear the same connection apart without a trace.
  **(2b)** **A sidecar carries 512 simultaneous QUIC flows**, over **all**
  listeners together — not 512 per allowed port. In the worst case that costs
  9.2 MiB (measured: 18.4 KiB per flow); it is the number that stands next to
  the memory limit from `tgctl cluster sidecar-overhead` (ADR-0067/0086).
  Whoever reaches the limit sees it at
  `tg_proxy_quic_egress_refused_total{reason="too_many"}`; how many flows are
  open is told by `tg_proxy_quic_egress_flows`. What a container learns of it
  is silence (ADR-0041) — the two numbers are the way to tell it apart from a
  network problem. **Since ADR-0131 the label names the cause**: `not_initial`
  is usually a connection migration (refused, permanently — a short header does
  not state its CID length, and the CID after it travels encrypted; whoever
  needs it takes TCP), `version` a QUIC version this sidecar does not read
  (which one is in its log), `undecryptable` usually a `Retry` that crossed the
  decision and heals itself within one round trip. Only `malformed` still means
  the frame is broken. **A slot comes back after a minute without a datagram,
  even if the listener goes completely silent** (ADR-0130). Until then it did
  not: measured, a listener held its slots over 100 deadlines, and another
  allowed port of the same workload got a permanent `too_many` for it. Whoever
  has a sidecar of an older state in front of them recognises the case by
  `tg_proxy_quic_egress_flows` standing still and not falling; the only way out
  was a restart of the workload — the sidecar hangs off it (ADR-0009).
  **(2c)** **An endpoint with an AAAA record is not reachable here over IPv6**
  (ADR-0136). The overlay is IPv4 (ADR-0012), a container has no IPv6 address
  and no route there. Until ADR-0136 the sidecar took the **first** address the
  resolver named — with a dual-stack name that is the AAAA, and the egress
  failed **silently** even though a perfectly good A record stood next to it.
  From here on IPv6 addresses fall away before they cost an attempt
  (`tg_proxy_egress_unroutable_total`), and the sidecar works through the
  remaining ones in turn until one answers
  (`tg_proxy_egress_attempts_failed_total` counts the futile ones). **A
  v6-only endpoint stays unreachable** — what is new is that you can see it.
  For QUIC only the first half applies: there the first usable address is taken
  and no second one is tried, because a `connect` on a UDP socket does not fail
  visibly.
  **(3)** **`udp` is the third transport** (ADR-0092, decision 5) and the
  coarser enforcement: the sidecar sees nothing of it, the **agent** resolves
  the name and lays one nftables rule per address **and** port. Whoever chooses
  it has asked for it — it is not guessed. Two things about it: a resolution
  that fails leaves the rule set **standing** (fail-static, ADR-0019) — a name
  that permanently does not resolve thereby also freezes this workload's
  remaining changes, and the reason is in the agent's log
  (`UDP target not resolved`); and an address that changes owner within a
  refresh window stays allowed for that long. How many workloads make use of it
  is told by `tg_cluster_udp_egress_workloads`; **which** ones, by
  `tgctl cluster show`.
- **The slice has one field more** (`trace`, ADR-0133) — a format break
  (ADR-0072), and it belongs in the same window. It carries the W3C
  `traceparent` of the command from which the state arose, so that a node's
  reconcile pass hangs off it in one trace. **Without `--otlp-endpoint` it is
  empty and `serde` omits it** — the normal case.
- **`--otlp-endpoint` does not exist on the sidecar** (ADR-0133, decision 2).
  `tg-proxy` rejects the setting instead of accepting it and doing nothing: the
  data plane gets no spans (ADR-0022, ADR-0114). Whoever had it in a command
  line gets an argument error from here on — and until now it killed the
  process at startup.
- **The slice has one field more** — a format break (ADR-0072). It belongs in
  the same bundled maintenance window as the others.

- **A caller that wanted another port is now refused** (ADR-0141). A mesh
  member offers **exactly one** port — the one from `<mesh port>`, and the
  schema allows only one. Whoever dials `ledger:9999` while `ledger` declares
  `8080` used to get a working connection **to 8080**; from here on the
  connection is refused.

  That was invisible until somebody expected a second service behind the
  second port number. What is hit is a caller whose configuration carries a
  port number that belongs to no `<mesh port>` — it was wrong before and
  worked anyway.

  The remedy is one of two: bring the port number at the **caller** to the one
  from `<mesh port>`, or, if it is right there, correct `<mesh port>` and
  decree the workload anew (`tgctl cluster restart`). Which port was wanted is
  in the sidecar's log; `tg_proxy_wrong_port_total` counts the cases, with the
  rule `TardigradeWrongMeshPort` on it.

  **There is no switch back.** A setting that restores the old behaviour would
  be one somebody sets and nobody takes back.

- **A workload without a sidecar now reaches only the node** (ADR-0093). Since
  this state the filter chains in the namespace belong to the **network** and
  not to the sidecar: they are laid when the instance is connected, not only
  when the sidecar starts. Whoever does not declare `<mesh>` thus has no way to
  a neighbour and none to the outside — before, they had both unfiltered. That
  also closes a **start-up window**: between the start of a workload and that
  of its sidecar the same used to apply.
- **`--proxy-image` is thereby effectively mandatory.** Without the setting the
  agent derives no sidecar (ADR-0059); a workload with `<mesh>` would get the
  baseline without the door and would be network-dead. A node that is to carry
  mesh workloads needs it.
- **ICMP out of a container is dropped**, except to its own node. A `ping` from
  one container to another no longer answers as of this state; it is not a
  diagnostic tool for the mesh. Whether a packet dies at the rule is told by
  the counter: `nft list table inet tardigrade` in the instance's namespace.

- **A workload can ask for a device** (ADR-0143, which builds ADR-0028) —
  a GPU, an FPGA, a SmartNIC. The declaration is one element:

  ```xml
  <devices>
    <device kind="nvidia.com/gpu" count="1"/>
  </devices>
  ```

  `@kind` is the CDI *kind*, `@count` how many. There is deliberately **no
  device name**: which of the two GPUs an instance gets is a node detail, and
  ADR-0028 keeps partitioning below the CDI line.

  What an operator has to do, and in this order:

  1. **Generate a CDI spec at provisioning time** with the vendor's tooling —
     the same category of step as installing a driver. It must be **JSON** —
     `nvidia-ctk cdi generate` writes YAML by default and takes an option to
     write JSON instead. YAML is not read here, and a `.yaml` file in the
     directory is reported by name at startup rather than silently skipped.
  2. **Remove the hooks from it.** A CDI hook is a program the runtime runs as
     root before the workload's own command; this node does not run it, and a
     spec that carries one is **refused whole** — a filtered hook would mean
     the file describes something other than what runs. The stock spec from
     `nvidia-ctk` carries an `update-ldcache` hook. Set the library path
     through the spec's own `env` instead.
  3. **Put it in `/etc/cdi` or `/var/run/cdi`**, or name your own directories
     with `--cdi-dir` (repeatable). That neither exists is not an error — a
     node without an accelerator is the normal case.

  What you can see once it runs:

  - `tg_node_devices_assigned{resource="device:nvidia.com/gpu"}` — how many of
    that type this node has handed out. Next to `tg_node_free` for the same
    `resource`, which is what the **leader** thinks is still free. The two
    drifting apart is a finding; until ADR-0145 nobody could see it.
  - **Which** device an instance holds is a log line, not a metric — the name
    differs per node and there is one per instance, so as a label it would be
    a memory leak (ADR-0015). Look for `Geraete zugeteilt`.
  - A device that has vanished from the host — card pulled, driver unloaded —
    stops the **next start** of an instance with a message naming the path. A
    container that is already running is not disturbed: what the kernel gave
    it, this check does not take away (ADR-0019), and a device disappearing
    under a running process is something that process notices itself.

  **Nothing of this is measured on real hardware.** On a machine with an
  accelerator, this is the order to work in, and what to check at each step:

  1. `nvidia-ctk cdi generate` with JSON output, into `/etc/cdi`. Then
     `tg-agent` at startup logs `CDI-Inventar gelesen` with a device count —
     if it says `geraete=0`, the spec was refused and the reason is a line
     above it.
  2. Remove the hooks from the spec. Without that step the whole file is
     refused, and the log says so by name.
  3. Declare `<devices><device kind="nvidia.com/gpu" count="1"/></devices>` on
     a workload and apply it. `tgctl cluster show` must then place it only on
     nodes whose capacity carries `device:nvidia.com/gpu`.
  4. In the container: the device node is present under `/dev`, with the file
     mode the spec asked for, and **no** cgroup device rule exists — the
     latter is deliberate and is what this system cannot enforce.

  Four things belong in mind:

  - **Isolation ends at the device node.** The cgroup device controller is
    eBPF in cgroup v2 and is ruled out here, so what CDI calls `permissions`
    becomes the node's **file mode**. A container that has the node has it
    subject to mode and ownership, not finer. That the barrier holds at all
    rests on `CAP_MKNOD` being absent — it is, and a guard keeps it that way.
    For a sharper separation you need hardware partitioning, which ADR-0028
    requires anyway (SR-IOV, MIG, passthrough).
  - **`intelRdt`, `netDevices` and `additionalGids` also cost the whole
    spec.** They describe isolation, a network interface and process identity;
    passing over them silently would mean accepting a file and building
    something else. An unknown field does the same, and that doubles as the
    version check.
  - **No time slicing.** A device belongs to exactly one instance at a time.
    The node keeps the assignment in `<data-dir>/devices/assigned` and
    **checks it on restart**: a device the catalogue doesn't know, or one
    handed out twice, stops the read and everything is assigned afresh.
  - **The cluster only counts.** A device appears as an ordinary resource,
    `device:nvidia.com/gpu`, in the node's capacity report and in the
    workload's demand. The scheduler treats it exactly like CPU and memory —
    a workload that asks for a device is not placed on a node that reports
    none.

- **Two workloads can now speak UDP to each other** (ADR-0142) — over QUIC
  datagrams, with the same mTLS and the same `may_talk` edge as TCP. Until now
  ADR-0074 dropped it, and the only way out was leaving out `<mesh>`, which
  switched off the very enforcement the mesh exists for.

  The opt-in is one attribute:

  ```xml
  <mesh port="8080" udp="9000"/>
  ```

  `@udp` is the port the **workload** listens on, exactly like `@port` for TCP.
  Without it nothing changes: ADR-0074 still applies to that workload.

  Four things belong in mind:

  - **Only towards peers with an edge and an address.** The agent derives one
    listener per permitted peer from `may_talk` (ADR-0025) and the reported
    endpoints (ADR-0073). A peer that has reported no endpoint gets no rule and
    no listener — datagrams to it die at the dropping rule, which is the safe
    direction.
  - **A datagram is limited to roughly 1350 bytes** on the overlay, and to
    around 1150 at the start of a connection: QUIC begins at a conservative
    minimum MTU and raises it by discovery. Anything larger is **refused, not
    truncated** — the sidecar's log names it. A protocol with larger datagrams
    does not fit here.
  - **It stays unreliable and unordered**, as UDP is. What QUIC adds is
    congestion control: a sender that sends more than the path carries gets
    datagrams refused instead of pushing them into the network.
  - **A new peer can move the listeners.** The local ports follow the sorted
    peer list, so a peer added alphabetically in front shifts the ports behind
    it — the QUIC sessions concerned break once and rebuild. Rule set and
    sidecar file come from one pass, so they never disagree.

- **A mesh member speaks UDP only with a permission** — and to its own node
  (DNS) always. Until ADR-0074 UDP went straight over the bridge and out
  through masquerading, past `may_talk` and past the egress allowlist; that was
  a gap and not a permission. ICMP (`ping`) remains.

  **The way out is a permission with a transport** (ADR-0092), and it is the
  reason for **not** having to leave out `<mesh>`:

  ```bash
  tgctl cluster allow-egress api s3.example.com:443/quic   # name from the packet
  tgctl cluster allow-egress api ntp.example.com:123/udp   # address from the agent
  ```

  **A wildcard is allowed, in exactly one form** (ADR-0124):

  ```bash
  tgctl cluster allow-egress api '*.s3.example.com:443/tcp'
  ```

  It covers **exactly one label** — `meinbucket.s3.example.com` yes,
  `a.b.s3.example.com` no — and **not the name itself** (`s3.example.com` needs
  its own line). That is the form from RFC 6125, so the one on every TLS
  certificate. The star must be the **whole** leftmost label, and behind it at
  least two labels must stand: `ab*.example.com`, `*.com` and `*` are refused.

  That is the way for virtual-hosted-style S3, where the bucket is in the
  name — otherwise every bucket needs its own cluster-wide log entry.
  **Whoever goes that way allows every bucket of that provider**, foreign ones
  too; this boundary does not get finer than one label.

  **For `udp` there is no wildcard.** There the node resolves the name itself
  (ADR-0092), and a wildcard does not resolve; an unresolvable target leaves
  the rule set standing (fail-static) and would thereby freeze **every further
  rule change of this workload**. The cluster refuses it.

  **Until ADR-0124 a wildcard was accepted and had effect nowhere** — the entry
  was in the log and in the slice, the target was forbidden anyway and the name
  was not even forwarded. Whoever has such lines from that time submits them
  anew; from here on the refusal happens on submission, with a reason.

  The difference between the two is with the behavioural changes for
  ADR-0092/0094: `quic` reads the name from the initial and is the fine
  enforcement, `udp` resolves the name in the agent and is the coarser one.
  What wants to go out without a permission dies at the dropping rule.

  **Leaving out `<mesh>` is not the same as "allowing UDP".** It costs this
  workload *both* — mTLS and the egress control — and since ADR-0092 it is not
  necessary either. Whoever does it anyway gives up a perimeter boundary and
  does not unlock a protocol.

  **How to recognise it.** Measured, the two directions differ:

  | Direction | What the sender learns |
  |---|---|
  | outbound (the workload sends) | `sendto` fails with **`EPERM`** — "Operation not permitted" appears in the workload's log |
  | inbound (somebody sends to it) | nothing; the packet vanishes, the sender sees a timeout |

  The outbound case is the frequent one, and there the workload names the
  reason itself. Whoever sees only the timeout — or whose workload conceals its
  error — asks the counter at the rule:

  ```bash
  # In the instance's namespace -- the counter stands at the udp rule.
  ip netns exec tg-<workload> nft list table inet tardigrade | grep -B1 drop
  ```

  If it rises while the workload is trying, it is this rule. If it does not
  rise, the cause is elsewhere — at the edge (`tgctl cluster allow`), at the
  egress permission or in the network.
- **Names of foreign workloads did not resolve until this state.** A node's
  resolver knew only its own containers; a workload on another node yielded
  `NXDOMAIN`. Since ADR-0073 the address travels upwards in the report and back
  in the slice — filtered over the `may_talk` edges. **No edge, no address:**
  whoever wants to resolve a name needs the permission to it
  (`tgctl cluster allow <a> <b>`).
- **Traffic between containers of two nodes did not get through until this
  state.** The node's rule set allowed the return direction and dropped the
  outbound one; measured on real packets between two nodes. It is a fault and
  not a setting — whoever observed it needs only the new version, no action.
- **The agent no longer ends by itself.** A broken entry in the cache costs its
  workload, not the node — whoever relied on an exit code as a configuration
  error must look at readiness and finding. (ADR-0062)
- **An agent intermediate with a key type other than Ed25519** mints SVIDs
  without complaint, and **none of them is accepted** — the verifier knows only
  `1.3.101.112`. The fault shows only at the first connection. (ADR-0014,
  "Verdrahtung")
- **The report has one field more** (`retired`, ADR-0104) — a format break
  (ADR-0072) that belongs in the same bundled maintenance window as the others.
  Until it has been run, the leader clears away no tombstones: an old node
  reports nothing, an old `tgd` would reject a new one's report. Both are
  conservative — the instruction stays, and the volume is deleted anyway.
