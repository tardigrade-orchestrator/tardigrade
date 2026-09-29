# Provenance of the QUIC fixtures

All four datagrams are **recorded**, not built: they come from
`curl --http3-only` against a UDP socket that never answers. The stack beneath
is **ngtcp2 1.22.1 with OpenSSL 3.5.7** — foreign code that read RFC 9000 and
RFC 9001 independently. The same yardstick as `dig` in phase 9c, `rust-spiffe`
in 7c and `curl` in 10d.

| File | What stands in it |
|---|---|
| `named_0.bin`, `named_1.bin` | a `ClientHello` with SNI `s3.example.com` |
| `anon_0.bin`, `anon_1.bin` | the same stack against an **IP** — without SNI |

**Two datagrams per case, and that is the point.** OpenSSL 3.5's `ClientHello`
carries post-quantum key shares and does **not** fit into one Initial (1200
bytes before address validation). Whoever reads only the first packet sees
nothing here — exactly the finding for whose sake ADR-0092 determination 4
makes CRYPTO reassembly mandatory.

A self-built datagram would be no evidence: it would arise with the same crypto
with which it is read and would show only self-consistency. A recording shows
interoperability.

They are recorded anew like this:

```text
python3 - <<'PY'
import socket, subprocess, threading
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0))
port = s.getsockname()[1]; s.settimeout(5)
threading.Thread(target=lambda: subprocess.run(
    ["curl", "--http3-only", "-sS", "--max-time", "3",
     "--resolve", f"s3.example.com:{port}:127.0.0.1",
     f"https://s3.example.com:{port}/"], capture_output=True), daemon=True).start()
for k in range(2):
    open(f"named_{k}.bin", "wb").write(s.recvfrom(65535)[0])
PY
```
