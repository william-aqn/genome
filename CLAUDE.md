# CLAUDE.md

## Project overview

Chameleon (`genome`) — polymorphic UDP tunneling protocol in Go. Every session derives a unique wire format ("genome") from a PSK via HKDF. Traffic appears as pure noise (~7.9 bits/byte entropy). Applications connect through a local SOCKS5 proxy; streams are multiplexed over one encrypted UDP tunnel to an exit server.

## Architecture (bottom-up)

1. **`internal/randutil`** — Deterministic PRNG (SHA-256 counter mode). Platform-stable, never use `math/rand` for genome derivation.
2. **`crypto/`** — HKDF-SHA256 key derivation from PSK. AEAD: ChaCha20-Poly1305 (12-byte nonce), XChaCha20-Poly1305 (24-byte nonce), AES-256-GCM. Nonce = genome-derived prefix || epoch (big-endian uint32).
3. **`morph/`** — Core polymorphism. `Derive(seed) -> *Genome` generates the wire format: magic byte, field order (Fisher-Yates), 0-3 decoy fields, nonce size 12/24, length encoding (BE/LE/varint/XOR), padding range. `Encoder`/`Decoder` handle frame serialization. Morph layer is crypto-agnostic — it never calls AEAD directly.
4. **`mux/`** — Stream multiplexer over `TransportConn` interface. Commands: OPEN, DATA, CLOSE, ACK. Full reliable delivery: per-stream sequence numbers, SACK, fast retransmit (3 dup ACKs), RTT estimation (Jacobson/Karels), NewReno congestion control, per-stream flow control. StreamID allocation: client=odd, server=even.
5. **`transport/`** — UDP tunnel glue: `payload -> AEAD.Seal -> morph.Encode -> UDP`. Anti-replay sliding window (256 epochs). Random initial epoch prevents replay rejection on reconnect. Server discovers peer from first valid packet. UDP read timeouts are non-fatal (retry loop).
6. **`socks5/`** — RFC 1928 SOCKS5, CONNECT only, no-auth. Hands off to `ConnectHandler`.
7. **`proxy/`** — Client: SOCKS5 -> `session.Open` -> bidirectional relay. Server: `session.Accept` -> `net.Dial` -> relay.
8. **`config/`** — JSON config + CLI flags. PSK is hex-encoded.
9. **`cmd/client/`, `cmd/server/`** — Entry points with graceful shutdown (SIGINT/SIGTERM). Drop callback logging for diagnostics.
10. **`cmd/probe/`** — Tunnel diagnostic tool: sends one OPEN and prints server response / drop reasons.
11. **`internal/dashboard/`** — Real-time ANSI console dashboard for the client: traffic stats, active streams, requests, logs.

## Build, test, deploy

```bash
go build ./...            # build all
go test ./... -v          # run all tests
go test ./... -count=1    # no cache
go test ./proxy/ -v       # integration tests (end-to-end through tunnel)

bash build.sh             # cross-compile linux/windows amd64/arm64 → dist/
bash test.sh              # vet + unit + integration + race detector
bash e2e-test.sh          # build, start client+server, curl through tunnel
bash release.sh v0.2.0    # build + create GitHub release with binaries
```

### Server deployment (one line)
```bash
curl -sSL https://raw.githubusercontent.com/william-aqn/genome/main/install-server.sh | sudo bash
```
Installs binary, generates PSK, opens firewall, creates systemd service.
Re-running upgrades the binary only (preserves PSK/config/port).

### Running client for debugging (from Claude Code)
Always use `-no-ui` when launching the client from this terminal — the ANSI dashboard corrupts piped output. Use `-log debug` for full diagnostics:
```bash
./chameleon-client -no-ui -log debug -server HOST:PORT -psk PSK_HEX -socks 127.0.0.1:1080 -socks-user USER -socks-pass PASS
```
The client auto-loads `client.json` if it exists next to the executable — no flags needed for repeated runs.

## Key design decisions

- **Morph is crypto-agnostic**: frame encode/decode never touches AEAD. Transport orchestrates both. This keeps layers independently testable.
- **Epoch-as-nonce**: monotonic counter zero-padded to NonceSize with genome-derived prefix. Eliminates nonce reuse risk. No random nonces.
- **Random initial epoch**: each tunnel starts from a random epoch to prevent replay window collisions when a client reconnects to a running server.
- **SHA-256 counter mode for PRNG** (not `math/rand`): algorithm stability across Go versions is critical for cross-platform genome determinism.
- **Odd/even StreamIDs**: client=odd, server=even. No handshake needed for ID coordination.
- **Single external dep**: only `golang.org/x/crypto`. `golang.org/x/net` is test-only (SOCKS5 client).
- **UDP MTU budget**: MSS must account for morph header + AEAD overhead + max padding. Safe payload ~1050-1100 bytes per packet.
- **Server never times out**: idle timeout disabled on server; it waits for clients indefinitely. UDP read timeouts retry instead of crashing.
- **No -s -w in ldflags**: stripped Go binaries trigger Kaspersky false positives. Keep debug symbols.

## Performance

Measured on a real VDS (Russia -> Europe):
- Download: ~2.16 Mbit/s
- Upload: ~1.17 Mbit/s
- Overhead: ~100-150 bytes/packet (morph header + AEAD tag + padding)

Playwright test results (12/12 pass):
- Simple sites (example.com, httpbin.org): 150-500ms
- Wikipedia with full CSS/JS/images: ~400ms
- Parallel 3 sites simultaneously: ~800ms
- Heavy sites (github.com): slow but don't block other streams

## Mux tuning (congestion / flow control)

Key parameters in `mux/`:
- **Initial CWND**: 256 KB (`congestion.go`) — high to avoid starving parallel streams in slow start
- **Min CWND**: 32 KB — prevents collapse on loss
- **Max CWND**: 16 MB — allows full utilization on fast links
- **Default recv window**: 512 KB per stream (`flowcontrol.go`)
- **Retransmit check interval**: 100ms (`stream.go`)
- **Flow control**: per-stream only, no global congestion blocking on Write path. Congestion control (NewReno) adjusts sending rate via ACK feedback but doesn't block individual stream writes.
- **WaitForSendWindow**: uses `sync.Cond` broadcast (wakes ALL blocked streams, not just one)
- **SendBuffer.Outstanding**: O(1) cached counter

If heavy sites still hang, check: congestion window collapse (too many OnTimeout calls), recv window exhaustion (slow Read draining), or UDP packet loss on the link.

## Important invariants

- Same PSK + same code version = identical genome on any platform. If you change `internal/randutil` or `morph/genome.go`, verify cross-platform determinism.
- `morph.Encoder.Encode` output must be indistinguishable from random. The entropy test in `morph/morph_test.go` (`TestFrameEntropy`) must pass >= 7.9 bits/byte.
- Anti-replay window in `transport/tunnel.go` rejects epoch 0 and epochs outside the sliding window. Resets when peer address changes (client reconnect).
- `mux.Session.recvLoop` runs independently of any stream's Write path — this prevents deadlocks where both sides block on flow control.
- All per-stream goroutines (retransmit loop) are tied to `stream.done` channel and stop on Close.
- Stream.Write uses per-stream flow control only. Global congestion control is advisory (affects ACK-driven rate, not blocking).

## Sensitive data policy

**NEVER commit real IPs, PSKs, passwords, SSH keys, or any credentials to the repository.** Before every commit:
- Check `git diff --staged` for IP addresses, hex keys, passwords, hostnames
- Use placeholders: `YOUR_SERVER_IP`, `PSK_HEX`, `YOUR_PASSWORD`
- The `deployment/` directory is gitignored — keep all real configs, keys, and connection scripts there
- README examples must use only placeholder values
- If sensitive data was accidentally committed, rewrite history with `git filter-repo` immediately

## Code style

- Pure Go, minimal dependencies.
- No global state. Configuration passed explicitly.
- `log/slog` for structured logging.
- Errors wrapped with `fmt.Errorf("package: context: %w", err)`.
- No generics unless they clearly simplify. Interfaces for testability (`mux.TransportConn`, `mux.CongestionController`).

## File layout

```
genome/
├── cmd/{client,server}/main.go   # entry points
├── cmd/probe/main.go             # tunnel diagnostics
├── config/config.go              # JSON + flags
├── crypto/{aead,keys}.go         # AEAD + HKDF
├── internal/randutil/            # deterministic PRNG
├── internal/logger/              # slog wrapper
├── morph/{genome,frame,lengthcodec,padding}.go  # polymorphism core
├── mux/{command,stream,session,reliability,congestion,flowcontrol}.go
├── proxy/{client,server}.go      # SOCKS5 <-> mux bridge
├── socks5/server.go              # SOCKS5 CONNECT
├── transport/{tunnel,shaper}.go  # UDP + morph + AEAD
├── build.sh                      # cross-compile
├── test.sh                       # full test suite
├── e2e-test.sh                   # live tunnel test
├── release.sh                    # GitHub release
└── install-server.sh             # one-line server deploy
```

## Extending

- **Add ECDH handshake (Elligator2)**: add `handshake/` package. Derive ephemeral salt from key exchange, pass to `crypto.DeriveSessionKeys`. The genome changes per-session automatically.
- **Add BBR congestion control**: implement `mux.CongestionController` interface in `mux/congestion.go`. Session already uses the interface.
- **Add protocol mimicry**: extend `morph/genome.go` to optionally prepend TLS/HTTP headers. Keep it behind a genome flag.
- **Add UDP ASSOCIATE to SOCKS5**: extend `socks5/server.go` with command 0x03 handler.
