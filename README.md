# Chameleon (genome)

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.19493212.svg)](https://doi.org/10.5281/zenodo.19493212)

Polymorphic UDP tunneling protocol. Each session derives a unique wire format ("genome") deterministically from a pre-shared key (PSK). Without the PSK, an observer sees only random bytes — no magic bytes, fixed headers, or recognizable handshakes.

[README на русском](README.RU.md)

## How It Works

```
Browser / curl / any application
        |  TCP
        v
  SOCKS5 (127.0.0.1:1080)        <-- client, accepts SOCKS5 CONNECT
        |
        v
  Chameleon client                 <-- multiplexer + encryption
        ║
   === UDP (polymorphic noise) === <-- only random bytes on the wire
        ║
        v
  Chameleon server                 <-- decryption + demultiplexer
        |  TCP
        v
  Target host (internet)
```

The PSK is expanded via HKDF into a **session genome** — a complete wire format specification:
- Pseudorandom magic byte (friend-or-foe filter)
- Header field order (Fisher-Yates shuffle)
- 0-3 decoy fields of random size
- Nonce size: 12 or 24 bytes
- Length encoding: uint16 BE / LE / varint / XOR-masked
- Padding range
- Wagon size range (for stream mode; see below)

Both sides know the PSK -> both derive the same genome -> they can communicate. A third party sees noise with ~7.9 bits/byte entropy.

## Stream Mode ("поток") — constant-rate cover traffic

Optional mode that hides **when** the user is active. From the moment the tunnel opens, a steady flow of fixed-shape "wagons" leaves the sender regardless of real traffic. Each wagon carries either real mux data (length-prefixed) or random chaff. An observer sees a river of ciphertext at a predictable rate and cannot distinguish browsing from idle.

- **Wagon size** is drawn per-packet from a **genome-derived range** `[WagonMin, WagonMax]`. From outside, sizes look random; only a peer knowing the PSK knows the envelope.
- **Flow rate envelope** is configurable: `stream_min_bytes_per_sec` and `stream_max_bytes_per_sec`. The pump drifts its target rate inside this window with a 1-second random walk — "the river is never at full flow".
- **Partial replacement**: when real data fits in a wagon, it's packed at the head and the rest is filler (`[uint16 RealLen][Real][Filler]`).
- **Full replacement + burst**: when the send queue builds up, the pump enters burst mode and drains at up to `4 × max_bps`, sending real data "as is" until the queue empties.
- **Receiver** strips the length prefix below the mux layer — chaff is invisible to the application.

Enable with `-stream` on both client and server. Both endpoints must agree on the mode; rate envelopes are local settings. Typical overhead: the new wire layout is backward-compatible — sessions without `-stream` work exactly as before.

## Architecture

| Layer | Package | Purpose |
|-------|---------|---------|
| Crypto | `crypto/` | AEAD (ChaCha20-Poly1305 / AES-256-GCM / XChaCha20), HKDF keys |
| Morph | `morph/` | Session genome, polymorphic framing (encode/decode) |
| Mux | `mux/` | Stream multiplexer with reliable delivery (SACK, fast retransmit, NewReno, flow control) |
| Transport | `transport/` | UDP tunnel = morph framing + AEAD + anti-replay, stream pump |
| SOCKS5 | `socks5/` | SOCKS5 CONNECT server (RFC 1928) |
| Proxy | `proxy/` | Client (SOCKS5 -> mux) and server (mux -> dial TCP) |

## Server Installation (one command)

```bash
curl -sSL https://raw.githubusercontent.com/william-aqn/genome/main/install-server.sh | sudo bash
```

The script:
- Downloads the binary (or builds from source)
- Generates a PSK
- Opens the UDP port in the firewall (ufw/firewalld/iptables)
- Creates a systemd service
- Prints the client connection command

Re-running upgrades only the binary, preserving PSK, config, and port.

## Performance

Measured on a real server (VDS, Russia -> Netherlands):

| Metric | Value |
|--------|-------|
| Peak throughput | **30 Mbit/s** (3.75 MB/s) |
| Speedtest.net (Ookla) | **2.16 / 1.17 Mbit/s** |
| 6.8 MB file download | **2 seconds** (stable, 5/5 attempts) |
| Parallel streams | 67 simultaneous requests, zero stalls |
| Degradation | **none** — no speed drop between downloads |
| Encryption | ChaCha20-Poly1305 |
| Overhead | ~100-150 bytes/packet (morph header + AEAD + padding) |

## Client

### Interactive mode (no arguments)

```
> chameleon-client.exe

Chameleon Client — Interactive Setup

  Server IP: YOUR_SERVER_IP
  Server port [9000]: 10322
  PSK (hex): 3e02d433...
  SOCKS5 port [random=38741]:
  SOCKS5 username [random=auto]:
  SOCKS5 password [random=auto]:

===========================================
  SOCKS5 proxy:  127.0.0.1:38741
  Username:      k7m2x9ab
  Password:      p3nq8fw2v5jt
  Server:        YOUR_SERVER_IP:10322
===========================================
```

Config is saved to `client.json` next to the executable. On the next launch it is loaded automatically — just double-click.

### With flags

```bash
./chameleon-client -server SERVER_IP:9000 -psk $PSK -socks-user myuser -socks-pass mypass
```

### Console dashboard

The client displays a real-time dashboard with traffic stats, active connections, and logs. For debugging without UI:

```bash
./chameleon-client -no-ui -log debug
```

### Usage

```bash
# curl through the tunnel
curl --proxy socks5://user:pass@127.0.0.1:1080 https://example.com

# Browser: set SOCKS5 proxy to 127.0.0.1:1080 with username/password
```

## Server (manual setup)

```bash
PSK=$(openssl rand -hex 32)
./chameleon-server -listen :9000 -psk $PSK
```

## Building

```bash
# Single binary
go build -o chameleon-client ./cmd/client
go build -o chameleon-server ./cmd/server

# Cross-compile (linux/windows, amd64/arm64)
bash build.sh
```

## CLI Flags

### Client

| Flag | Default | Description |
|------|---------|-------------|
| `-psk` | | PSK in hex |
| `-server` | | Server address (host:port) |
| `-socks` | random port | SOCKS5 proxy address |
| `-socks-user` | random | SOCKS5 username (RFC 1929) |
| `-socks-pass` | random | SOCKS5 password |
| `-cipher` | `chacha20` | `chacha20` or `aes256gcm` |
| `-log` | `info` | `debug`, `info`, `warn`, `error` |
| `-no-ui` | `false` | Disable dashboard, plain logs |
| `-config` | `client.json` | Path to JSON config (auto-detected next to exe) |
| `-stream` | `false` | Enable constant-rate cover traffic |
| `-stream-min-bps` | `500000` (when `-stream`) | Flow envelope lower bound, bytes/sec |
| `-stream-max-bps` | `3000000` (when `-stream`) | Flow envelope upper bound, bytes/sec |

### Server

| Flag | Default | Description |
|------|---------|-------------|
| `-psk` | | PSK in hex |
| `-listen` | `:9000` | UDP listen address |
| `-cipher` | `chacha20` | `chacha20` or `aes256gcm` |
| `-log` | `info` | `debug`, `info`, `warn`, `error` |
| `-config` | | Path to JSON config |
| `-stream` | `false` | Enable constant-rate cover traffic |
| `-stream-min-bps` | `500000` (when `-stream`) | Flow envelope lower bound, bytes/sec |
| `-stream-max-bps` | `3000000` (when `-stream`) | Flow envelope upper bound, bytes/sec |

### JSON config

```json
{
  "psk": "a1b2c3d4...",
  "listen_addr": ":9000",
  "peer_addr": "1.2.3.4:9000",
  "socks_addr": "127.0.0.1:1080",
  "socks_user": "myuser",
  "socks_pass": "mypass",
  "cipher_suite": "chacha20",
  "log_level": "info",
  "idle_timeout_sec": 300,

  "stream_mode": true,
  "stream_min_bytes_per_sec": 500000,
  "stream_max_bytes_per_sec": 3000000
}
```

## Tests

```bash
go test ./... -v          # all tests
bash test.sh              # vet + unit + integration + race detector
bash e2e-test.sh          # full test: build, client+server, curl through tunnel
```

Coverage:
- **Determinism**: same seed -> identical genome and PRNG output
- **Round-trip**: encode -> decode for all layers (frame, command, AEAD)
- **Entropy**: wire output >= 7.9 bits/byte (Shannon test)
- **Replay protection**: anti-replay sliding window
- **Mux**: send/receive buffers, SACK, RTT estimator, NewReno, flow control
- **SOCKS5**: IPv4, domain, unsupported command rejection
- **End-to-end**: HTTP via SOCKS5 -> tunnel -> HTTP server
- **Parallel streams**: 10 simultaneous requests through tunnel

## Diagnostics

```bash
# Check connectivity to server
go run ./cmd/probe SERVER_IP:PORT PSK_HEX
```

Probe sends a single OPEN packet and prints the server response or drop reason (decode/replay/aead).

## Project Structure

```
genome/
├── cmd/
│   ├── client/main.go          # Client CLI
│   ├── server/main.go          # Server CLI
│   └── probe/main.go           # Tunnel diagnostics
├── config/config.go            # Configuration
├── crypto/
│   ├── aead.go                 # AEAD ciphers
│   └── keys.go                 # HKDF key derivation
├── internal/
│   ├── logger/logger.go        # slog wrapper
│   └── randutil/deterministic.go # Deterministic PRNG
├── morph/
│   ├── genome.go               # Derive(seed) -> Genome
│   ├── frame.go                # Encode/Decode wire packets
│   ├── lengthcodec.go          # 4 length encoding variants
│   └── padding.go              # Random padding
├── mux/
│   ├── command.go              # OPEN/DATA/CLOSE/ACK
│   ├── stream.go               # io.ReadWriteCloser stream
│   ├── session.go              # Stream manager
│   ├── reliability.go          # Retransmit, SACK, RTT
│   ├── congestion.go           # NewReno
│   └── flowcontrol.go          # Per-stream flow control
├── proxy/
│   ├── client.go               # SOCKS5 -> mux
│   └── server.go               # mux -> TCP dial
├── socks5/server.go            # SOCKS5 CONNECT
├── transport/
│   ├── tunnel.go               # UDP + morph + AEAD
│   ├── stream_pump.go          # Constant-rate cover traffic ("wagons")
│   └── shaper.go               # Timing jitter
├── build.sh                    # Cross-compile
├── test.sh                     # Full test suite
├── e2e-test.sh                 # Live tunnel test
├── release.sh                  # GitHub release
└── install-server.sh           # One-line server deploy
```

## Reliable Delivery (TCP-over-UDP)

The multiplexer provides:
- Per-stream sequence numbers
- Selective ACK (SACK)
- Fast retransmit (3 duplicate ACKs)
- RTT estimation (Jacobson/Karels EWMA)
- Congestion control (NewReno: slow start, congestion avoidance, fast recovery)
- Per-stream flow control (receive window)
- Keepalive / idle timeout

## Threat Model

- **Passive observer with DPI**: cannot build a signature — each session is structurally unique
- **Replay attack**: anti-replay sliding window (256 epochs), random initial epoch
- **Tampered packets**: AEAD authentication, epoch in associated data
- **Active probing**: server does not respond without a valid first packet (PSK-only)
- **Timing / activity inference** (with `-stream`): a constant flow of wagons hides when the user is actually sending real data. Burst mode breaks this partially during heavy downloads — narrow the envelope to trade throughput for stricter cover.

### Known Limitations

- High-entropy traffic may be blocked as "too random" (noise paradox)
- PSK is exchanged out-of-band
- No forward secrecy without ECDH handshake (planned)

## Dependencies

- `golang.org/x/crypto` — ChaCha20-Poly1305
- `golang.org/x/net` — SOCKS5 client (test-only)

Everything else is Go standard library.
