# memhunt

Hunt keys in a memory dump from a single known artifact.

During reverse engineering you often capture an encrypted request parameter, a
signature, or a hashed value — but have no idea which key produced it, only
that the secret must still be sitting somewhere in the process's memory.
memhunt turns that into a one-liner: slide a window over every byte of the
dump, try each window as a key (or hash/HMAC), and keep the candidates that
match your artifact.

A modern, fast, cross-platform rewrite of the idea behind
[HZJQF/help_tool](https://github.com/HZJQF/help_tool) (unmaintained since
2024-10), implemented in Rust. Also backports the classic memory-forensics
technique of detecting AES expanded key schedules.

## Five things it does

| Mode | Artifact you have | What it finds |
|---|---|---|
| `scan` | a known ciphertext | the cipher key (AES-128/192/256 ECB/CBC/CTR/GCM, DES, 3DES-EDE3, SM4 ECB/CBC) |
| `hash` | a digest (MD5/SHA-1/SHA-256/SM3) | the hashed bytes still resident in the dump |
| `hash --mode hmac_key` | a MAC + the signed message | the HMAC secret key |
| `key-schedules` | a dump, nothing else | expanded AES key schedules (key = schedule head) |
| `serve` | an MCP client | the four modes as Model-Context-Protocol tools for AI agents |

## Install

Requires Rust 1.75+.

```sh
cargo install --path crates/memhunt-cli
# or
cargo build --release
```

## Usage

### Block-cipher key hunt (given a ciphertext)

```sh
# Scan a process dump for the key behind a captured ciphertext (hex or base64)
memhunt scan app_dump.bin --target 8a4c4056e06d89ef...

# Restrict to AES-128, stop after the first hit
memhunt scan app_dump.bin --target <ciphertext> --cipher aes-128 --max-hits 1

# Include more ciphers (DES, 3DES, SM4) in one pass
memhunt scan app_dump.bin --target <ciphertext> --cipher all

# Pin a known plaintext fragment (strongest oracle)
memhunt scan app_dump.bin --target <ciphertext> --oracle known:password,utf8

# Known IV (enables single-block CBC scans)
memhunt scan app_dump.bin --target <ciphertext> --iv 000102...0f

# AES-CTR with a known 16-byte initial counter block
memhunt scan app_dump.bin --target <ciphertext> \
    --cipher aes-128-ctr --nonce f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff

# AES-GCM with a 12-byte nonce and authentication tag (zero false positives)
memhunt scan app_dump.bin --target <ciphertext> \
    --cipher aes-256-gcm --nonce cafebabefacedbaddecaf888 \
    --tag 4d5c2af327cd64a62cf35abd2ba6fab4

# AES-GCM without a tag falls back to keystream decryption plus oracles
memhunt scan app_dump.bin --target <ciphertext> \
    --cipher aes-256-gcm --nonce cafebabefacedbaddecaf888 --oracle json

# JSON Lines output for scripting / AI agents
memhunt scan app_dump.bin --target <ciphertext> --json
```

`--cipher` accepts a comma-separated list: `aes-128`, `aes-192`, `aes-256`,
`des`, `3des`, `sm4`, `chacha20`, `xchacha20`, `aes` (= all three AES sizes),
`chacha20-poly1305`, `xchacha20-poly1305`, or `all`. AES tokens may also use a
`-ctr` or `-gcm` suffix, such as `aes-128-ctr` or `aes-gcm`. CTR requires a
16-byte initial counter block in `--nonce`; GCM a 12-byte nonce. GCM accepts
optional `--tag` (16 bytes) and `--aad` (hex); a tagged scan verifies keys
cryptographically and needs no oracle. ChaCha20 takes a 12-byte nonce,
XChaCha20 a 24-byte nonce; `--tag` turns a ChaCha hunt into Poly1305 AEAD
verification (with optional `--aad`). Block-mode tokens (`des`, `3des`, `sm4`) may not
mix with AES modes or stream ciphers. All tokens in one list must select the
same mode.

Output goes to stdout, progress and stats to stderr. Exit codes: `0` hit
found, `1` no hit, `2` error.

### Hash preimage & HMAC-key hunt (given a digest)

```sh
# Find the hashed bytes in the dump (e.g. the plaintext behind a sign= digit)
memhunt hash app_dump.bin --digest <hex> --mode preimage \
    --algos md5,sha256

# Recover the HMAC secret key from a captured MAC + the signed message
memhunt hash app_dump.bin --digest <hex> --mode hmac_key \
    --algos sha256 --message "GET /api?a=1"
```

Preimage / HMAC-key windows are scanned across the configured length range
(`--min-len 8 --max-len 128` by default) plus the common 16/24/32/64-byte
HMAC key sizes.

### AES key-schedule detection (no ciphertext needed)

```sh
# Find expanded AES keys (the schedule head = the key itself) in the dump
memhunt key-schedules app_dump.bin
memhunt key-schedules app_dump.bin --json
```

Any 32-byte window whose first 16/24/32 bytes expand forward (FIPS-197) to the
following words is a key-schedule head. False positives are ~2^-32 per window
(4 words of agreement), so on real dumps a hit is essentially always a live
OpenSSL-type expanded key.

### MCP server (AI agents)

```sh
memhunt serve
```

Speaks Model Context Protocol over stdio (JSON-RPC 2.0, newline-delimited).
Exposes the tools `memhunt_scan`, `memhunt_key_schedules`, and
`memhunt_hash_scan`. Point any MCP client at `memhunt serve`.

For Codex, add the server to `~/.codex/config.toml` using an absolute binary
path, then restart the client and run `/mcp`:

```toml
[mcp_servers.memhunt]
command = "/absolute/path/to/memhunt"
args = ["serve"]
startup_timeout_sec = 20
tool_timeout_sec = 600
```

The model can then choose a tool from a natural-language request. For example,
an AES-256-GCM key hunt sends:

```json
{
  "dump_path": "/path/to/process.dump",
  "ciphertext": "<hex-or-base64>",
  "ciphers": "aes-256-gcm",
  "nonce": "<12-byte-hex>",
  "tag": "<16-byte-hex>",
  "oracles": "json"
}
```

`memhunt_key_schedules` takes only `dump_path`; `memhunt_hash_scan` takes
`dump_path`, `mode`, `digest`, and optionally `algos`, `message`, `min_len`,
and `max_len`. Tool execution failures are returned as MCP results with
`isError: true`.

## How it works

Two ideas make the ciphertext path practical:

1. **Oracle-driven verification.** Each candidate key is validated by *what
   the decryption looks like*: valid UTF-8 text (`utf8`), a JSON document
   (`json`), a plaintext fragment (`known:<text>`), or a gzip / protobuf magic
   header. Oracles are composable and confidence-rated (`known`/`json`/`gzip`
   = high, `utf8`/`protobuf` = medium).

2. **IV-free CBC verification.** In CBC mode, blocks 1..n decrypt without the
   IV (`P[i] = D(K, C[i]) XOR C[i-1]`). memhunt verifies the key on those
   blocks first; only after a hit does it scan the dump again to locate the IV,
   ranking candidates by oracle confidence.

Only the first two ciphertext blocks are decrypted during candidate
validation; full decrypt and padding strip run once per hit. CTR and GCM use
the same two-block limit for oracle validation, then fully decrypt on a hit;
streaming ciphertexts do not need block alignment. GCM keystream blocks start
at `inc32(J0)`, where `J0 = nonce || 0^31 || 1`; the authentication tag uses
`J0` itself. When a GCM tag is supplied, memhunt verifies the complete
ciphertext/tag pair with RustCrypto `aes-gcm`, yielding a deterministic High
confidence hit with no oracle. Scan with `rayon` across all cores and AES-NI
when available. DES/3DES (8-byte blocks) and SM4 (16-byte blocks) ride the same
generic engine through a small version-bridging adapter.

### IV candidates

CBC key verification is IV-independent, so the IV is located in a second pass
after a hit. A candidate IV is accepted when the concatenation of its
decrypted block 0 and the (already-verified) following blocks passes an
oracle. Candidates are ranked by oracle confidence, then block-0
"plaintext-ness", then offset, and up to 8 are returned. Weak oracles (`utf8`
alone) can make several IVs tie — add a `json`/`known:` oracle to pin the
unique one.

### Sizes

- Only the first two ciphertext blocks (`VERIFY_BLOCKS = 2`) are consulted to
  validate a candidate key.
- ECB/CBC ciphertext must be a multiple of the cipher's block size (16 for
  AES/SM4, 8 for DES/3DES); CTR/GCM ciphertext may be any non-empty length.
- Single-block CBC scans need a fixed `--iv`.
- Preimage/HMAC windows scan lengths in `--min-len..=--max-len` (default
  8..=128) plus fixed 16/24/32/64-byte HMAC keys.

## Where dumps come from

Any raw process/core dump works: `procdump`, `gcore`, `frida-dump`, or a
custom `ptrace`/`ReadProcessMemory` script. memhunt only needs raw bytes.

## Regression harness

`scripts/repro_regression.py` rebuilds the v0.1.0 handover bug scenarios
(exit-code contract, utf8-only IV ambiguity, `known:` fragment in a later
block, default-oracle IV pinning) against a deterministic dump and asserts
the fixed behavior end-to-end against the built binary:

```sh
cargo build --release
./scripts/repro_regression.py            # or pass a binary path explicitly
```

Requires `openssl`; Python 3.8+ stdlib only. Exits non-zero on any failure.

## Roadmap

- [x] DES / 3DES / SM4 block-cipher hunting
- [x] ChaCha20 / XChaCha20 stream-cipher and Poly1305-AEAD hunting
- [x] SM4 round-key schedule structure detection (no ciphertext required)
- [x] MD5 / SHA-1 / SHA-256 / SM3 preimage and HMAC-key matching
- [x] AES key-schedule structure detection (no ciphertext required)
- [x] gzip / protobuf magic oracles
- [x] MCP server mode for AI-agent integration
- [ ] Rijndael-256 / Camellia / ChaCha20 (stream cipher key searches)
- [ ] CFB / OFB mode verification
- [x] CTR mode verification
- [x] AES-GCM mode verification (tag and oracle paths)
- [ ] Runtime maps (map hits back to allocations)

## License

Apache-2.0. Use only on systems you are explicitly authorized to analyze.