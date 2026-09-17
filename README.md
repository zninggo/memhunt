# memhunt

Hunt AES keys in a memory dump from a single known ciphertext.

During reverse engineering you often capture an encrypted request parameter but
have no idea which key encrypted it — only that the key must still be sitting
somewhere in the process's memory. memhunt turns that into a one-liner: slide a
window over every byte of the dump, try each window as an AES key, and keep the
candidates whose decryption validates against pluggable oracles.

A modern, fast, cross-platform rewrite of the idea behind
[HZJQF/help_tool](https://github.com/HZJQF/help_tool) (unmaintained since
2024-10), implemented in Rust.

## Install

Requires Rust 1.75+.

```sh
cargo install --path crates/memhunt-cli
# or
cargo build --release
```

## Usage

```sh
# Scan a process dump for the key behind a captured ciphertext (hex or base64)
memhunt scan app_dump.bin --target 8a4c4056e06d89ef...

# Restrict to AES-128, stop after the first hit
memhunt scan app_dump.bin --target <ciphertext> --key-size 128 --max-hits 1

# Pin a known plaintext fragment (strongest oracle)
memhunt scan app_dump.bin --target <ciphertext> --oracle known:password,utf8

# Known IV (enables single-block CBC scans)
memhunt scan app_dump.bin --target <ciphertext> --iv 000102...0f

# JSON Lines output for scripting / AI agents
memhunt scan app_dump.bin --target <ciphertext> --json
```

Output goes to stdout, progress and stats to stderr. Exit codes: `0` hit
found, `1` no hit, `2` error.

## How it works

Two ideas make this practical:

1. **Oracle-driven verification.** Instead of comparing against a known key,
   each candidate key is validated by *what the decryption looks like*:
   valid UTF-8 text (`utf8`), a JSON document (`json`), or a known plaintext
   fragment (`known:<text>`). Oracles are composable and confidence-rated
   (`known`/`json` = high, `utf8` = medium).

2. **IV-free CBC verification.** In CBC mode, blocks 1..n decrypt without the
   IV (`P[i] = D(K, C[i]) XOR C[i-1]`). memhunt verifies the key on those
   blocks first; only after a hit does it scan the dump a second time to
   locate the IV itself — with candidates ranked by oracle confidence to
   reject false positives.

Only the first two ciphertext blocks are decrypted during candidate
validation; full decryption and padding checks (pkcs7 / zero) run once per
hit. Scan with `rayon` across all cores and AES-NI when available.

### IV candidates

Because CBC key verification is IV-independent (`P[i] = D(K, C[i]) XOR
C[i-1]`), the IV itself is located in a second scan pass after a hit. A
candidate IV is accepted when the concatenation of its decrypted block 0 and
the (already-verified) following blocks passes an oracle — so `known:<text>`
fragments in any block, and JSON structure that spans the block-0 boundary,
are honored. Candidates are ranked by oracle confidence, then block-0
"plaintext-likeness", then offset, and up to 8 are returned as
`iv_candidates` (best first) in JSON output; the human report prints each.

**Weak oracles are honest about ambiguity.** With `utf8` alone, many random
16-byte windows decrypt to "printable" text, so several candidate IVs can tie —
the top pick is best-effort, not guaranteed. Add a block-0-sensitive oracle
(`json`, or a `known:<...>` fragment that sits in the first plaintext block) to
pin the unique IV. The default `utf8,json` set usually resolves it.

### Key / ciphertext size limits

Only the first two ciphertext blocks (`VERIFY_BLOCKS = 2`) are consulted to
validate a candidate key. That means:
- In **CBC**, a `known:<fragment>` must sit inside plaintext bytes 16..48
  (blocks 1..2) to confirm the key.
- In **ECB**, the fragment must sit inside plaintext bytes 0..32 (blocks 0..1).
- Ciphertext must be a multiple of 16 bytes; single-block CBC scans need a
  fixed `--iv`.

Measured on one test machine: a 64 MiB dump scanned across all three AES key
sizes (201M candidate windows) in ~9s — roughly 50x the throughput of the
original Python implementation.

## Where dumps come from

Any raw process/core dump works: `procdump`, `gcore`, `frida-dump`, or a
custom `ptrace`/`ReadProcessMemory` script. memhunt only needs raw bytes.

## Roadmap

- [ ] DES / 3DES / SM4, hash and HMAC matching (md5/sha1/sha256/sm3)
- [ ] AES key-schedule structure detection (no ciphertext required)
- [ ] MCP server mode for AI-agent integration
- [ ] gzip / protobuf magic oracles

## License

Apache-2.0. Use only on systems you are authorized to analyze.
