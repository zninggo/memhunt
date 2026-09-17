#!/usr/bin/env python3
"""memhunt regression harness: reproduces the three v0.1.0 handover bugs.

Scenarios (all against a deterministic 1 MiB dump):
  1. exit-code contract .... hit=0, no-hit=1, error=2
  2a. utf8-only IV scan .... true IV must appear among iv_candidates (top-8)
  2b. known:<frag> in a later plaintext block ... no 16-'?' block, candidates
      non-empty, full plaintext decodable
  baseline utf8,json ...... true IV pinned @ IV_OFFSET with High confidence

Usage:
  ./scripts/repro_regression.py [path-to-memhunt-binary]
                                (default: target/release/memhunt)

Requires: openssl (enc -aes-128-cbc). Python 3.8+ stdlib only.
Exits 0 iff every assertion holds.
"""
import hashlib
import os
import subprocess
import sys

KEY = bytes(range(16))                       # 000102..0f
IV = bytes(range(0x10, 0x20))                # 101112..1f
KEY_OFF = 0x30000
IV_OFF = 0x50000
DUMP_SIZE = 1024 * 1024
# "admin" starts at byte 22 => inside block 1 (bytes 16..32), NOT block 0.
PLAINTEXT = b'{"x":"aaaaaaaaaaaaaaaaadmin","ok":true}' + b" " * 9
assert len(PLAINTEXT) == 48 and PLAINTEXT[22:27] == b"admin"


def build_dump(path):
    """Deterministic xorshift64* filler (same PRNG as the integration tests)."""
    state = 0x9E3779B97F4A7C15
    out = bytearray()
    while len(out) < DUMP_SIZE:
        state ^= state >> 12
        state ^= (state << 25) & 0xFFFFFFFFFFFFFFFF
        state ^= state >> 27
        out += (state * 0x2545F4914F6CDD1D & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")
    out = out[:DUMP_SIZE]
    out[KEY_OFF:KEY_OFF + 16] = KEY
    out[IV_OFF:IV_OFF + 16] = IV
    with open(path, "wb") as f:
        f.write(bytes(out))


def openssl_cbc(pt, key, iv):
    r = subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-nopad", "-K", key.hex(), "-iv", iv.hex()],
        input=pt, capture_output=True, check=True)
    assert len(r.stdout) == len(pt)
    return r.stdout


def run(binary, dump, ct_hex, oracle, extra=()):
    p = subprocess.run(
        [binary, "scan", dump, "--target", ct_hex, "--oracle", oracle,
         "--cipher", "aes-128", *extra],
        capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def check(label, ok, detail=""):
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}" + (f"  ({detail})" if detail else ""))
    return ok


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                             else os.path.join(root, "target/release/memhunt"))
    if not os.path.isfile(binary):
        sys.exit(f"memhunt binary not found: {binary} (build with cargo build --release)")

    work = os.path.join(root, "target", "repro")
    os.makedirs(work, exist_ok=True)
    dump = os.path.join(work, "dump.bin")
    build_dump(dump)

    ct = openssl_cbc(PLAINTEXT, KEY, IV).hex()
    wrong_key_ct = openssl_cbc(PLAINTEXT, b"\xff" * 16, IV).hex()
    all_ok = True
    print(f"binary={binary}\ndump={dump} (key@{KEY_OFF:#x} iv@{IV_OFF:#x})\n")

    # --- 1. exit-code contract ------------------------------------------------
    print("[1] exit codes")
    rc, _, _ = run(binary, dump, ct, "utf8,json")
    all_ok &= check("hit exits 0", rc == 0, f"rc={rc}")
    rc, _, err = run(binary, dump, wrong_key_ct, "json")
    all_ok &= check("no-hit exits 1", rc == 1, f"rc={rc}")
    rc, _, _ = run(binary, dump + ".missing", ct, "json")
    all_ok &= check("missing dump exits 2", rc == 2, f"rc={rc}")

    # --- 2a. utf8-only: true IV must be among iv_candidates -------------------
    print("[2a] utf8-only IV ambiguity is surfaced, not hidden")
    rc, out, _ = run(binary, dump, ct, "utf8")
    cand_offsets = [int(l.split("@")[1].split()[0])
                    for l in out.splitlines() if "iv-candidate[" in l and "@" in l]
    all_ok &= check("exit 0 on hit", rc == 0, f"rc={rc}")
    all_ok &= check(f"true IV @{IV_OFF} in iv_candidates",
                    IV_OFF in cand_offsets, f"candidates={cand_offsets}")

    # --- 2b. known-fragment in a later block: no '?' block, candidates exist --
    print("[2b] known:admin (fragment in block 1)")
    rc, out, _ = run(binary, dump, ct, "known:admin")
    all_ok &= check("exit 0 on hit", rc == 0, f"rc={rc}")
    all_ok &= check("block 0 decoded (no 16 '?')",
                    "????????????????" not in out)
    all_ok &= check("tail plaintext visible", 'admin","ok":true}' in out)
    has_cands = "iv-candidate[" in out
    all_ok &= check("iv_candidates non-empty", has_cands)

    # --- baseline: default oracles pin the true IV -----------------------------
    print("[baseline] utf8,json pins the true IV")
    rc, out, _ = run(binary, dump, ct, "utf8,json")
    all_ok &= check("exit 0 on hit", rc == 0, f"rc={rc}")
    all_ok &= check(f"iv =@{IV_OFF}", f"iv =@{IV_OFF} {IV.hex()}" in out)
    all_ok &= check("full plaintext decodes", PLAINTEXT.decode() in out)
    all_ok &= check("top candidate is the true IV, High confidence",
                    "iv-candidate[0] @{IV_OFF} High".format(IV_OFF=IV_OFF) in out)

    print("\nRESULT:", "ALL PASS" if all_ok else "FAILURES PRESENT")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
