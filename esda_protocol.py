#!/usr/bin/env python3
"""
ESDA Protocol — Engine, Shamir, Data, Algorithm
Paradox OS · Branden Duffield · Era 2, v1.1.0

A local-first cryptography workbench. Standard library only; the optional
audited-library cross-checks use `cryptography` and `coincurve` when installed.
Research / educational code: NOT independently audited, NOT constant-time.
Do not use it to protect real funds or real keys.
"""

import hashlib
import hmac
import json
import os
import platform
import secrets
import socket
import sqlite3
import sys
import time
import urllib.request
from datetime import datetime, timezone

VERSION = "Era 2, v1.1.0"
VOW = "ENCRYPTION NEVER DIES. IT ONLY GETS STRONGER."

RESULTS = []
LOG = []


def out(line=""):
    print(line)
    LOG.append(line)


def record(door, name, status, detail=""):
    """status: PASS, FAIL or SKIP"""
    RESULTS.append({"door": door, "test": name, "status": status, "detail": detail})
    out(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))


# ─────────────────────────────────────────────────────────────
# DOOR 1 — Shamir Secret Sharing over GF(257)
# ─────────────────────────────────────────────────────────────
PRIME = 257  # field prime; share values range 0..256 (9 bits), stored as 2 bytes


def _eval_poly(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % PRIME
    return acc


def _encode_share(values):
    return b"".join(v.to_bytes(2, "big") for v in values)


def _decode_share(blob):
    if len(blob) % 2:
        raise ValueError("malformed share")
    return [int.from_bytes(blob[i:i + 2], "big") for i in range(0, len(blob), 2)]


def shamir_split(secret: bytes, k: int, n: int):
    """Split secret into n shares; any k reconstruct it."""
    if not (2 <= k <= n < PRIME):
        raise ValueError("require 2 <= k <= n < 257")
    columns = {x: [] for x in range(1, n + 1)}
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(PRIME) for _ in range(k - 1)]
        for x in columns:
            columns[x].append(_eval_poly(coeffs, x))
    return [(x, _encode_share(v)) for x, v in columns.items()]


def shamir_reconstruct(shares):
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate share indices")
    cols = [_decode_share(b) for _, b in shares]
    if len({len(c) for c in cols}) != 1:
        raise ValueError("shares have different lengths")
    secret = bytearray()
    for i in range(len(cols[0])):
        s = 0
        for j, xj in enumerate(xs):
            num, den = 1, 1
            for m, xm in enumerate(xs):
                if m != j:
                    num = num * (-xm) % PRIME
                    den = den * (xj - xm) % PRIME
            s = (s + cols[j][i] * num * pow(den, -1, PRIME)) % PRIME
        if s > 255:
            raise ValueError("value out of byte range — wrong, too few, or corrupted shares")
        secret.append(s)
    return bytes(secret)


def door1():
    out("\nDOOR 1 — Guardian Lock (Shamir over GF(257))")
    secret = secrets.token_bytes(32)
    k, n = 3, 5
    shares = shamir_split(secret, k, n)

    subset = secrets.SystemRandom().sample(shares, k)
    ok = hmac.compare_digest(shamir_reconstruct(subset), secret)
    record(1, f"{k}-of-{n} reconstruct (random subset {sorted(x for x, _ in subset)})",
           "PASS" if ok else "FAIL")

    ok = hmac.compare_digest(shamir_reconstruct(shares), secret)
    record(1, f"all {n} shares reconstruct", "PASS" if ok else "FAIL")

    try:
        got = shamir_reconstruct(shares[: k - 1])
        ok = not hmac.compare_digest(got, secret)
    except ValueError:
        ok = True
    record(1, f"{k - 1} shares do NOT recover secret", "PASS" if ok else "FAIL")

    # Statistical secrecy check: one share of secret 0x00 and one share of 0xFF
    # should look the same. Fails if coefficients are not uniformly random.
    trials = 20000
    hist_lo, hist_hi = [0] * PRIME, [0] * PRIME
    for _ in range(trials):
        hist_lo[_decode_share(shamir_split(b"\x00", 2, 2)[0][1])[0]] += 1
        hist_hi[_decode_share(shamir_split(b"\xff", 2, 2)[0][1])[0]] += 1
    tvd = sum(abs(a - b) for a, b in zip(hist_lo, hist_hi)) / (2 * trials)
    record(1, "one share of 0x00 vs 0xFF statistically indistinguishable",
           "PASS" if tvd < 0.12 else "FAIL", f"total variation distance {tvd:.3f} over {trials:,} splits")


# ─────────────────────────────────────────────────────────────
# DOOR 2 — SHA-256 Hash-Chained Ledger
# ─────────────────────────────────────────────────────────────
GENESIS = b"\x00" * 32


def chain_create():
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE blocks (i INTEGER PRIMARY KEY, data BLOB NOT NULL, h BLOB NOT NULL)")
    return conn


def chain_write(conn, items):
    """h_i = SHA256(h_{i-1} || data_i). Returns the head hash."""
    row = conn.execute("SELECT h FROM blocks ORDER BY i DESC LIMIT 1").fetchone()
    prev = row[0] if row else GENESIS
    rows = []
    for data in items:
        prev = hashlib.sha256(prev + data).digest()
        rows.append((data, prev))
    conn.executemany("INSERT INTO blocks (data, h) VALUES (?, ?)", rows)
    conn.commit()
    return prev


def chain_verify(conn, expected_head=None):
    prev = GENESIS
    for i, data, h in conn.execute("SELECT i, data, h FROM blocks ORDER BY i"):
        calc = hashlib.sha256(prev + data).digest()
        if not hmac.compare_digest(calc, h):
            return False, i
        prev = calc
    if expected_head is not None and not hmac.compare_digest(prev, expected_head):
        return False, "head"
    return True, None


def chain_clone(conn):
    clone = sqlite3.connect(":memory:")
    conn.backup(clone)
    return clone


# ── S2: Merkle inclusion proofs (RFC 6962-style domain separation) ──────────
def _merkle_leaf(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _merkle_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_build(items):
    """All tree levels, leaves first. An odd node is promoted unchanged (no duplication,
    so the CVE-2012-2459 duplicate-leaf trick does not apply)."""
    level = [_merkle_leaf(d) for d in items]
    if not level:
        raise ValueError("empty tree")
    levels = [level]
    while len(level) > 1:
        level = [_merkle_node(level[i], level[i + 1]) if i + 1 < len(level) else level[i]
                 for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_proof(levels, index):
    """Sibling path for leaf `index`: list of (node_is_right_child, sibling_hash)."""
    proof = []
    for level in levels[:-1]:
        sib = index ^ 1
        if sib < len(level):
            proof.append((index & 1, level[sib]))
        index >>= 1
    return proof


def merkle_verify(root, data, proof):
    h = _merkle_leaf(data)
    for is_right, sib in proof:
        h = _merkle_node(sib, h) if is_right else _merkle_node(h, sib)
    return hmac.compare_digest(h, root)


# ── S3: on-disk ledger in SQLite WAL mode + crash recovery ───────────────────
WAL_BATCH = 100


def chain_open_file(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("CREATE TABLE IF NOT EXISTS blocks (i INTEGER PRIMARY KEY, data BLOB NOT NULL, h BLOB NOT NULL)")
    conn.commit()
    return conn


def _wal_writer(path, batches=5, inflight=20000):
    """Child process for the crash test: commit `batches` batches, then start a large
    transaction that is never committed and wait to be killed."""
    conn = chain_open_file(path)
    # Tiny cache + explicit spill threshold: uncommitted pages are forced into the WAL file.
    # (Apple's system SQLite defaults cache_spill to 20,000 pages, so cache_size alone is not enough.)
    conn.execute("PRAGMA cache_size=10")
    conn.execute("PRAGMA cache_spill=10")
    i = 0
    for _ in range(batches):
        head = chain_write(conn, ((i + j).to_bytes(8, "big") for j in range(WAL_BATCH)))
        i += WAL_BATCH
        print(f"committed {i} {head.hex()}", flush=True)
    prev = conn.execute("SELECT h FROM blocks ORDER BY i DESC LIMIT 1").fetchone()[0]
    for j in range(inflight):
        data = (i + j).to_bytes(8, "big")
        prev = hashlib.sha256(prev + data).digest()
        conn.execute("INSERT INTO blocks (data, h) VALUES (?, ?)", (data, prev))
    print("inflight", flush=True)
    time.sleep(120)


def wal_crash_test():
    """Kill -9 a writer in the middle of an uncommitted transaction, then reopen."""
    import subprocess, tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "ledger.db")
        proc = subprocess.Popen([sys.executable, os.path.abspath(__file__), "--wal-writer", path],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        last_count, last_head, wal_committed, wal_inflight = 0, None, 0, 0
        try:
            for line in proc.stdout:
                parts = line.split()
                if parts[0] == "committed":
                    last_count, last_head = int(parts[1]), bytes.fromhex(parts[2])
                    wal_committed = os.path.getsize(path + "-wal")
                elif parts[0] == "inflight":
                    wal_inflight = os.path.getsize(path + "-wal")
                    break
        finally:
            proc.kill()  # SIGKILL on POSIX: no cleanup, no commit
            proc.wait()
        if last_head is None or not wal_inflight:
            return False, f"writer did not reach mid-write: {proc.stderr.read().strip()[:200]}"
        conn = chain_open_file(path)  # recovery happens here
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        count = conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
        chain_ok, _ = chain_verify(conn, last_head)
        head2 = chain_write(conn, (b"after-recovery-%d" % k for k in range(10)))
        resume_ok, _ = chain_verify(conn, head2)
        conn.close()
        spilled = wal_inflight > wal_committed
        ok = (mode == "wal" and integrity == "ok" and count == last_count and chain_ok
              and resume_ok and spilled)
        return ok, (f"killed with {wal_inflight - wal_committed:,} B of uncommitted WAL frames on disk · "
                    f"reopened: {count} blocks = last commit {last_count}, integrity {integrity}, "
                    f"head matches, appends resume")


# ── S4: cross-check against audited libraries (optional) ─────────────────────
def _crosscheck_required():
    return os.environ.get("ESDA_REQUIRE_CROSSCHECK") == "1"


def _missing(door, name, what):
    status = "FAIL" if _crosscheck_required() else "SKIP"
    record(door, name, status, f"{what} not installed — pip install cryptography coincurve")


def door4_library_crosscheck():
    name = "8. audited-library cross-check: ESDA d·G matches OpenSSL and libsecp256k1"
    libs = []
    try:
        import cryptography
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization
        libs.append(f"cryptography {cryptography.__version__} (OpenSSL)")
    except ImportError:
        ec = None
    try:
        import coincurve
        libs.append(f"coincurve {getattr(coincurve, '__version__', '?')} (libsecp256k1)")
    except ImportError:
        coincurve = None
    if ec is None and coincurve is None:
        return _missing(4, name, "cryptography / coincurve")
    keys = [1, 2, 3, N - 1] + [secrets.randbelow(N - 1) + 1 for _ in range(16)]
    ok = True
    for d in keys:
        pub = scalar_mult(d, G)
        mine_c = compress(pub)
        mine_u = b"\x04" + pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")
        if ec is not None:
            lpub = ec.derive_private_key(d, ec.SECP256K1()).public_key()
            ok &= lpub.public_bytes(serialization.Encoding.X962,
                                    serialization.PublicFormat.CompressedPoint) == mine_c  # ct-ok: public keys
            ok &= lpub.public_bytes(serialization.Encoding.X962,
                                    serialization.PublicFormat.UncompressedPoint) == mine_u  # ct-ok: public keys
        if coincurve is not None:
            cpub = coincurve.PrivateKey(d.to_bytes(32, "big")).public_key
            ok &= cpub.format(compressed=True) == mine_c
            # ESDA's decompress must agree with libsecp256k1's
            ok &= coincurve.PublicKey(mine_c).format(compressed=False) == b"\x04" + b"".join(
                v.to_bytes(32, "big") for v in decompress(mine_c))
    if len(libs) < 2 and _crosscheck_required():
        record(4, name, "FAIL", f"only {', '.join(libs)} available")
        return
    record(4, name, "PASS" if ok else "FAIL",
           f"{len(keys)} keys incl. 1, 2, 3, n−1 · {' · '.join(libs)}")


def door6_library_crosscheck(key, msg, sig):
    name = "9. audited-library cross-check: cryptography signs with ESDA's key, identical bytes"
    try:
        import cryptography
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
    except ImportError:
        return _missing(6, name, "cryptography")
    pubn = rsa.RSAPublicNumbers(key["e"], key["n"])
    priv = rsa.RSAPrivateNumbers(key["p"], key["q"], key["d"], key["dp"], key["dq"], key["qi"],
                                 pubn).private_key()
    lib_sig = priv.sign(msg, padding.PKCS1v15(), hashes.SHA256())

    def lib_verifies(s, m):
        try:
            priv.public_key().verify(s, m, padding.PKCS1v15(), hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    same = lib_sig == sig
    a = lib_verifies(sig, msg)                       # ESDA → library
    b = rsa_verify(key["n"], key["e"], msg, lib_sig)  # library → ESDA
    c = not lib_verifies(sig, msg + b"!")             # library rejects tamper
    record(6, name, "PASS" if same and a and b and c else "FAIL",
           f"cryptography {cryptography.__version__} · key accepted · ESDA→lib {'ok' if a else 'FAIL'} · "
           f"lib→ESDA {'ok' if b else 'FAIL'} · bytes identical {'yes' if same else 'NO'} · tamper rejected {'yes' if c else 'NO'}")



def door2():
    out("\nDOOR 2 — Hash-Chained Ledger (SHA-256)")
    n_blocks = int(os.environ.get("ESDA_BLOCKS", "1000000"))
    conn = chain_create()
    t0 = time.perf_counter()
    head = chain_write(conn, (i.to_bytes(8, "big") for i in range(n_blocks)))
    dt = time.perf_counter() - t0
    record(2, f"write {n_blocks:,} blocks in RAM", "PASS", f"{dt:.2f} s")

    t0 = time.perf_counter()
    ok, _ = chain_verify(conn, head)
    dt = time.perf_counter() - t0
    record(2, "verify full chain against head", "PASS" if ok else "FAIL", f"{dt:.2f} s")

    # Tamper test on a clone: flip one byte in a middle block.
    clone = chain_clone(conn)
    target = n_blocks // 2
    data = bytearray(clone.execute("SELECT data FROM blocks WHERE i=?", (target,)).fetchone()[0])
    data[0] ^= 0x01
    clone.execute("UPDATE blocks SET data=? WHERE i=?", (bytes(data), target))
    ok, where = chain_verify(clone, head)
    record(2, "single-byte tamper detected", "PASS" if not ok else "FAIL", f"broken at block {where}")

    # Full rewrite attack: recompute every hash after tampering. Only the anchored head catches it.
    rewritten = chain_create()
    rows = [r[0] for r in clone.execute("SELECT data FROM blocks ORDER BY i")]
    forged_head = chain_write(rewritten, rows)
    internally_ok, _ = chain_verify(rewritten)
    ok_vs_anchor, _ = chain_verify(rewritten, head)
    record(2, "full-rewrite attack caught by anchored head",
           "PASS" if internally_ok and not ok_vs_anchor else "FAIL",
           "chain alone is NOT enough — publish the head")

    ok, _ = chain_verify(conn, head)
    record(2, "original chain unaffected by clone tamper", "PASS" if ok else "FAIL")

    # S2 — Merkle inclusion proofs over the same blocks
    for size in range(1, 65):
        items = [b"blk%d" % k for k in range(size)]
        lv = merkle_build(items)
        if not all(merkle_verify(lv[-1][0], items[k], merkle_proof(lv, k)) for k in range(size)):
            record(2, "Merkle proofs verify at every position, tree sizes 1–64", "FAIL", f"size {size}")
            break
    else:
        record(2, "Merkle proofs verify at every position, tree sizes 1–64", "PASS")

    t0 = time.perf_counter()
    blocks = [r[0] for r in conn.execute("SELECT data FROM blocks ORDER BY i")]
    levels = merkle_build(blocks)
    root = levels[-1][0]
    dt = time.perf_counter() - t0
    idx = secrets.randbelow(len(blocks))
    proof = merkle_proof(levels, idx)
    ok = merkle_verify(root, blocks[idx], proof)
    record(2, "Merkle inclusion: one block proven without sharing the chain", "PASS" if ok else "FAIL",
           f"block {idx:,}: {len(proof)} hashes ({len(proof) * 32:,} B) instead of {len(blocks):,} blocks · "
           f"tree built in {dt:.2f} s")

    tampered = bytes([blocks[idx][0] ^ 1]) + blocks[idx][1:]
    other = (idx + 1) % len(blocks)
    bad_proof = [(proof[0][0], bytes([proof[0][1][0] ^ 1]) + proof[0][1][1:])] + proof[1:]
    rejects = (not merkle_verify(root, tampered, proof)
               and not merkle_verify(root, blocks[other], proof)
               and not merkle_verify(root, blocks[idx], bad_proof))
    record(2, "Merkle proof rejects tampered block, wrong position, altered proof",
           "PASS" if rejects else "FAIL")

    forged = levels[0][0] + levels[0][1]          # an internal node's preimage posing as a leaf
    forged_proof = merkle_proof(levels[1:], 0)
    record(2, "Merkle domain separation: an internal node cannot pose as a leaf",
           "PASS" if not merkle_verify(root, forged, forged_proof) else "FAIL",
           "0x00 leaf / 0x01 node prefixes (RFC 6962)")
    del blocks, levels

    # S3 — on-disk WAL ledger survives kill -9 mid-write
    try:
        ok, detail = wal_crash_test()
    except Exception as e:
        ok, detail = False, f"{type(e).__name__}: {e}"
    record(2, "WAL ledger: kill -9 mid-write recovers to last commit", "PASS" if ok else "FAIL", detail)
    out(f"  head = {head.hex()}")


# ─────────────────────────────────────────────────────────────
# DOOR 3 — Observer-Quotient Affine Fast-Forward
# ─────────────────────────────────────────────────────────────
def affine_compose(f, g, m):
    """(f ∘ g)(x) = f(g(x)) for f = (a1, b1), g = (a2, b2)."""
    a1, b1 = f
    a2, b2 = g
    return (a1 * a2) % m, (a1 * b2 + b1) % m


def affine_power(a, b, n, m):
    """T^n as an affine map (A, B), via square-and-multiply: O(log n). Works for any m."""
    result, base = (1 % m, 0), (a % m, b % m)
    while n:
        if n & 1:
            result = affine_compose(base, result, m)
        base = affine_compose(base, base, m)
        n >>= 1
    return result


def fast_forward(x, a, b, n, m):
    A, B = affine_power(a, b, n, m)
    return (A * x + B) % m


def closed_form(x, a, b, n, m):
    """a^n x + b (a^n - 1)/(a - 1) mod m — only valid when gcd(a-1, m) = 1."""
    an = pow(a, n, m)
    return (an * x + b * (an - 1) * pow(a - 1, -1, m)) % m


def orbit_certificate(x, a, b, m, max_iter=None):
    """Cycle length of x under T, bounded by the field size m."""
    max_iter = m if max_iter is None else min(max_iter, m)
    y = x
    for length in range(1, max_iter + 1):
        y = (a * y + b) % m
        if y == x:
            return length
    return None


def door3():
    out("\nDOOR 3 — Observer-Quotient (affine fast-forward)")
    m = (1 << 61) - 1  # Mersenne prime
    a, b, x0 = 6364136223846793005 % m, 1442695040888963407 % m, 42
    n = int(os.environ.get("ESDA_ITERS", "10000000"))

    t0 = time.perf_counter()
    y = x0
    for _ in range(n):
        y = (a * y + b) % m
    naive_dt = time.perf_counter() - t0

    reps = 1000
    t0 = time.perf_counter()
    for _ in range(reps):
        z = fast_forward(x0, a, b, n, m)
    fast_dt = (time.perf_counter() - t0) / reps

    record(3, f"fast-forward matches naive loop at n = {n:,}", "PASS" if y == z else "FAIL")
    record(3, "matches closed form a^n·x + b(a^n−1)/(a−1)",
           "PASS" if closed_form(x0, a, b, n, m) == z else "FAIL")
    record(3, "timing", "PASS",
           f"loop {naive_dt:.2f} s vs fast {fast_dt * 1e6:.1f} µs — O(n) → O(log n); ratio grows with n")

    sm, sa, sb, sx = 10007, 5, 3, 1
    L = orbit_certificate(sx, sa, sb, sm)
    ok = L is not None and fast_forward(sx, sa, sb, L, sm) == sx
    record(3, f"orbit certificate (m={sm}) bounded by m", "PASS" if ok else "FAIL", f"cycle length {L}")


# ─────────────────────────────────────────────────────────────
# DOOR 4 — secp256k1 Validation (7 pure-Python tests + 1 library cross-check)
# ─────────────────────────────────────────────────────────────
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
G2 = (0xC6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5,
      0x1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A)


def on_curve(pt):
    if pt is None:
        return True
    x, y = pt
    return (y * y - x * x * x - 7) % P == 0


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def point_neg(pt):
    return None if pt is None else (pt[0], (-pt[1]) % P)


def scalar_mult(k, pt):
    """Double-and-add. NOT constant-time — fine for validation, not for secret keys."""
    result = None
    while k:
        if k & 1:
            result = point_add(result, pt)
        pt = point_add(pt, pt)
        k >>= 1
    return result


def compress(pt):
    x, y = pt
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def decompress(blob):
    if len(blob) != 33 or blob[0] not in (2, 3):
        raise ValueError("bad SEC1 prefix/length")
    x = int.from_bytes(blob[1:], "big")
    if x >= P:
        raise ValueError("x out of range")
    rhs = (pow(x, 3, P) + 7) % P
    y = pow(rhs, (P + 1) // 4, P)
    if y * y % P != rhs:
        raise ValueError("x not on curve")
    if (y & 1) != (blob[0] & 1):
        y = P - y
    return x, y


def door4():
    out("\nDOOR 4 — secp256k1 Validation (8 tests)")
    record(4, "1. generator G lies on y² = x³ + 7", "PASS" if on_curve(G) else "FAIL")
    record(4, "2. n·G = point at infinity", "PASS" if scalar_mult(N, G) is None else "FAIL")
    record(4, "3. 2·G matches published test vector", "PASS" if point_add(G, G) == G2 else "FAIL")

    a, b = secrets.randbelow(N - 1) + 1, secrets.randbelow(N - 1) + 1
    lhs = scalar_mult((a + b) % N, G)
    rhs = point_add(scalar_mult(a, G), scalar_mult(b, G))
    record(4, "4. (a+b)·G = a·G + b·G (random a, b)", "PASS" if lhs == rhs else "FAIL")

    Q = scalar_mult(a, G)
    record(4, "5. Q + (−Q) = infinity", "PASS" if point_add(Q, point_neg(Q)) is None else "FAIL")

    d = secrets.randbelow(N - 1) + 1
    pub = scalar_mult(d, G)
    ok = 1 <= d < N and pub is not None and on_curve(pub)
    record(4, "6. CSPRNG private key in [1, n−1], pubkey on curve", "PASS" if ok else "FAIL")

    round_trip = decompress(compress(pub)) == pub
    bad_x = next(x for x in range(1, 100) if pow((x ** 3 + 7) % P, (P - 1) // 2, P) != 1)
    try:
        decompress(b"\x02" + bad_x.to_bytes(32, "big"))
        rejected = False
    except ValueError:
        rejected = True
    record(4, "7. SEC1 compress round-trip + off-curve point rejected",
           "PASS" if round_trip and rejected else "FAIL")

    # S4 — the same math, checked against audited libraries
    door4_library_crosscheck()


# ─────────────────────────────────────────────────────────────
# DOOR 5 — Brian Local AI Health Check (Ollama, optional)
# ─────────────────────────────────────────────────────────────
def check_brian(host="127.0.0.1", port=11434, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError:
        return {"online": False}
    try:
        with urllib.request.urlopen(f"http://{host}:{port}/api/tags", timeout=timeout) as r:
            data = json.load(r)
        return {"online": True, "models": [m.get("name") for m in data.get("models", [])]}
    except Exception as e:
        return {"online": True, "models": [], "error": type(e).__name__}


def door5():
    out("\nDOOR 5 — Brian (local AI health check)")
    status = check_brian()
    if not status["online"]:
        record(5, "Ollama on localhost:11434", "SKIP", "offline — optional door, start Ollama to enable")
    else:
        models = ", ".join(status.get("models") or []) or "no models pulled"
        record(5, "Ollama on localhost:11434", "PASS", models)


# ─────────────────────────────────────────────────────────────
# DOOR 6 — RSA-2048 Proof of Concept
# ─────────────────────────────────────────────────────────────
_SMALL_PRIMES = [p for p in range(3, 2000) if all(p % q for q in range(2, int(p ** 0.5) + 1))]


def _is_probable_prime(n, rounds=40):
    if n < 2:
        return False
    if n < 5:
        return n in (2, 3)
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False
    d, s = n - 1, 0
    while d % 2 == 0:  # ct-ok: Miller–Rabin on a public candidate
        d //= 2
        s += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits, e=65537):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if c % e != 1 and _is_probable_prime(c):
            return c


def rsa_keygen(bits=2048, e=65537):
    while True:
        p, q = _random_prime(bits // 2, e), _random_prime(bits // 2, e)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = (p - 1) * (q - 1) // _gcd(p - 1, q - 1)
        if _gcd(e, lam) != 1:
            continue
        d = pow(e, -1, lam)
        return {"n": n, "e": e, "d": d, "p": p, "q": q,
                "dp": d % (p - 1), "dq": d % (q - 1), "qi": pow(q, -1, p)}


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


_SHA256_DIGESTINFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _emsa_pkcs1_v15(msg, k):
    t = _SHA256_DIGESTINFO + hashlib.sha256(msg).digest()
    return b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t


def rsa_sign(key, msg):
    k = (key["n"].bit_length() + 7) // 8
    m = int.from_bytes(_emsa_pkcs1_v15(msg, k), "big")
    # CRT signing
    s1, s2 = pow(m, key["dp"], key["p"]), pow(m, key["dq"], key["q"])
    h = key["qi"] * (s1 - s2) % key["p"]
    return (s2 + h * key["q"]).to_bytes(k, "big")


def rsa_verify(n, e, msg, sig):
    k = (n.bit_length() + 7) // 8
    if len(sig) != k:
        return False
    m = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    return hmac.compare_digest(m, _emsa_pkcs1_v15(msg, k))


def _pollard_rho(n):
    if n % 2 == 0:
        return 2
    while True:
        x = y = secrets.randbelow(n - 2) + 2
        c = secrets.randbelow(n - 1) + 1
        d = 1
        while d == 1:  # ct-ok: Pollard rho on a public toy modulus
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = _gcd(abs(x - y), n)
        if d != n:  # ct-ok: Pollard rho on a public toy modulus
            return d


def door6():
    out("\nDOOR 6 — RSA-2048 Proof of Concept")
    t0 = time.perf_counter()
    key = rsa_keygen(2048)
    record(6, "1. generate 2048-bit key (Miller–Rabin, 40 rounds)", "PASS",
           f"{time.perf_counter() - t0:.2f} s")
    n, e, d, p, q = key["n"], key["e"], key["d"], key["p"], key["q"]
    record(6, "2. n = p × q, exactly 2048 bits, p ≠ q",
           "PASS" if p * q == n and n.bit_length() == 2048 and p != q else "FAIL")
    lam = (p - 1) * (q - 1) // _gcd(p - 1, q - 1)
    record(6, "3. e·d ≡ 1 (mod λ(n))", "PASS" if e * d % lam == 1 else "FAIL")  # ct-ok: self-check of a fresh test key
    ok = key["dp"] == d % (p - 1) and key["dq"] == d % (q - 1) and key["qi"] * q % p == 1  # ct-ok: self-check of a fresh test key
    record(6, "4. CRT parameters dP, dQ, qInv consistent", "PASS" if ok else "FAIL")

    m = secrets.randbelow(n)
    record(6, "5. (m^e)^d ≡ m round-trip (textbook RSA — math check only)",
           "PASS" if pow(pow(m, e, n), d, n) == m else "FAIL")  # ct-ok: self-check of a fresh test key

    msg = b"ESDA Protocol - Paradox OS"
    sig = rsa_sign(key, msg)
    ok = rsa_verify(n, e, msg, sig) and not rsa_verify(n, e, msg + b"!", sig)
    record(6, "6. RSASSA-PKCS1-v1_5 / SHA-256 sign + verify, tampered message rejected",
           "PASS" if ok else "FAIL")

    toy_p, toy_q = _random_prime(32), _random_prime(32)
    t0 = time.perf_counter()
    f = _pollard_rho(toy_p * toy_q)
    dt = time.perf_counter() - t0
    record(6, "7. the wall: 64-bit toy modulus factors, 2048-bit does not",
           "PASS" if f in (toy_p, toy_q) else "FAIL",
           f"64-bit in {dt * 1000:.1f} ms · RSA-2048 ≈ 112-bit security (NIST SP 800-57)")

    # 8. Interop: ESDA signatures must be standard PKCS#1 v1.5 that OpenSSL accepts, both ways.
    door6_openssl_interop(key, msg, sig)

    # 9. S4 — the same signature from an audited library (pyca/cryptography)
    door6_library_crosscheck(key, msg, sig)


def _der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_int(x):
    b = x.to_bytes(x.bit_length() // 8 + 1, "big")  # leading 0x00 keeps it positive
    return b"\x02" + _der_len(len(b)) + b


def rsa_private_pem(key):
    """PKCS#1 RSAPrivateKey (RFC 8017 A.1.2) as PEM — standard library only."""
    import base64
    body = b"".join(_der_int(v) for v in (0, key["n"], key["e"], key["d"], key["p"], key["q"],
                                          key["dp"], key["dq"], key["qi"]))
    der = b"\x30" + _der_len(len(body)) + body
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN RSA PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END RSA PRIVATE KEY-----\n"


def _openssl_binaries():
    """Every distinct `openssl` CLI on this machine. On macOS /usr/bin/openssl is Apple's LibreSSL,
    so real OpenSSL (Homebrew) is looked up explicitly; each is labelled by what it reports itself as."""
    import shutil, subprocess
    cands = [shutil.which("openssl"), "/opt/homebrew/opt/openssl@3/bin/openssl", "/opt/homebrew/bin/openssl",
             "/usr/local/opt/openssl@3/bin/openssl", "/usr/local/bin/openssl", "/usr/bin/openssl"]
    seen, found = set(), []
    for c in cands:
        if not c or not os.path.isfile(c) or not os.access(c, os.X_OK):
            continue
        real = os.path.realpath(c)
        if real in seen:
            continue
        seen.add(real)
        try:
            ver = subprocess.run([c, "version"], capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            continue
        if ver:
            found.append((c, ver))
    found.sort(key=lambda t: 0 if t[1].startswith("OpenSSL") else 1)  # real OpenSSL first
    return found


def door6_openssl_interop(key, msg, sig):
    bins = _openssl_binaries()
    if not bins:
        record(6, "8. OpenSSL/LibreSSL interop", "SKIP", "no openssl CLI found")
        return
    has_openssl = any(v.startswith("OpenSSL") for _, v in bins)
    for i, (exe, ver) in enumerate(bins):
        lib = ver.split()[0]  # "OpenSSL" or "LibreSSL" — as the binary reports itself
        _interop_one(key, msg, sig, exe, ver,
                     f"8{'abcdefgh'[i]}. {lib} interop: ESDA sig verifies in {lib}, {lib} sig verifies in ESDA")
    if not has_openssl:
        record(6, "8z. real OpenSSL interop", "SKIP",
               "only LibreSSL found — install real OpenSSL with: brew install openssl@3")


def _interop_one(key, msg, sig, exe, ver, name):
    import shutil, subprocess, tempfile
    tmp = tempfile.mkdtemp(prefix="esda-rsa-")  # throwaway test key only, deleted below
    try:
        kp, pp, mp = (os.path.join(tmp, f) for f in ("k.pem", "pub.pem", "m.bin"))
        sp, op = os.path.join(tmp, "esda.sig"), os.path.join(tmp, "ossl.sig")
        fd = os.open(kp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, rsa_private_pem(key).encode()); os.close(fd)
        open(mp, "wb").write(msg); open(sp, "wb").write(sig)
        run = lambda *a: subprocess.run([exe, *a], capture_output=True, text=True)
        r0 = run("rsa", "-in", kp, "-check", "-noout")
        r1 = run("rsa", "-in", kp, "-pubout", "-out", pp)
        r2 = run("dgst", "-sha256", "-verify", pp, "-signature", sp, mp)
        r3 = run("dgst", "-sha256", "-sign", kp, "-out", op, mp)
        ossl = open(op, "rb").read() if r3.returncode == 0 else b""
        a = r0.returncode == 0 and r1.returncode == 0          # key DER accepted + consistent
        b = r2.returncode == 0 and "Verified OK" in r2.stdout  # ESDA -> OpenSSL
        c = bool(ossl) and rsa_verify(key["n"], key["e"], msg, ossl)  # OpenSSL -> ESDA
        d = ossl == sig  # RSASSA-PKCS1-v1_5 is deterministic: same key + msg must give the same bytes
        lib = ver.split()[0]
        record(6, name, "PASS" if (a and b and c and d) else "FAIL",
               f"{ver} ({exe}) · key check {'ok' if a else 'FAIL'} · ESDA→{lib} {'ok' if b else 'FAIL'}"
               f" · {lib}→ESDA {'ok' if c else 'FAIL'}"
               f" · signature bytes identical {'yes' if d else 'NO'} (PKCS#1 v1.5 is deterministic)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ─────────────────────────────────────────────────────────────
# DOOR 7 — SHA-256 Proof of Concept (independent implementation)
# ─────────────────────────────────────────────────────────────
_K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
_H256 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def sha256_pure(msg: bytes) -> bytes:
    """FIPS 180-4 SHA-256 written from the spec — for cross-checking hashlib."""
    M = 0xFFFFFFFF
    rotr = lambda x, r: ((x >> r) | (x << (32 - r))) & M
    ml = len(msg) * 8
    msg = msg + b"\x80" + b"\x00" * ((55 - len(msg)) % 64) + ml.to_bytes(8, "big")
    h = list(_H256)
    for off in range(0, len(msg), 64):
        w = [int.from_bytes(msg[off + 4 * i: off + 4 * i + 4], "big") for i in range(16)]
        for i in range(16, 64):
            s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & M)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
            ch = (e & f) ^ (~e & g)
            t1 = (hh + S1 + ch + _K256[i] + w[i]) & M
            S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = (S0 + maj) & M
            a, b, c, d, e, f, g, hh = (t1 + t2) & M, a, b, c, (d + t1) & M, e, f, g
        h = [(x + y) & M for x, y in zip(h, [a, b, c, d, e, f, g, hh])]
    return b"".join(x.to_bytes(4, "big") for x in h)


def door7():
    out("\nDOOR 7 — SHA-256 Proof of Concept")
    vectors = [
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "empty string"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", '"abc"'),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", "448-bit two-block"),
    ]
    ok = all(sha256_pure(m).hex() == h and hashlib.sha256(m).hexdigest() == h for m, h, _ in vectors)  # ct-ok: public NIST vectors
    record(7, "1–3. NIST FIPS 180-4 vectors (empty, abc, two-block)", "PASS" if ok else "FAIL",
           "pure-Python and hashlib both match")

    ok = hashlib.sha256(b"a" * 1_000_000).hexdigest() == \
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"  # ct-ok: public NIST vector
    record(7, "4. one million 'a' vector", "PASS" if ok else "FAIL")

    rnd_ok = all(sha256_pure(b) == hashlib.sha256(b).digest()  # ct-ok: public random test inputs
                 for b in (secrets.token_bytes(secrets.randbelow(300)) for _ in range(200)))
    record(7, "5. independent implementation = hashlib on 200 random inputs", "PASS" if rnd_ok else "FAIL")

    trials, total = 200, 0
    for _ in range(trials):
        x = bytearray(secrets.token_bytes(32))
        h1 = int.from_bytes(hashlib.sha256(x).digest(), "big")
        bit = secrets.randbelow(256)
        x[bit // 8] ^= 1 << (bit % 8)
        h2 = int.from_bytes(hashlib.sha256(x).digest(), "big")
        total += bin(h1 ^ h2).count("1")
    avg = total / trials
    record(7, "6. avalanche: 1 input bit flips ≈ 128 of 256 output bits",
           "PASS" if 120 <= avg <= 136 else "FAIL", f"average {avg:.1f}")

    count, t0 = 0, time.perf_counter()
    while time.perf_counter() - t0 < 1.0:
        for i in range(10000):
            hashlib.sha256(i.to_bytes(8, "big")).digest()
        count += 10000
    rate = count / (time.perf_counter() - t0)
    year = 3600 * 24 * 365.25
    years_128 = 2 ** 128 / rate / year
    years_256 = 2 ** 256 / rate / year
    record(7, "7. the wall: brute-force cost at this machine's measured rate", "PASS",
           f"{rate:,.0f} H/s → 2^128 ≈ {years_128:.1e} yrs, 2^256 preimage ≈ {years_256:.1e} yrs")


# ─────────────────────────────────────────────────────────────
def main():
    started = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    out("=" * 62)
    out(f" ESDA PROTOCOL — {VERSION}")
    out(" Paradox OS · Branden Duffield")
    out(f" {started} · Python {platform.python_version()} · {platform.system()} {platform.machine()}")
    out("=" * 62)

    for door in (door1, door2, door3, door4, door5, door6, door7):
        try:
            door()
        except Exception as e:
            record(door.__name__[-1], f"{door.__name__} crashed", "FAIL", f"{type(e).__name__}: {e}")

    passed = sum(r["status"] == "PASS" for r in RESULTS)
    failed = sum(r["status"] == "FAIL" for r in RESULTS)
    skipped = sum(r["status"] == "SKIP" for r in RESULTS)
    out("\n" + "=" * 62)
    out(f" RESULT: {passed} passed · {failed} failed · {skipped} skipped")
    out(" Boundary: 2^128. SHA-256 and secp256k1 are not broken here.")
    out(" Not independently audited. Not constant-time.")
    out(f" {VOW}")
    out("=" * 62)

    here = os.path.dirname(os.path.abspath(__file__))
    if os.environ.get("ESDA_OUT"):
        here = os.environ["ESDA_OUT"]
    elif "site-packages" in here or "dist-packages" in here:
        here = os.getcwd()  # installed with pip: write results where the user ran `esda`
    with open(os.path.join(here, "esda_output.txt"), "w") as f:
        f.write("\n".join(LOG) + "\n")
    with open(os.path.join(here, "esda_results.json"), "w") as f:
        json.dump({"version": VERSION, "run_at": started, "results": RESULTS}, f, indent=2)

    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--wal-writer":
        _wal_writer(sys.argv[2])
        sys.exit(0)
    main()
