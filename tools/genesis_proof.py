#!/usr/bin/env python3
"""
genesis_proof.py - rebuild 7 mainnet genesis blocks from their raw fields and
prove each one hashes to the published genesis hash. All chains, one run.

    python3 genesis_proof.py            # run every chain
    python3 genesis_proof.py --json     # machine-readable result
    python3 genesis_proof.py btc eth    # only some chains
    python3 genesis_proof.py --json-out genesis_results.json   # text + JSON file

Exit code: 1 if any chain FAILs or ERRORs; a SKIP (Dash without X11) does
not fail the run unless ESDA_REQUIRE_X11=1 is set, matching ESDA's doors.

Nothing is taken on trust except the raw inputs, copied from each project's
own source code (file named next to each chain below). Every hash, merkle
root, state root and proof-of-work check is recomputed here.

Dependencies: Python 3.8+ standard library. Dash's block hash is X11, which
is not in the standard library: `pip install dash_hash` (Dash's own package;
the older x11_hash also works on Python < 3.10). If neither works, Dash is
reported as SKIPPED, never as passed.

Ethereum's state root is rebuilt from the 8,893-account genesis allocation in
go-ethereum's core/genesis_alloc.go. The script reads ./eth_mainnet_alloc.rlp
(that allocation's raw bytes, shipped alongside) or ./genesis_alloc.go; only if
neither is present does it download genesis_alloc.go once from GitHub.
"""
import hashlib, json, os, struct, sys, urllib.request

# --------------------------------------------------------------------------
# Expected genesis hashes (the table being proven)
# --------------------------------------------------------------------------
EXPECTED = {
    "btc":  "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "ltc":  "12a765e31ffd4059bada1e25190f6e98c99d9714d334efa41a195a7e7e04bfe2",
    "doge": "1a91e3dace36e2be3bf030a65679fe821aa1d6ef92e7c9902eb318182c355691",
    "eth":  "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
    "dash": "00000ffd590b1485b3caadc19b22e6379c733355108f107a430458cdf3407ab6",
    "xmr":  "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3",
    "zec":  "00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08",
}
NAMES = {"btc": "Bitcoin", "ltc": "Litecoin", "doge": "Dogecoin", "eth": "Ethereum",
         "dash": "Dash", "xmr": "Monero", "zec": "Zcash"}

# --------------------------------------------------------------------------
# Primitives
# --------------------------------------------------------------------------
def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def rev_hex(b):            # bitcoin-family display order (byte-reversed)
    return b[::-1].hex()

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1

def _keccak_f(A):
    for rc in _RC:
        C = [A[x][0] ^ A[x][1] ^ A[x][2] ^ A[x][3] ^ A[x][4] for x in range(5)]
        D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        A = [[A[x][y] ^ D[x] for y in range(5)] for x in range(5)]
        B = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                v = A[x][y]
                B[y][(2 * x + 3 * y) % 5] = ((v << r) | (v >> (64 - r))) & _M if r else v
        A = [[B[x][y] ^ ((~B[(x + 1) % 5][y]) & B[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        A[0][0] ^= rc
    return A

def keccak256(data):
    """Original Keccak-256 (0x01 padding) - used by Ethereum and Monero.
    NOT the same as hashlib.sha3_256 (0x06 padding)."""
    rate = 136
    q = rate - len(data) % rate
    p = bytearray(data) + (b"\x81" if q == 1 else b"\x01" + b"\x00" * (q - 2) + b"\x80")
    A = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        blk = p[off:off + rate]
        for i in range(rate // 8):
            A[i % 5][i // 5] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        A = _keccak_f(A)
    out = b"".join(A[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out

def bits_to_target(bits):
    exp, mant = bits >> 24, bits & 0xFFFFFF
    return mant * (1 << (8 * (exp - 3)))

# --------------------------------------------------------------------------
# Bitcoin-family block construction (BTC, LTC, DOGE, DASH, ZEC all share it)
# --------------------------------------------------------------------------
def push(data):
    n = len(data)
    if n < 0x4C:   return bytes([n]) + data
    if n <= 0xFF:  return b"\x4c" + bytes([n]) + data
    return b"\x4d" + struct.pack("<H", n) + data

def script_num(v):          # CScript() << int64  (minimal little-endian, sign bit)
    out = bytearray()
    while v:
        out.append(v & 0xFF); v >>= 8
    if out and out[-1] & 0x80:
        out.append(0)
    return bytes(out)

def varint(n):              # bitcoin CompactSize
    if n < 0xFD:     return bytes([n])
    if n <= 0xFFFF:  return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)

def coinbase_tx(bits_push, timestamp, pubkey_hex, reward_sats):
    script_sig = push(script_num(bits_push)) + push(script_num(4)) + push(timestamp.encode("utf-8"))
    spk = push(bytes.fromhex(pubkey_hex)) + b"\xac"          # <pubkey> OP_CHECKSIG
    return (struct.pack("<i", 1) + b"\x01" + b"\x00" * 32 + b"\xff\xff\xff\xff"
            + varint(len(script_sig)) + script_sig + b"\xff\xff\xff\xff"
            + b"\x01" + struct.pack("<q", reward_sats) + varint(len(spk)) + spk
            + b"\x00\x00\x00\x00")

COIN = 100_000_000
SATOSHI_KEY = ("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61de"
               "b649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f")
LTC_KEY = ("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb"
           "4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9")

def btc_family(cfg, pow_fn=None, pow_name=None, hash_fn=sha256d):
    tx = coinbase_tx(cfg["push"], cfg["msg"], cfg["key"], cfg["reward"])
    merkle = sha256d(tx)                   # one tx: merkle root == txid
    header = (struct.pack("<i", cfg["ver"]) + b"\x00" * 32 + merkle
              + struct.pack("<III", cfg["time"], cfg["bits"], cfg["nonce"]))
    h = hash_fn(header)
    target = bits_to_target(cfg["bits"])
    checks = [("merkle root", rev_hex(merkle), cfg["merkle"]),
              ("block hash", rev_hex(h), cfg["expect"])]
    pw = (pow_fn or hash_fn)(header)
    checks.append(((pow_name or "PoW") + " <= target",
                   int.from_bytes(pw, "little") <= target, True))
    return checks, {"header_hex": header.hex(), "coinbase_tx_hex": tx.hex(),
                    "pow_hash": rev_hex(pw), "target": "%064x" % target}

# Inputs below: <repo> src/chainparams.cpp (bitcoin: src/kernel/chainparams.cpp)
def chain_btc():
    return btc_family(dict(push=486604799, key=SATOSHI_KEY, reward=50 * COIN, ver=1,
        msg="The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
        time=1231006505, nonce=2083236893, bits=0x1d00ffff,
        merkle="4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
        expect=EXPECTED["btc"]), pow_name="sha256d")

def _scrypt(h):
    return hashlib.scrypt(h, salt=h, n=1024, r=1, p=1, dklen=32)

def chain_ltc():
    return btc_family(dict(push=486604799, key=LTC_KEY, reward=50 * COIN, ver=1,
        msg="NY Times 05/Oct/2011 Steve Jobs, Apple’s Visionary, Dies at 56",
        time=1317972665, nonce=2084524493, bits=0x1e0ffff0,
        merkle="97ddfbbae6be97fd6cdf3e7ca13232a3afff2353e29badfab7f73011edd4ced9",
        expect=EXPECTED["ltc"]), pow_fn=_scrypt, pow_name="scrypt")

def chain_doge():
    return btc_family(dict(push=486604799, key=LTC_KEY, reward=88 * COIN, ver=1,
        msg="Nintondo", time=1386325540, nonce=99943, bits=0x1e0ffff0,
        merkle="5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69",
        expect=EXPECTED["doge"]), pow_fn=_scrypt, pow_name="scrypt")

def chain_dash():
    x11 = None
    for mod in ("dash_hash", "x11_hash"):      # dash_hash = Dash's own package
        try:
            x11 = __import__(mod).getPoWHash
            x11(b"\x00" * 80)                  # old x11_hash builds fail on Py3.10+
            break
        except Exception:
            x11 = None
    if x11 is None:
        raise SkipChain("X11 not available - run: pip install dash_hash")
    return btc_family(dict(push=486604799, key=LTC_KEY, reward=50 * COIN, ver=1,
        msg="Wired 09/Jan/2014 The Grand Experiment Goes Live: Overstock.com Is Now Accepting Bitcoins",
        time=1390095618, nonce=28917698, bits=0x1e0ffff0,
        merkle="e0028eb9648db56b1ac77cf090b99048a8007e2bb64b68f092c03c7f56a662c7",
        expect=EXPECTED["dash"]), hash_fn=x11, pow_name="X11")

# --------------------------------------------------------------------------
# Zcash: bitcoin-style coinbase + 140-byte Equihash input + 1344-byte solution
# Input: zcash/zcash src/chainparams.cpp (CMainParams)
# --------------------------------------------------------------------------
ZEC_SOLUTION = (
"000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed045fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf6058343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398bca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a570215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc5422816655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec109d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7bb8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567affff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719bac64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07fa0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a599c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec06ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63fef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9fcc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b6602b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd861b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc09b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1aec01c4a68e41ce157")

def equihash_verify(n, k, base, solution):
    """Full Equihash(n,k) solution check, as in zcash src/crypto/equihash.cpp."""
    cbl = n // (k + 1)                       # collision bit length (20)
    ilen = cbl + 1                           # index bit length (21)
    nidx = 1 << k                            # 512 indices
    if len(solution) * 8 != nidx * ilen:
        return False, "bad solution length"
    bits = int.from_bytes(solution, "big")
    total = len(solution) * 8
    idx = [(bits >> (total - ilen * (i + 1))) & ((1 << ilen) - 1) for i in range(nidx)]
    per = 512 // n                           # hash outputs per blake2b call (2)
    nbytes = n // 8
    person = b"ZcashPoW" + struct.pack("<II", n, k)
    def leaf(i):
        h = hashlib.blake2b(base + struct.pack("<I", i // per),
                            digest_size=per * nbytes, person=person).digest()
        o = (i % per) * nbytes
        return int.from_bytes(h[o:o + nbytes], "big")
    level = [(leaf(i), [i]) for i in idx]
    for r in range(1, k + 1):
        nxt = []
        for a, b in zip(level[0::2], level[1::2]):
            if a[1][0] >= b[1][0]:
                return False, "index order violated at round %d" % r
            if set(a[1]) & set(b[1]):
                return False, "duplicate index at round %d" % r
            x = a[0] ^ b[0]
            zero_bits = n if r == k else cbl * r
            if x >> (n - zero_bits):
                return False, "collision failed at round %d" % r
            nxt.append((x, a[1] + b[1]))
        level = nxt
    return True, "%d indices, %d rounds, final XOR = 0" % (nidx, k)

def chain_zec():
    tx = coinbase_tx(520617983, "Zcash0b9c4eef8b7cc417ee5001e3500984b6fea35683a7cac141a043c42064835d34",
                     SATOSHI_KEY, 0)
    merkle = sha256d(tx)
    nonce = (0x1257).to_bytes(32, "little")
    bits, time_ = 0x1f07ffff, 1477641360
    base = (struct.pack("<i", 4) + b"\x00" * 32 + merkle + b"\x00" * 32   # hashFinalSaplingRoot
            + struct.pack("<II", time_, bits))
    sol = bytes.fromhex(ZEC_SOLUTION)
    header = base + nonce + varint(len(sol)) + sol
    h = sha256d(header)
    ok, why = equihash_verify(200, 9, base + nonce, sol)
    checks = [("merkle root", rev_hex(merkle),
               "c4eaa58879081de3c24a7b117ed2b28300e7ec4c4c1dff1d3f1268b7857a4ddb"),
              ("block hash", rev_hex(h), EXPECTED["zec"]),
              ("sha256d <= target", int.from_bytes(h, "little") <= bits_to_target(bits), True),
              ("Equihash(200,9) solution valid", ok, True)]
    return checks, {"equihash": why, "solution_bytes": len(sol), "header_bytes": len(header)}

# --------------------------------------------------------------------------
# Ethereum: RLP header, Keccak-256, state root rebuilt from genesis allocation
# Inputs: go-ethereum core/genesis.go DefaultGenesisBlock, core/genesis_alloc.go
# --------------------------------------------------------------------------
def rlp(x):
    if isinstance(x, list):
        body = b"".join(rlp(i) for i in x)
        return _rlp_len(len(body), 0xC0) + body
    if isinstance(x, int):
        x = x.to_bytes((x.bit_length() + 7) // 8, "big") if x else b""
    if len(x) == 1 and x[0] < 0x80:
        return x
    return _rlp_len(len(x), 0x80) + x

def _rlp_len(n, off):
    if n < 56:
        return bytes([off + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(b)]) + b

def rlp_decode(b, i=0):
    p = b[i]
    if p < 0x80:  return b[i:i + 1], i + 1
    if p < 0xB8:  n = p - 0x80; return b[i + 1:i + 1 + n], i + 1 + n
    if p < 0xC0:
        ll = p - 0xB7; n = int.from_bytes(b[i + 1:i + 1 + ll], "big"); s = i + 1 + ll
        return b[s:s + n], s + n
    if p < 0xF8:  n = p - 0xC0; s = i + 1
    else:
        ll = p - 0xF7; n = int.from_bytes(b[i + 1:i + 1 + ll], "big"); s = i + 1 + ll
    out, j = [], s
    while j < s + n:
        item, j = rlp_decode(b, j); out.append(item)
    return out, s + n

def go_string_literal(raw):
    """Unquote a Go "..." string literal (bytes of the source) into bytes."""
    assert raw[:1] == b'"' and raw[-1:] == b'"'
    s, out, i = raw[1:-1], bytearray(), 0
    simple = {b"a": 7, b"b": 8, b"f": 12, b"n": 10, b"r": 13, b"t": 9, b"v": 11,
              b"\\": 92, b'"': 34, b"'": 39}
    while i < len(s):
        c = s[i:i + 1]
        if c != b"\\":
            out += c; i += 1; continue
        e = s[i + 1:i + 2]
        if e in simple:  out.append(simple[e]); i += 2
        elif e == b"x":  out.append(int(s[i + 2:i + 4], 16)); i += 4
        elif e == b"u":  out += chr(int(s[i + 2:i + 6], 16)).encode(); i += 6
        elif e == b"U":  out += chr(int(s[i + 2:i + 10], 16)).encode(); i += 10
        elif e in b"01234567": out.append(int(s[i + 1:i + 4], 8)); i += 4
        else: raise ValueError("bad escape %r" % e)
    return bytes(out)

ALLOC_URL = "https://raw.githubusercontent.com/ethereum/go-ethereum/master/core/genesis_alloc.go"

def load_mainnet_alloc():
    """Raw RLP of go-ethereum's mainnetAllocData. Looked for, in order:
    ./eth_mainnet_alloc.rlp (bundled, no network), ./genesis_alloc.go,
    then a one-time download of genesis_alloc.go from GitHub. Trust is not
    needed in any of them: the rebuilt state root must equal the one in the
    genesis header, so altered data fails the check."""
    here = os.path.dirname(os.path.abspath(__file__))
    rlp_path = os.path.join(here, "eth_mainnet_alloc.rlp")
    go_path = os.path.join(here, "genesis_alloc.go")
    if os.path.exists(rlp_path):
        with open(rlp_path, "rb") as f:
            data = f.read()
    else:
        if not os.path.exists(go_path):
            with urllib.request.urlopen(ALLOC_URL, timeout=60) as r, open(go_path, "wb") as f:
                f.write(r.read())
        with open(go_path, "rb") as f:
            for line in f:
                if line.startswith(b"const mainnetAllocData = "):
                    data = go_string_literal(line.split(b" = ", 1)[1].strip())
                    break
            else:
                raise RuntimeError("mainnetAllocData not found in " + go_path)
    items, _ = rlp_decode(data)
    alloc = []
    for it in items:
        if len(it) != 2:
            raise RuntimeError("mainnet alloc entry has code/storage - unexpected")
        alloc.append((it[0].rjust(20, b"\x00"), int.from_bytes(it[1], "big")))
    return alloc, hashlib.sha256(data).hexdigest()

def _hp(nibbles, leaf):
    flag = 2 if leaf else 0
    if len(nibbles) % 2:
        nibbles = [flag + 1] + nibbles
    else:
        nibbles = [flag, 0] + nibbles
    return bytes(nibbles[i] * 16 + nibbles[i + 1] for i in range(0, len(nibbles), 2))

def _trie(items):
    """items: sorted list of (nibble list, value bytes). Returns node as python list."""
    if len(items) == 1:
        k, v = items[0]
        return [_hp(k, True), v]
    pre = 0
    while all(len(k) > pre for k, _ in items) and len({k[pre] for k, _ in items}) == 1:
        pre += 1
    if pre:
        return [_hp(items[0][0][:pre], False), _ref(_trie([(k[pre:], v) for k, v in items]))]
    node, val = [b""] * 17, b""
    for d in range(16):
        sub = [(k[1:], v) for k, v in items if k and k[0] == d]
        if sub:
            node[d] = _ref(_trie(sub))
    for k, v in items:
        if not k:
            val = v
    node[16] = val
    return node

class _Raw(bytes):            # already-encoded child node embedded inline (<32 bytes)
    pass

def _enc(node):
    if isinstance(node, _Raw):
        return bytes(node)
    if isinstance(node, list):
        body = b"".join(_enc(i) for i in node)
        return _rlp_len(len(body), 0xC0) + body
    return rlp(node)

def _ref(node):
    e = _enc(node)
    return _Raw(e) if len(e) < 32 else keccak256(e)

def state_root(alloc):
    empty_root = keccak256(rlp(b""))
    empty_code = keccak256(b"")
    items = []
    for addr, bal in alloc:
        key = keccak256(addr)
        nib = [n for byte in key for n in (byte >> 4, byte & 15)]
        items.append((nib, rlp([0, bal, empty_root, empty_code])))
    items.sort()
    return keccak256(_enc(_trie(items)))

def chain_eth():
    empty_trie = keccak256(rlp(b""))
    ommers = keccak256(rlp([]))
    alloc, alloc_sha = load_mainnet_alloc()
    sroot = state_root(alloc)
    header = [b"\x00" * 32, ommers, b"\x00" * 20, sroot, empty_trie, empty_trie,
              b"\x00" * 256, 17179869184, 0, 5000, 0, 0,
              bytes.fromhex("11bbe8db4e347b4e8c937c1c8370e4b5ed33adb3db69cbdb7a38e1e50b1b82fa"),
              b"\x00" * 32, (66).to_bytes(8, "big")]
    h = keccak256(rlp(header))
    total = sum(b for _, b in alloc)
    checks = [("keccak self-test ('' -> c5d246...)", keccak256(b"").hex(),
               "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
              ("ommers hash", ommers.hex(),
               "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347"),
              ("empty tx/receipt root", empty_trie.hex(),
               "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"),
              ("state root (from %d accounts)" % len(alloc), sroot.hex(),
               "d7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544"),
              ("block hash", h.hex(), EXPECTED["eth"])]
    return checks, {"accounts": len(alloc), "total_wei": str(total),
                    "total_eth": "%.6f" % (total / 10**18), "alloc_rlp_sha256": alloc_sha}

# --------------------------------------------------------------------------
# Monero: CryptoNote block hashing blob, Keccak-256 ("cn_fast_hash")
# Input: monero-project/monero src/cryptonote_config.h (GENESIS_TX, GENESIS_NONCE)
# --------------------------------------------------------------------------
def leb128(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)

def chain_xmr():
    tx = bytes.fromhex("013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f"
                       "5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d"
                       "24a28e9d0bc890d1")
    tx_hash = keccak256(tx)                          # v1 tx: hash of whole blob
    merkle = tx_hash                                 # tree_hash of one hash = itself
    hdr = leb128(1) + leb128(0) + leb128(0) + b"\x00" * 32 + struct.pack("<I", 10000)
    blob = hdr + merkle + leb128(1)                  # + number of txs incl. miner tx
    h = keccak256(leb128(len(blob)) + blob)
    # decode the coinbase so the output is human-checkable
    unlock = tx[1]                                   # 0x3c = 60 blocks
    reward, j, sh = 0, 7, 0
    while True:
        b = tx[j]; reward |= (b & 0x7F) << sh; sh += 7; j += 1
        if not b & 0x80:
            break
    checks = [("keccak self-test", keccak256(b"").hex(),
               "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
              ("block hash", h.hex(), EXPECTED["xmr"])]
    return checks, {"miner_tx_hash": tx_hash.hex(), "hashing_blob": blob.hex(),
                    "unlock_time": unlock, "reward_atomic": reward,
                    "reward_xmr": "%.12f" % (reward / 10**12),
                    "note": "Monero does not check PoW on the genesis block; none is checked here"}

# --------------------------------------------------------------------------
class SkipChain(Exception):
    pass

CHAINS = [("btc", chain_btc), ("ltc", chain_ltc), ("doge", chain_doge), ("eth", chain_eth),
          ("dash", chain_dash), ("xmr", chain_xmr), ("zec", chain_zec)]

def main(argv):
    json_out = None
    if "--json-out" in argv:
        i = argv.index("--json-out")
        json_out = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    want = [a for a in argv if not a.startswith("-")]
    as_json = "--json" in argv
    results = []
    for key, fn in CHAINS:
        if want and key not in want:
            continue
        r = {"chain": NAMES[key], "id": key, "expected": EXPECTED[key]}
        try:
            checks, info = fn()
            r["checks"] = [{"name": n, "got": g, "want": w, "ok": g == w} for n, g, w in checks]
            r["info"] = info
            r["status"] = "PASS" if all(c["ok"] for c in r["checks"]) else "FAIL"
        except SkipChain as e:
            r["status"], r["reason"] = "SKIPPED", str(e)
        except Exception as e:
            r["status"], r["reason"] = "ERROR", "%s: %s" % (type(e).__name__, e)
        results.append(r)

    if as_json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print("\n[%s] %s" % (r["status"], r["chain"]))
            print("   expected  %s" % r["expected"])
            if "reason" in r:
                print("   reason    %s" % r["reason"])
            for c in r.get("checks", []):
                mark = "ok " if c["ok"] else "XX "
                got = c["got"] if isinstance(c["got"], str) else ("yes" if c["got"] else "no")
                print("   %s %-36s %s" % (mark, c["name"], got))
            for k, v in r.get("info", {}).items():
                if k.endswith("_hex") or k == "hashing_blob":
                    continue
                print("       %-20s %s" % (k, v))
        npass = sum(r["status"] == "PASS" for r in results)
        nskip = sum(r["status"] == "SKIPPED" for r in results)
        print("\n%d/%d chains proven." % (npass, len(results))
              + (" %d skipped." % nskip if nskip else ""))
    if json_out:
        with open(json_out, "w") as f:
            json.dump(results, f, indent=2)
    bad = {"FAIL", "ERROR"} | ({"SKIPPED"} if os.environ.get("ESDA_REQUIRE_X11") == "1" else set())
    return 1 if any(r["status"] in bad for r in results) else 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
