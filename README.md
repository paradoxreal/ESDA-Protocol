# ESDA Protocol

**Engine · Shamir · Data · Algorithm** — a local-first cryptography workbench.
By Branden Duffield · Paradox OS · Era 2, v1.1.0

One Python file, standard library only, no network required. It runs 41 tests across seven doors and prints exactly what passed. (Door 6's interop check runs once for each OpenSSL or LibreSSL it finds, so a Mac with Homebrew OpenSSL shows 43.) Optional cross-checks compare ESDA's math against audited libraries when `cryptography` and `coincurve` are installed.

> Research and teaching code. Not independently audited. Not constant-time. Do not use it to protect real funds or real keys.

## Run it (macOS Terminal)

```
cd ESDA_Protocol
chmod +x run.sh
./run.sh
```

Results print to the screen and are saved to `esda_output.txt` and `esda_results.json`, then the genesis proof (below) runs and saves `genesis_output.txt` and `genesis_results.json`. The run exits non-zero if any test fails.

Or install it as a command (Python 3.9+):

```
pip install .                  # from this folder
pip install ".[crosscheck]"    # also installs cryptography + coincurve
esda                           # results are saved in the folder you run it from
```

Options: `ESDA_BLOCKS=20000` for a quick run (default 1,000,000), `ESDA_REQUIRE_CROSSCHECK=1` to fail instead of skip when the audited libraries are missing, `ESDA_OUT=<dir>` to choose where results go.

## The seven doors

| Door | Name | What it proves |
|---|---|---|
| 1 | Guardian Lock | Shamir secret sharing over GF(257): any 3 of 5 shares rebuild a 32-byte secret; 2 shares don't. |
| 2 | Hash-Chained Ledger | 1,000,000 SHA-256-chained blocks. One flipped byte is caught. A full rewrite is caught only by an anchored head hash, so publish it. Merkle inclusion proofs (RFC 6962 leaf/node prefixes) prove one block with 20 hashes instead of the whole chain. An on-disk SQLite WAL ledger is killed with `kill -9` mid-write and must reopen at exactly its last commit. |
| 3 | Observer-Quotient | Affine fast-forward of T(x) = ax + b mod m in O(log n) instead of O(n), checked against the naive loop and the closed form. |
| 4 | secp256k1 | Seven checks: generator on curve, n·G = ∞, 2·G test vector, additivity, negation, key range, SEC1 round-trip with off-curve rejection. Plus an optional cross-check: ESDA's public keys must match OpenSSL (via `cryptography`) and libsecp256k1 (via `coincurve`) byte for byte. |
| 5 | Brian | Optional health check for a local Ollama model on port 11434. Skipped if it's off. |
| 6 | RSA-2048 PoC | Key generation, n = p·q, e·d ≡ 1 mod λ(n), CRT parameters, PKCS#1 v1.5 SHA-256 sign/verify with tamper rejection, the wall (a 64-bit toy modulus falls in milliseconds; 2048-bit is ~112-bit security), interop with every OpenSSL/LibreSSL CLI found, and an optional cross-check that `cryptography` signs with ESDA's key and produces identical bytes. |
| 7 | SHA-256 PoC | A from-scratch FIPS 180-4 implementation that matches `hashlib` on NIST vectors and 200 random inputs, an avalanche test, and the measured cost of brute force on your own machine. |

## Companion check: genesis proof

`tools/genesis_proof.py` rebuilds the mainnet genesis block of seven chains from their raw fields and proves each one hashes to its published genesis hash. It is not a door and doesn't count toward the 41 tests. `run.sh` and CI run it after the doors.

| Chain | Rebuilt and checked |
|---|---|
| Bitcoin | Coinbase tx, merkle root, block hash, SHA-256d proof of work |
| Litecoin, Dogecoin | Same, with scrypt proof of work |
| Dash | Same, with X11 hash and proof of work |
| Zcash | Coinbase tx, merkle root, block hash, full Equihash(200,9) check of the 1,344-byte solution |
| Ethereum | State root rebuilt from all 8,893 genesis accounts (Merkle Patricia trie), RLP header, Keccak-256 block hash |
| Monero | CryptoNote block hashing blob, Keccak-256 block hash (Monero checks no proof of work on its genesis block) |

Inputs are copied from each project's own source (`chainparams.cpp`, go-ethereum `core/genesis.go`, Monero `cryptonote_config.h`); every hash is recomputed, and Keccak is written from scratch. `tools/eth_mainnet_alloc.rlp` is go-ethereum's genesis allocation, bundled so no network is needed. Altered data can't pass, because the rebuilt state root must match the header.

Standard library only, except Dash: X11 needs `dash_hash` (Dash's own package). Without it Dash is skipped, never passed; `ESDA_REQUIRE_X11=1` turns that skip into a failure. Homebrew Python blocks global installs, so use a venv: `python3 -m venv ~/.venvs/esda-genesis && ~/.venvs/esda-genesis/bin/pip install dash_hash`. `run.sh` uses that venv automatically, or set `ESDA_GENESIS_PY` to another interpreter.

Reference run on the M2 (macOS arm64, Python 3.15): 7 of 7 chains proven, about 7 seconds.

## Honest boundaries

- The wall is 2^128. Nothing here breaks SHA-256, RSA-2048 or secp256k1, and nothing here claims to.
- The Door 3 speedup is ordinary fast exponentiation, not new math. The number 956 has no special role.
- The hash chain is tamper-evident only when its head hash is stored somewhere an attacker can't reach.

## Security reports

Use GitHub's private vulnerability reporting on this repo. Questions go in Issues or Discussions.

## Sample run

See `esda_output.txt`. Reference run on the M2 (macOS arm64, Python 3.15): 43 passed, 0 failed, 0 skipped. Without Ollama running, Door 5 shows as skipped.

`tools/audit_secret_compares.py` flags any `==` on secret-looking values that isn't marked as reviewed. CI runs it on every push.
---

## Mission Plan — Paradox OS Security & Internet Development

### Security track

| Phase | Work | Done when |
|---|---|---|
| S1 — Now | Keep every test green on every change. Turn on GitHub private vulnerability reporting. Sign commits. | CI badge green, reporting enabled |
| S2 — Moves 5–10 | Merkle proofs for the ledger so one entry can be proven without sharing the whole chain. Audit every secret comparison for `hmac.compare_digest`. | Merkle inclusion test passes; no `==` on secrets |
| S3 — Moves 11–15 | WAL persistence for the ledger (SQLite `journal_mode=WAL`) with crash-recovery tests. Publish each day's head hash somewhere public so a full rewrite can't hide. | Kill-mid-write test recovers cleanly; head log public |
| S4 — Hardening | Swap the teaching code for audited libraries anywhere real keys are touched: `cryptography` for RSA, `libsecp256k1` (via `coincurve`) for ECC. Keep the pure-Python versions as the cross-check suite. | Both paths agree on every test vector |
| S5 — Review | Ask for outside review (r/crypto, a university lab, or a paid audit when funding exists). Publish findings and fixes in CHRONICLE. | Written review on file |

Rules that don't change: never claim to break SHA-256, RSA-2048 or secp256k1; never hold other people's keys or funds; never ship pure-Python crypto as a production key handler.

### Internet development track

| Phase | Work | Done when |
|---|---|---|
| I1 — Home | GitHub organization `paradoxreal`, repo `ESDA-Protocol`, MIT or Apache-2.0 license, README with real `esda_output.txt` from the M2. | Repo public |
| I2 — CI | GitHub Actions running `./run.sh` on macOS and Linux for every push. | Green on both |
| I3 — Site | A plain GitHub Pages site for Paradox OS explaining the three human tools: Split-Key Vault, Tamper-Proof Diary, Offline Brain. | Site live |
| I4 — Launch | Honest posts to r/cryptography, r/privacy and Hacker News. Answer questions in the repo's Issues and Discussions. | First outside issue answered |
| I5 — Package | `pip install esda-protocol` with a `esda` command. | Installs clean on a fresh Mac |
| I6 — Grow | Toward the goal of 100–1,000 users: tutorials, a Paradox OS app wrapper, and Brian (Door 5) answering questions over the local ledger. | 100 GitHub stars / users |

### Canadian law check

The workbench runs offline and collects no data, so privacy law (PIPEDA) doesn't apply to the tool itself. That changes if the site ever adds accounts, analytics or a mailing list. Anything involving selling tokens or holding crypto for others falls under securities and FINTRAC rules; get a lawyer's review before going there. Not legal advice.

*Branden Duffield · Paradox OS · ENCRYPTION NEVER DIES. IT ONLY GETS STRONGER.*
