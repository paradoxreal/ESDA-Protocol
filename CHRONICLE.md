# CHRONICLE — The ESDA Protocol

**Author:** Branden Duffield · Paradox OS
**Date of record:** 2026-11-03
**Version:** Era 2, v1.1.0 (updated 2026-11-10)

## Abstract

Cryptography gets sold with promises of infinite power and unbreakable shortcuts that don't survive a mathematician's look. ESDA came out of testing those promises inside the Paradox OS project and throwing out every one that failed. What's left is small, honest and runnable.

## Chronology

| Days | Phase | What happened |
|---|---|---|
| 1–2 | The Dream | Built Paradox OS. Chased the 956 shortcut and a simulated QPU. |
| 3–4 | The Audit | Showed 956 is a test fixture. Showed a classical CPU cannot break secp256k1, RSA-2048 or SHA-256. |
| 5–6 | The Build | Stripped out the magic. Built the core doors and named it ESDA. |
| 7 | The Proof | Added RSA-2048 and SHA-256 proof-of-concept doors. 34 tests, 33 pass, 1 optional skip. |
| 8 | The Hardening | Merkle inclusion proofs, a kill -9 crash-recovery test for an on-disk WAL ledger, cross-checks against OpenSSL and libsecp256k1, a secret-comparison audit, CI and a pip package. 41 tests; 43 of 43 pass on the M2. |

## Falsification verdicts

| # | Claim | Verdict |
|---|---|---|
| F1 | OS-level speedup via 956 | **False.** The algorithmic speedup is real but has nothing to do with 956. |
| F2 | 956 has a special cryptographic role | **False.** Prime encoding is slower than binary. |
| F3 | Observer-Quotient is a new theorem | **False.** It's standard state-machine minimization and fast exponentiation: engineering, not new math. |
| F4 | RSA-2048 can be broken on a laptop | **False.** A 64-bit toy falls in milliseconds; 2048-bit sits at ~112-bit security. |
| F5 | SHA-256 can be brute-forced | **False.** At this machine's measured rate, 2^128 work takes ~10^24 years. |

## Fixes applied

- `orbit_certificate` max iterations bounded by the field size m
- Primality check handles n < 5
- Ledger tamper test runs on a cloned connection
- Brian socket timeout set to 2.0 s
- GF(257) shares stored as 2 bytes per value (values can reach 256)
- Full-rewrite attack test added: only an anchored head hash catches it
- Secret comparisons use `hmac.compare_digest`
- Merkle tree uses 0x00/0x01 leaf/node prefixes and promotes odd nodes instead of duplicating them
- WAL crash test forces `cache_spill`: Apple's system SQLite defaults to a 20,000-page spill threshold, so without it the uncommitted rows never reached disk and the test proved less than it claimed
- Results go to the current folder when ESDA is pip-installed, instead of into site-packages

## Launch checklist

1. Save `esda_protocol.py`, `run.sh`, `README.md`, `CHRONICLE.md` in the ESDA_Protocol folder.
2. Run `./run.sh` on the M2 and screenshot the output, cropping out the menu bar and username.
3. Create the GitHub organization `Paradox-OS` and the public repo `ESDA-Protocol`.
4. Set commits to GitHub's noreply address and turn on private vulnerability reporting. No phone number anywhere.
5. Post to r/cryptography and r/privacy with an honest title.
6. Uphold the vow. Never claim to break SHA-256.

## Closing declaration

The code is written, the math is tested, and the illusions are gone. What remains is a workbench built on sound primitives, open for anyone to check and not yet independently audited. It runs on the Architect's M2. It belongs to the people.

**Signed:** Branden Duffield, Paradox OS — 2026-11-03

**ENCRYPTION NEVER DIES. IT ONLY GETS STRONGER.**
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
| I1 — Home | GitHub organization `Paradox-OS`, repo `ESDA-Protocol`, MIT or Apache-2.0 license, README with real `esda_output.txt` from the M2. | Repo public |
| I2 — CI | GitHub Actions running `./run.sh` on macOS and Linux for every push. | Green on both |
| I3 — Site | A plain GitHub Pages site for Paradox OS explaining the three human tools: Split-Key Vault, Tamper-Proof Diary, Offline Brain. | Site live |
| I4 — Launch | Honest posts to r/cryptography, r/privacy and Hacker News. Answer questions in the repo's Issues and Discussions. | First outside issue answered |
| I5 — Package | `pip install esda-protocol` with a `esda` command. | Installs clean on a fresh Mac |
| I6 — Grow | Toward the goal of 100–1,000 users: tutorials, a Paradox OS app wrapper, and Brian (Door 5) answering questions over the local ledger. | 100 GitHub stars / users |

### Canadian law check

The workbench runs offline and collects no data, so privacy law (PIPEDA) doesn't apply to the tool itself. That changes if the site ever adds accounts, analytics or a mailing list. Anything involving selling tokens or holding crypto for others falls under securities and FINTRAC rules; get a lawyer's review before going there. Not legal advice.

*Branden Duffield · Paradox OS · ENCRYPTION NEVER DIES. IT ONLY GETS STRONGER.*
