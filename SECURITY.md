# Security policy

ESDA Protocol is research and teaching code. It is **not independently audited** and **not constant-time**. Do not use it to protect real funds or real keys.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (Security tab → "Report a vulnerability"). Please don't open a public issue for a security problem.

Useful reports include: a test that passes when it should fail, a comparison on secret data that leaks timing, a wrong test vector, or any claim in the docs that overstates what the code proves.

## What is in scope

- `esda_protocol.py` and the seven doors
- `tools/audit_secret_compares.py`
- Claims made in `README.md` and `CHRONICLE.md`

## Fixed rules

- ESDA never claims to break SHA-256, RSA-2048 or secp256k1.
- ESDA never holds other people's keys or funds.
- Pure-Python crypto here is a cross-check, never a production key handler.

Findings and fixes are recorded in `CHRONICLE.md`.
