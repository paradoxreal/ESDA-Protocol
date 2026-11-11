# ESDA Protocol v1.1.0 — Bitcoin timestamp

| | |
|---|---|
| Release | git commit `800a1b0b6959a184cf647fa1f1aabf0daaeac8fe` (tree `a96833f66e39265203cbbd820b69edef2f382b29`) |
| Manifest | `ESDA_v1.1.0_MANIFEST.txt` — SHA-256 of all 18 tracked files at that commit |
| Manifest SHA-256 | `d4dbd50950d87ecac63fc8d8dc00b0ecee0ea6cfb5aff6433ba2d6edc41720fe` |
| Proof | `ESDA_v1.1.0_MANIFEST.txt.ots` (OpenTimestamps) |
| Submitted | 2026-11-11 ~12:57 PST (20:57 UTC) to 4 calendars: alice.btc.calendar.opentimestamps.org, bob (b.pool), finney.calendar.eternitywall.com, ots.btc.catallaxy.com |
| Status at submission | **PENDING** — not yet in a Bitcoin block |

Only the manifest hash was sent to the calendars. No file contents, no keys.

## Finish the proof (after a few hours)

```sh
pip install opentimestamps-client
ots upgrade ESDA_v1.1.0_MANIFEST.txt.ots    # pulls the Bitcoin attestation into the .ots
ots info    ESDA_v1.1.0_MANIFEST.txt.ots    # should show BitcoinBlockHeaderAttestation(<height>)
```

## Verify (anyone)

```sh
# 1. manifest matches the code
git checkout 800a1b0b6959a184cf647fa1f1aabf0daaeac8fe
for f in $(git ls-files); do sha256sum "$f"; done   # compare to manifest lines
# 2. manifest is in Bitcoin
ots verify ESDA_v1.1.0_MANIFEST.txt.ots             # needs a Bitcoin node or uses an explorer with --no-bitcoin + manual header check
```

Keep **both** the manifest and the `.ots` file. Either one alone proves nothing.
