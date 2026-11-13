# PFTL Amendment-State Probe: Quantum Threat Model for the Amendment Process

Which parts of the amendment process a harvest-now quantum adversary
can attack, what each break would and would not buy, and where the
process is structurally safe.

Pinned tree: postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`. Live probe fetched
2026-11-13T23:02:58Z from the public read-only endpoints
`https://rpc.testnet.postfiat.org/` and
`https://vhs.testnet.postfiat.org/v1/network/` (108 requests, 0
failed; no credentials, no writes, no live peer connections).

## Headline finding

The amendment process is a **threshold game over secp256k1
signatures**, and the threshold is **67%, not 80%**. With all 66
validators voting, forcing an amendment to a majority takes **45
broken validator keys** under the live 67% rule (53 under the
upstream 80% rule), and blocking a unanimous yes vote takes **22**
(14 under 80%). No single broken key can do anything: one key is
one vote, and the ledger records the majority, not the individual
vote. The process has never been exercised live on this testnet: all
64 enabled amendments were enabled at a single ledger (86785,
2026-02-09T14:31:12Z) and **no amendment currently holds a
majority**. The cheapest quantum attack is forging a majority for an
**unsupported** amendment, which makes every node that does not
support it halt with "server blocked".

## Files

- `threat_model.md` — formal threat model: assets, trust boundaries,
  attacker model, amendment pipeline, attack-path summary, measured
  findings
- `attack_trees.md` — nine attack trees (T-01 to T-09) with leaf
  evidence and file:line citations into the pinned tree
- `threat_model.csv` — the seven assets with mechanism, attacker
  capability, pinned-tree evidence, measured support, verdict
- `claim_evidence_index.md` — every headline claim mapped to repo
  file, field, and line (measured and source-derived claims in
  separate sections)
- `harness.py` — live probe / offline analyser
- `run_all.sh` — regenerate every derived output offline, rebuild
  the results page, verify digests
- `verify_digests.sh` — SHA-256 manifest (`SHA256SUMS`)
- `build_derived.py` — render `docs/index.html` from the results
- `docs/index.html` — canonical results page
- `results/` — vendored raw sample (`sample_amendment_data.json`),
  fetch log, derived measurements (`summary.json`, `summary.txt`),
  per-record tables

## Reproduction

```sh
bash run_all.sh
```

Regenerates every derived output offline from the vendored sample,
rebuilds the results page, and verifies digests. Expected: exit 0,
byte-identical outputs. See `REPRODUCTION.md` for the exact
procedure and recorded result, `results/run_log.txt` for the raw
console log, and `results/digest_check_output.txt` for the raw
digest-check output. Verify digests at any time with
`bash verify_digests.sh --check`.

To fetch a fresh live sample instead, run
`python3 harness.py --live` first (public read-only endpoints, no
credentials), then `bash run_all.sh`. A live re-probe produces
different ledger numbers as the testnet advances; that is expected,
and is why the vendored sample is the reproducible artifact.

## Limitations

- The live sample is a single point in time (2026-11-13T23:02:58Z);
  validator counts, ledger numbers, and amendment state move as the
  testnet advances. Offline reproduction re-derives from the vendored
  sample, not from a fresh fetch.
- Thresholds are computed from the live counts and the pinned-tree
  threshold code; no ledger was compiled or run locally, and no
  validation was forged or replayed against a live node.
- Validator public keys in the tables are public VHS data; no
  private key, seed, or credential appears anywhere in this pack.
- The `.sh` files are executable in this pack. A GitHub web upload
  strips the executable bit; run the scripts with `bash` after a web
  upload.
