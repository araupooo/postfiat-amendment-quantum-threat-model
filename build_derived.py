#!/usr/bin/env python3
"""Build docs/index.html from the derived results.

Reads results/summary.json, results/amendment_counts.csv,
results/validator_counts.csv and results/attack_path_counts.csv and
renders the canonical results page. Deterministic: no timestamps are
written except the fetch date copied from the vendored sample.
"""

import csv
import html
import json
import os

PACK_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(PACK_DIR, "results")


def esc(value):
    return html.escape(str(value))


def main():
    with open(os.path.join(RESULTS, "summary.json"),
              encoding="utf-8") as fh:
        s = json.load(fh)

    with open(os.path.join(RESULTS, "amendment_counts.csv"),
              encoding="utf-8") as fh:
        amd_counts = list(csv.DictReader(fh))

    with open(os.path.join(RESULTS, "validator_counts.csv"),
              encoding="utf-8") as fh:
        val_counts = list(csv.DictReader(fh))

    with open(os.path.join(RESULTS, "attack_path_counts.csv"),
              encoding="utf-8") as fh:
        paths = list(csv.DictReader(fh))

    am = s["amendments"]
    vs = s["validators"]
    vv = s["vhs_vote"]
    ls = s["ledger_sample"]
    sv = s["server_snapshot"]
    mn = s["manifest_node"]

    amd_rows = "\n".join(
        "<tr><td>%s</td><td>%s</td></tr>" % (
            esc(r["metric"]), esc(r["count"]))
        for r in amd_counts)

    val_rows = "\n".join(
        "<tr><td>%s</td><td>%s</td></tr>" % (
            esc(r["metric"]), esc(r["count"]))
        for r in val_counts)

    path_rows = "\n".join(
        "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
        "<td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(p["trusted_validations"]), esc(p["context"]),
            esc(p["threshold_67pct"]), esc(p["force_votes_67pct"]),
            esc(p["block_votes_67pct"]), esc(p["threshold_80pct"]),
            esc(p["force_votes_80pct"]), esc(p["block_votes_80pct"]))
        for p in paths)

    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>PFTL Amendment-State Probe: Quantum Threat Model for the Amendment Process</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  max-width:900px;margin:2em auto;padding:0 1em;color:#111;line-height:1.5}
h1{font-size:1.6em}h2{font-size:1.25em;margin-top:1.5em}
table{border-collapse:collapse;width:100%%;margin:1em 0}
th,td{border:1px solid #ccc;padding:.35em .6em;text-align:left;
  font-size:.92em}th{background:#f0f0f0}
code{background:#f4f4f4;padding:0 .2em}
.callout{background:#f7f3e8;border-left:4px solid #b58900;padding:.7em 1em}
.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.9em}
</style>
</head>
<body>
<h1>PFTL Amendment-State Probe: Quantum Threat Model for the Amendment Process</h1>
<p>Which parts of the amendment process a harvest-now quantum adversary
can attack, what each break would and would not buy, and where the
process is structurally safe. Pinned tree: postfiatd main
<code>%(pinned)s</code>. Live probe fetched %(fetch_date)s from the
public read-only endpoints <code>%(endpoint_rpc)s</code> and
<code>%(endpoint_vhs)s</code> (no credentials, no writes, no live peer
connections). Server: build %(build)s, network_id %(net)d, validated
ledger %(validated)d.</p>

<div class="callout"><strong>Headline finding.</strong> The amendment
process is a <strong>threshold game over secp256k1 signatures</strong>,
and the threshold is <strong>67%%, not 80%%</strong>. With all 66
validators voting, forcing an amendment to a majority takes
<strong>45 broken validator keys</strong> under the live 67%% rule
(53 under the upstream 80%% rule), and blocking a unanimous yes vote
takes <strong>22</strong> (14 under 80%%). The 67%% rule therefore
makes forcing easier and blocking harder than upstream — but the
number that matters is still large, and no single broken key can do
anything at all: one key is one vote, and the ledger records the
majority, not the individual vote. The process has never been
exercised live on this testnet: all %(enabled)d enabled amendments
were enabled at a single ledger (%(enable_ledger)d,
%(enable_date)s) and <strong>no amendment currently holds a
majority</strong>. The cheapest quantum attack is therefore not
forging a majority at all — it is forging a majority for an
<strong>unsupported</strong> amendment, which makes every node that
does not support it halt with &ldquo;server blocked&rdquo;.</div>

<h2>Headline numbers</h2>
<table>
<tr><th>Measure</th><th>Value</th></tr>
<tr><td>Amendments listed</td><td>%(total)d (%(enabled)d enabled, %(not_enabled)d not enabled, %(majority)d with a majority timestamp)</td></tr>
<tr><td>fixAmendmentMajorityCalc</td><td>%(fix_calc)s (post-fix 67%% rule live)</td></tr>
<tr><td>PostFiat-specific amendments</td><td>%(pf_names)s — %(pf_total)d total, %(pf_enabled)d enabled</td></tr>
<tr><td>Validators (VHS)</td><td>%(validators)d total, %(unl)d in UNL, %(master_eq)d master key == validation key, %(signing_ne)d signing key != master key</td></tr>
<tr><td>Domain verified / revoked / partial</td><td>%(domain_verified)d / %(revoked)d / %(partial)d</td></tr>
<tr><td>Server versions</td><td>%(versions)s</td></tr>
<tr><td>Agreement (1h) validators with missed &gt; 0</td><td>%(missed)d</td></tr>
<tr><td>Node manifest</td><td>Ephemeral key equals master key: %(manifest_eq)s (the probed node validates with its master key directly)</td></tr>
<tr><td>Ledger sample</td><td>%(ledgers)d requested, %(fetched)d fetched, %(missing)d missing; %(tx)d transactions, %(amend_tx)d amendment pseudo-transactions</td></tr>
<tr><td>Mean close interval</td><td>%(interval)s s over %(span)d s</td></tr>
<tr><td>Secrets redacted from the vendored sample</td><td>%(redactions)d</td></tr>
<tr><td>Sample SHA-256</td><td class="mono">%(sample_sha)s</td></tr>
</table>

<h2>Quorum arithmetic per attack path</h2>
<p>Force = votes needed to push an amendment over the majority
threshold (threshold + 1). Block = votes that must be removed or
flipped to stop a unanimous yes vote from reaching a majority.
Validation quorum = max(ceil(t &times; 0.67), ceil(t &times; 0.6)).</p>
<table>
<tr><th>Trusted validations</th><th>Context</th>
<th>Threshold 67%%</th><th>Force 67%%</th><th>Block 67%%</th>
<th>Threshold 80%%</th><th>Force 80%%</th><th>Block 80%%</th></tr>
%(path_rows)s
</table>

<h2>Amendment status counts</h2>
<table>
<tr><th>Metric</th><th>Count</th></tr>
%(amd_rows)s
</table>

<h2>Validator-set counts</h2>
<table>
<tr><th>Metric</th><th>Count</th></tr>
%(val_rows)s
</table>

<h2>Reproduction</h2>
<p class="mono">bash run_all.sh</p>
<p>Regenerates every derived output offline from the vendored sample
(<code>results/sample_amendment_data.json</code>), rebuilds this page,
and verifies digests. Expected: exit 0, byte-identical outputs. See
<code>REPRODUCTION.md</code> for the exact command and recorded
result, <code>results/run_log.txt</code> for the raw console log, and
<code>results/digest_check_output.txt</code> for the raw digest-check
output. Verify digests at any time with
<code>bash verify_digests.sh --check</code>. To fetch a fresh live
sample instead, run <code>python3 harness.py --live</code> first
(public read-only endpoints, no credentials), then
<code>bash run_all.sh</code>.</p>

<h2>Files</h2>
<ul>
<li><code>threat_model.md</code> — formal threat model: assets,
trust boundaries, attacker model, amendment pipeline, attack-path
summary, measured findings</li>
<li><code>attack_trees.md</code> — nine attack trees (T-01 to T-09)
with leaf evidence and file:line citations into the pinned tree</li>
<li><code>threat_model.csv</code> — the seven assets with mechanism,
attacker capability, pinned-tree evidence, measured support, verdict</li>
<li><code>claim_evidence_index.md</code> — every headline claim mapped
to repo file, field, and line (measured and source-derived claims in
separate sections)</li>
<li><code>harness.py</code> — live probe / offline analyser</li>
<li><code>results/sample_amendment_data.json</code> — vendored raw sample</li>
<li><code>results/fetch_log.json</code> — per-request fetch record</li>
<li><code>results/summary.json</code> / <code>summary.txt</code> —
derived measurements</li>
<li><code>results/amendment_table.csv</code>,
<code>results/amendment_counts.csv</code>,
<code>results/validator_sample.csv</code>,
<code>results/validator_counts.csv</code>,
<code>results/attack_path_counts.csv</code>,
<code>results/ledger_sample.csv</code> — per-record tables</li>
</ul>

<h2>Limitations</h2>
<ul>
<li>The live sample is a single point in time
(%(fetch_date)s); validator counts, ledger numbers, and amendment
state move as the testnet advances. Offline reproduction re-derives
from the vendored sample, not from a fresh fetch.</li>
<li>Thresholds are computed from the live counts and the pinned-tree
threshold code; no ledger was compiled or run locally, and no
validation was forged or replayed against a live node.</li>
<li>Validator public keys in the tables are public VHS data; no
private key, seed, or credential appears anywhere in this pack.</li>
</ul>
</body>
</html>
""" % {
        "pinned": esc(s["pinned_commit"]),
        "fetch_date": esc(s["fetch_date_utc"]),
        "endpoint_rpc": esc(s["endpoint_rpc"]),
        "endpoint_vhs": esc(s["endpoint_vhs"]),
        "build": esc(sv["build_version"]),
        "net": sv["network_id"],
        "validated": sv["validated_ledger_seq"],
        "total": am["total_listed"],
        "enabled": am["enabled"],
        "not_enabled": am["not_enabled"],
        "majority": am["with_majority_timestamp"],
        "fix_calc": esc(am["fixAmendmentMajorityCalc_enabled"]),
        "pf_names": esc(", ".join(am["postfiat_specific_names"])),
        "pf_total": am["postfiat_specific_total"],
        "pf_enabled": am["postfiat_specific_enabled"],
        "enable_ledger": vv["distinct_enablement_ledgers"][0]
        if vv["distinct_enablement_ledgers"] else 0,
        "enable_date": esc(vv["distinct_enablement_dates"][0])
        if vv["distinct_enablement_dates"] else "",
        "validators": vs["vhs_count"],
        "unl": vs["unl_count"],
        "master_eq": vs["master_eq_validation_key"],
        "signing_ne": vs["signing_ne_master_key"],
        "domain_verified": vs["domain_verified"],
        "revoked": vs["revoked"],
        "partial": vs["partial"],
        "versions": esc(", ".join(
            "%s: %d" % (k, v)
            for k, v in sorted(vs["server_versions"].items()))),
        "missed": vs["agreement_1h_missed_gt0"],
        "manifest_eq": esc(mn["ephemeral_eq_master"]),
        "ledgers": ls["ledgers_requested"],
        "fetched": ls["ledgers_fetched"],
        "missing": len(ls["ledgers_missing"]),
        "tx": ls["transactions_total"],
        "amend_tx": ls["amendment_pseudo_transactions"],
        "interval": ls["mean_close_interval_s"],
        "span": ls["close_time_span_s"],
        "redactions": s["redactions"],
        "sample_sha": esc(s["sample_sha256"]),
        "amd_rows": amd_rows,
        "val_rows": val_rows,
        "path_rows": path_rows,
    }

    out_path = os.path.join(PACK_DIR, "docs", "index.html")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    print("build_derived.py: OK (docs/index.html)")


if __name__ == "__main__":
    main()
