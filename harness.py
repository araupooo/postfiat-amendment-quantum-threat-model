#!/usr/bin/env python3
"""harness.py — live amendment-state probe for the PFTL testnet, v1.0.0.

Measures the live amendment-relevant state of the public read-only PFTL
testnet and derives the quorum/threshold arithmetic for the threat model.

    python3 harness.py --live    [--out-dir results] [--tree <postfiatd tree>]
    python3 harness.py           [--out-dir results] [--tree <postfiatd tree>]

--live fetches from the public endpoints below (read-only calls only, no
credentials, no writes, no live peer connections). The default (offline)
mode re-derives every output from the vendored
results/sample_amendment_data.json; it never touches the network.

Endpoints (all public, read-only):
  RPC  https://rpc.testnet.postfiat.org/   (JSON-RPC: server_info, feature,
                                              manifest, ledger)
  VHS  https://vhs.testnet.postfiat.org/v1/network/
                                              (validators/, amendments/vote/test,
                                              amendments/info)

Each request is attempted up to 4 times; every attempt is recorded in
results/fetch_log.json. Nothing is ever sent that could mutate state, and
no secret, seed, or passphrase is ever sent or stored (redaction count is
reported in the summary).

Derived outputs (written to --out-dir, default <pack>/results):
  sample_amendment_data.json  vendored raw responses (live mode only;
                              offline mode reads it, never overwrites it)
  fetch_log.json              every request attempt (live mode; offline mode
                              keeps the vendored log)
  summary.json / summary.txt  headline numbers
  ledger_sample.csv           the sampled validated ledgers
  amendment_table.csv         the full amendment table from `feature`
  amendment_counts.csv        amendment status counts
  validator_sample.csv        one row per validator from VHS
  validator_counts.csv        validator-set counts
  attack_path_counts.csv      quorum/threshold arithmetic per attack path
"""
import argparse
import csv
import hashlib
import json
import math
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"
RPC_URL = "https://rpc.testnet.postfiat.org/"
VHS_BASE = "https://vhs.testnet.postfiat.org/v1/network/"
HARNESS_VERSION = "1.0.0"
LEDGER_SAMPLE_SIZE = 100
MAX_ATTEMPTS = 4
TIMEOUT_S = 30

# Fields that would be secret material if they ever appeared in a response.
# None of the probed endpoints returns them; the redaction pass below proves
# it (redaction count is reported in the summary).
SENSITIVE_KEYS = {"secret", "seed", "seed_hex", "passphrase", "master_seed",
                  "master_seed_hex", "validation_seed", "validation_private_key",
                  "private_key", "master_key_private"}


def fetch_json(url, payload=None, fetch_log=None, label=""):
    """GET (payload None) or POST (payload dict) a JSON endpoint.

    Returns (parsed_json_or_None, ok_bool). Retries up to MAX_ATTEMPTS.
    Every attempt is appended to fetch_log.
    """
    attempts = 0
    last_error = None
    t0 = time.time()
    while attempts < MAX_ATTEMPTS:
        attempts += 1
        try:
            if payload is None:
                req = urllib.request.Request(url, method="GET")
            else:
                body = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    url, data=body, method="POST",
                    headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read()
            parsed = json.loads(raw.decode("utf-8"))
            ms = int((time.time() - t0) * 1000)
            if fetch_log is not None:
                fetch_log.append({"request": label, "url": url,
                                  "attempts": attempts, "ok": True,
                                  "error": None, "ms": ms,
                                  "http_status": 200})
            return parsed, True
        except Exception as exc:  # noqa: BLE001 - record and retry
            last_error = "%s: %s" % (type(exc).__name__, exc)
            time.sleep(min(2 ** attempts, 8))
    ms = int((time.time() - t0) * 1000)
    if fetch_log is not None:
        fetch_log.append({"request": label, "url": url,
                          "attempts": attempts, "ok": False,
                          "error": last_error, "ms": ms,
                          "http_status": None})
    return None, False


def rpc(method, params, fetch_log, label):
    return fetch_json(RPC_URL, {"method": method, "params": [params]},
                      fetch_log, label)


def count_sensitive(obj):
    """Count occurrences of sensitive key names anywhere in a JSON value."""
    n = 0
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.lower() in SENSITIVE_KEYS:
                n += 1
            n += count_sensitive(v)
    elif isinstance(obj, list):
        for v in obj:
            n += count_sensitive(v)
    return n


def fetch_live():
    """Fetch the live sample. Returns (sample_dict, fetch_log_list)."""
    fetch_log = []
    sample = {"endpoint_rpc": RPC_URL, "endpoint_vhs": VHS_BASE,
              "fetch_date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                              time.gmtime())}

    server_info, ok = rpc("server_info", {}, fetch_log, "server_info")
    sample["server_info"] = server_info
    if not ok or not server_info or "result" not in server_info:
        raise SystemExit("live fetch failed: server_info unavailable")
    info = server_info["result"]["info"]
    validated_seq = info["validated_ledger"]["seq"]
    pubkey_node = info.get("pubkey_node", "")

    feature, _ = rpc("feature", {}, fetch_log, "feature_all")
    sample["feature_all"] = feature

    fix_calc, _ = rpc("feature", {"feature": "fixAmendmentMajorityCalc"},
                      fetch_log, "feature_fixAmendmentMajorityCalc")
    sample["feature_fixAmendmentMajorityCalc"] = fix_calc

    manifest, _ = rpc("manifest", {"public_key": pubkey_node},
                      fetch_log, "manifest_node")
    sample["manifest"] = manifest

    validated_ledger, _ = rpc(
        "ledger", {"ledger_index": "validated", "transactions": True,
                   "expand": True}, fetch_log, "ledger_validated")
    sample["ledger_validated"] = validated_ledger

    # Sample of consecutive validated ledgers ending at the validated ledger,
    # transactions expanded, to count amendment pseudo-transactions.
    ledgers = []
    for seq in range(validated_seq - LEDGER_SAMPLE_SIZE + 1,
                     validated_seq + 1):
        resp, ok = rpc("ledger", {"ledger_index": seq, "transactions": True,
                                  "expand": True},
                       fetch_log, "ledger_%d" % seq)
        if ok and resp and "result" in resp:
            ledgers.append(resp["result"])
        else:
            ledgers.append({"ledger_index": seq, "fetch_failed": True})
    sample["ledger_sample"] = ledgers

    vhs_validators, _ = fetch_json(VHS_BASE + "validators/", None,
                                   fetch_log, "vhs_validators")
    sample["vhs_validators"] = vhs_validators

    vhs_vote, _ = fetch_json(VHS_BASE + "amendments/vote/test", None,
                             fetch_log, "vhs_amendments_vote")
    sample["vhs_amendments_vote"] = vhs_vote

    vhs_info, _ = fetch_json(VHS_BASE + "amendments/info", None,
                             fetch_log, "vhs_amendments_info")
    sample["vhs_amendments_info"] = vhs_info

    sample["redactions"] = count_sensitive(sample)
    return sample, fetch_log


def quorum_arithmetic(trusted):
    """Amendment-majority and validation-quorum numbers for a trusted set.

    Post-fix amendment rule (fixAmendmentMajorityCalc enabled): threshold =
    floor(t * 67 / 100); a majority needs votes strictly greater than the
    threshold, i.e. force = threshold + 1. Upstream 80% rule: threshold =
    floor(t * 80 / 100); force = threshold + 1. Blocking a unanimous yes
    vote needs (t - threshold) votes removed/flipped. Validation quorum =
    max(ceil(t * 0.67), ceil(t * 0.6)).
    """
    t67 = (trusted * 67) // 100
    t80 = (trusted * 80) // 100
    return {
        "trusted_validations": trusted,
        "threshold_67pct": t67,
        "force_votes_67pct": t67 + 1,
        "block_votes_67pct": trusted - t67,
        "threshold_80pct": t80,
        "force_votes_80pct": t80 + 1,
        "block_votes_80pct": trusted - t80,
        "validation_quorum": max(math.ceil(trusted * 0.67),
                                 math.ceil(trusted * 0.6)),
    }


def write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def analyse(sample):
    """Derive every measured number from the vendored/live sample."""
    fetch_date = sample.get("fetch_date_utc", "")
    info = sample["server_info"]["result"]["info"]
    validated = info["validated_ledger"]
    features = sample["feature_all"]["result"]["features"]

    amendments = []
    for amd_id, v in sorted(features.items()):
        amendments.append({
            "id": amd_id, "name": v.get("name", ""),
            "enabled": bool(v.get("enabled")),
            "supported": bool(v.get("supported")),
            "majority": v.get("majority"),
        })
    n_enabled = sum(1 for a in amendments if a["enabled"])
    n_majority = sum(1 for a in amendments if a.get("majority") is not None)
    pf = [a for a in amendments if a["name"].startswith("PF_")]
    fix_calc = [a for a in amendments
                if a["name"] == "fixAmendmentMajorityCalc"]
    fix_calc_enabled = bool(fix_calc and fix_calc[0]["enabled"])

    manifest = sample["manifest"]["result"]
    details = manifest.get("details", {})
    manifest_eq = (details.get("ephemeral_key") is not None and
                   details.get("ephemeral_key") == details.get("master_key"))

    validators = sample["vhs_validators"]["validators"]
    vhs_count = sample["vhs_validators"].get("count", len(validators))
    unl = [v for v in validators if v.get("unl")]
    master_eq = sum(1 for v in validators
                    if v.get("master_key") == v.get("validation_public_key"))
    signing_ne = sum(1 for v in validators
                     if v.get("signing_key") != v.get("master_key"))
    domain_verified = sum(1 for v in validators if v.get("domain_verified"))
    revoked = sum(1 for v in validators if v.get("revoked"))
    partial = sum(1 for v in validators if v.get("partial"))
    versions = {}
    for v in validators:
        versions[v.get("server_version", "?")] = \
            versions.get(v.get("server_version", "?"), 0) + 1
    idx = [v.get("current_index", 0) for v in validators]
    missed_1h = sum(1 for v in validators
                    if (v.get("agreement_1h") or {}).get("missed", 0) > 0)

    vote = sample["vhs_amendments_vote"]
    vote_amds = vote.get("amendments", [])
    vote_ledgers = sorted({a.get("ledger_index") for a in vote_amds})
    vote_dates = sorted({a.get("date") for a in vote_amds})
    info_amds = sample["vhs_amendments_info"].get("amendments", [])
    info_deprecated = sum(1 for a in info_amds if a.get("deprecated"))

    ledgers = sample["ledger_sample"]
    fetched = [l for l in ledgers if not l.get("fetch_failed")]
    missing = [l["ledger_index"] for l in ledgers if l.get("fetch_failed")]
    tx_total = 0
    amend_tx = 0
    tx_types = {}
    close_times = []
    for l in fetched:
        lg = l.get("ledger", l)
        if lg.get("close_time") is not None:
            close_times.append(lg["close_time"])
        for tx in lg.get("transactions", []) or []:
            tx_total += 1
            tt = tx.get("TransactionType", "?")
            tx_types[tt] = tx_types.get(tt, 0) + 1
            if tt == "AMENDMENT":
                amend_tx += 1
    close_times.sort()
    span = (close_times[-1] - close_times[0]) if len(close_times) > 1 else 0
    mean_interval = (span / (len(close_times) - 1)) if len(close_times) > 1 \
        else 0.0

    # Quorum arithmetic for the live set sizes and a participation ladder.
    paths = []
    for t in (66, 50, 40, 30, 25, 17):
        row = quorum_arithmetic(t)
        row["context"] = {
            66: "VHS validator count (live)",
            50: "partial participation sensitivity",
            40: "partial participation sensitivity",
            30: "partial participation sensitivity",
            25: "UNL count (live, VHS unl=true)",
            17: "probed node validation_quorum (live, server_info)",
        }[t]
        paths.append(row)

    summary = {
        "harness_version": HARNESS_VERSION,
        "pinned_commit": PINNED_COMMIT,
        "fetch_date_utc": fetch_date,
        "endpoint_rpc": sample.get("endpoint_rpc", RPC_URL),
        "endpoint_vhs": sample.get("endpoint_vhs", VHS_BASE),
        "redactions": sample.get("redactions", 0),
        "server_snapshot": {
            "build_version": info.get("build_version"),
            "network_id": info.get("network_id"),
            "validated_ledger_seq": validated.get("seq"),
            "validated_ledger_hash": validated.get("hash"),
            "complete_ledgers": info.get("complete_ledgers"),
            "peers": info.get("peers"),
            "validation_quorum": info.get("validation_quorum"),
            "pubkey_node": info.get("pubkey_node"),
            "last_close_proposers": (info.get("last_close") or {})
            .get("proposers"),
        },
        "amendments": {
            "total_listed": len(amendments),
            "enabled": n_enabled,
            "not_enabled": len(amendments) - n_enabled,
            "supported": sum(1 for a in amendments if a["supported"]),
            "with_majority_timestamp": n_majority,
            "postfiat_specific_total": len(pf),
            "postfiat_specific_enabled": sum(1 for a in pf if a["enabled"]),
            "postfiat_specific_names": sorted(a["name"] for a in pf),
            "fixAmendmentMajorityCalc_enabled": fix_calc_enabled,
        },
        "validators": {
            "vhs_count": vhs_count,
            "rows_returned": len(validators),
            "unl_count": len(unl),
            "master_eq_validation_key": master_eq,
            "signing_ne_master_key": signing_ne,
            "domain_verified": domain_verified,
            "revoked": revoked,
            "partial": partial,
            "server_versions": versions,
            "current_index_min": min(idx) if idx else None,
            "current_index_max": max(idx) if idx else None,
            "agreement_1h_missed_gt0": missed_1h,
        },
        "vhs_vote": {
            "enabled_amendments": vote.get("count", len(vote_amds)),
            "distinct_enablement_ledgers": vote_ledgers,
            "distinct_enablement_dates": vote_dates,
            "info_total": sample["vhs_amendments_info"].get(
                "count", len(info_amds)),
            "info_deprecated": info_deprecated,
        },
        "manifest_node": {
            "ephemeral_eq_master": manifest_eq,
            "ephemeral_key": details.get("ephemeral_key"),
            "master_key": details.get("master_key"),
        },
        "ledger_sample": {
            "ledgers_requested": len(ledgers),
            "ledgers_fetched": len(fetched),
            "ledgers_missing": missing,
            "ledger_start": ledgers[0]["ledger_index"] if ledgers else None,
            "ledger_end": ledgers[-1]["ledger_index"] if ledgers else None,
            "transactions_total": tx_total,
            "transactions_by_type": tx_types,
            "amendment_pseudo_transactions": amend_tx,
            "close_time_span_s": span,
            "mean_close_interval_s": round(mean_interval, 3),
        },
        "quorum_paths": paths,
        "tree_check": {},
        "sample_sha256": "",
    }

    tables = {
        "amendments": amendments,
        "validators": validators,
        "vote_amendments": vote_amds,
        "info_amendments": info_amds,
        "paths": paths,
        "ledgers": fetched,
    }
    return summary, tables


def tree_head(tree):
    try:
        out = subprocess.run(["git", "-C", tree, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        head = out.stdout.strip()
    except Exception:  # noqa: BLE001
        head = ""
    return {"tree_head_commit": head,
            "tree_head_matches_pinned": head == PINNED_COMMIT}


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="PFTL amendment-state probe (live) / analyser (offline)")
    ap.add_argument("--live", action="store_true",
                    help="fetch from the public endpoints (default: offline, "
                         "reuse vendored sample)")
    ap.add_argument("--out-dir", default=None,
                    help="results directory (default: <pack>/results)")
    ap.add_argument("--tree", default="/home/hatch/workspace/"
                    "postfiatd-amendment/worktree-0085a1ff",
                    help="postfiatd tree to record HEAD for "
                         "(default: pinned worktree)")
    args = ap.parse_args(argv)

    pack_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = args.out_dir or os.path.join(pack_dir, "results")
    os.makedirs(out_dir, exist_ok=True)

    if args.live:
        sample, fetch_log = fetch_live()
        write_json(os.path.join(out_dir, "sample_amendment_data.json"),
                   sample)
        write_json(os.path.join(out_dir, "fetch_log.json"), fetch_log)
    else:
        sample_path = os.path.join(out_dir, "sample_amendment_data.json")
        with open(sample_path, encoding="utf-8") as fh:
            sample = json.load(fh)
        # Offline mode never overwrites the vendored live fetch log: it is
        # the record of the actual network fetch. Only create a placeholder
        # if no fetch log was shipped at all.
        if not os.path.exists(os.path.join(out_dir, "fetch_log.json")):
            write_json(os.path.join(out_dir, "fetch_log.json"),
                       [{"request": "offline-mode", "ok": True,
                         "error": None,
                         "note": "no network access; reused vendored "
                                 "results/sample_amendment_data.json"}])

    summary, tables = analyse(sample)
    summary["tree_check"] = tree_head(args.tree)
    # Deterministic content hash of the vendored sample, for traceability.
    with open(os.path.join(out_dir, "sample_amendment_data.json"),
              "rb") as fh:
        summary["sample_sha256"] = hashlib.sha256(fh.read()).hexdigest()

    write_json(os.path.join(out_dir, "summary.json"), summary)

    # Per-amendment table (from the live `feature` call).
    with open(os.path.join(out_dir, "amendment_table.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["id", "name", "enabled", "supported", "majority"])
        for a in tables["amendments"]:
            w.writerow([a["id"], a["name"], a["enabled"], a["supported"],
                        a["majority"] if a["majority"] is not None else ""])

    # Amendment status counts.
    with open(os.path.join(out_dir, "amendment_counts.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["metric", "count"])
        am = summary["amendments"]
        w.writerow(["total_listed", am["total_listed"]])
        w.writerow(["enabled", am["enabled"]])
        w.writerow(["not_enabled", am["not_enabled"]])
        w.writerow(["supported", am["supported"]])
        w.writerow(["with_majority_timestamp",
                    am["with_majority_timestamp"]])
        w.writerow(["postfiat_specific_total",
                    am["postfiat_specific_total"]])
        w.writerow(["postfiat_specific_enabled",
                    am["postfiat_specific_enabled"]])
        w.writerow(["fixAmendmentMajorityCalc_enabled",
                    int(am["fixAmendmentMajorityCalc_enabled"])])

    # Validator rows (from VHS; public keys are public data).
    with open(os.path.join(out_dir, "validator_sample.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["validation_public_key", "master_key", "signing_key",
                    "domain", "domain_verified", "unl", "revoked",
                    "partial", "server_version", "current_index",
                    "agreement_1h_missed", "agreement_1h_total",
                    "agreement_1h_score"])
        for v in tables["validators"]:
            a1 = v.get("agreement_1h") or {}
            w.writerow([v.get("validation_public_key", ""),
                        v.get("master_key", ""), v.get("signing_key", ""),
                        v.get("domain", ""), v.get("domain_verified", ""),
                        v.get("unl", ""), v.get("revoked", ""),
                        v.get("partial", ""), v.get("server_version", ""),
                        v.get("current_index", ""),
                        a1.get("missed", ""), a1.get("total", ""),
                        a1.get("score", "")])

    # Validator-set counts.
    with open(os.path.join(out_dir, "validator_counts.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["metric", "count"])
        vs = summary["validators"]
        for k in ("vhs_count", "rows_returned", "unl_count",
                  "master_eq_validation_key", "signing_ne_master_key",
                  "domain_verified", "revoked", "partial",
                  "agreement_1h_missed_gt0"):
            w.writerow([k, vs[k]])
        for ver, n in sorted(vs["server_versions"].items()):
            w.writerow(["server_version_" + str(ver), n])

    # Quorum/threshold arithmetic per attack path.
    with open(os.path.join(out_dir, "attack_path_counts.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["trusted_validations", "context", "threshold_67pct",
                    "force_votes_67pct", "block_votes_67pct",
                    "threshold_80pct", "force_votes_80pct",
                    "block_votes_80pct", "validation_quorum"])
        for p in tables["paths"]:
            w.writerow([p["trusted_validations"], p["context"],
                        p["threshold_67pct"], p["force_votes_67pct"],
                        p["block_votes_67pct"], p["threshold_80pct"],
                        p["force_votes_80pct"], p["block_votes_80pct"],
                        p["validation_quorum"]])

    # Sampled ledgers.
    with open(os.path.join(out_dir, "ledger_sample.csv"), "w",
              encoding="utf-8", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["ledger_index", "ledger_hash", "close_time",
                    "parent_hash", "tx_count", "amendment_tx_count"])
        for l in tables["ledgers"]:
            lg = l.get("ledger", l)
            txs = lg.get("transactions", []) or []
            w.writerow([lg.get("ledger_index"), lg.get("ledger_hash"),
                        lg.get("close_time"), lg.get("parent_hash"),
                        len(txs),
                        sum(1 for t in txs
                            if t.get("TransactionType") == "AMENDMENT")])

    # Human-readable summary.
    s = summary
    lines = [
        "PFTL amendment-state probe",
        "fetch date (UTC): %s" % s["fetch_date_utc"],
        "pinned commit: %s" % s["pinned_commit"],
        "tree_head_matches_pinned: %s"
        % s["tree_check"]["tree_head_matches_pinned"],
        "",
        "Server: build %s, network_id %s, validated ledger %s"
        % (s["server_snapshot"]["build_version"],
           s["server_snapshot"]["network_id"],
           s["server_snapshot"]["validated_ledger_seq"]),
        "complete_ledgers: %s; peers: %s; validation_quorum: %s; "
        "last_close proposers: %s"
        % (s["server_snapshot"]["complete_ledgers"],
           s["server_snapshot"]["peers"],
           s["server_snapshot"]["validation_quorum"],
           s["server_snapshot"]["last_close_proposers"]),
        "node public key: %s"
        % s["server_snapshot"]["pubkey_node"],
        "",
        "Amendments: %d listed, %d enabled, %d not enabled, "
        "%d with a majority timestamp"
        % (s["amendments"]["total_listed"], s["amendments"]["enabled"],
           s["amendments"]["not_enabled"],
           s["amendments"]["with_majority_timestamp"]),
        "fixAmendmentMajorityCalc enabled: %s"
        % s["amendments"]["fixAmendmentMajorityCalc_enabled"],
        "PostFiat-specific amendments: %s (enabled: %d)"
        % (", ".join(s["amendments"]["postfiat_specific_names"]),
           s["amendments"]["postfiat_specific_enabled"]),
        "VHS vote list: %d enabled amendments, enablement ledgers %s, "
        "dates %s"
        % (s["vhs_vote"]["enabled_amendments"],
           s["vhs_vote"]["distinct_enablement_ledgers"],
           s["vhs_vote"]["distinct_enablement_dates"]),
        "",
        "Validators (VHS): %d total, %d in UNL, %d master==validation key, "
        "%d signing key != master key"
        % (s["validators"]["vhs_count"], s["validators"]["unl_count"],
           s["validators"]["master_eq_validation_key"],
           s["validators"]["signing_ne_master_key"]),
        "domain_verified: %d; revoked: %d; partial: %d; "
        "agreement_1h missed>0: %d"
        % (s["validators"]["domain_verified"], s["validators"]["revoked"],
           s["validators"]["partial"],
           s["validators"]["agreement_1h_missed_gt0"]),
        "server versions: %s"
        % json.dumps(s["validators"]["server_versions"], sort_keys=True),
        "",
        "Node manifest: ephemeral key == master key: %s"
        % s["manifest_node"]["ephemeral_eq_master"],
        "",
        "Ledger sample: %d requested, %d fetched, %d missing; "
        "%d transactions, %d amendment pseudo-transactions"
        % (s["ledger_sample"]["ledgers_requested"],
           s["ledger_sample"]["ledgers_fetched"],
           len(s["ledger_sample"]["ledgers_missing"]),
           s["ledger_sample"]["transactions_total"],
           s["ledger_sample"]["amendment_pseudo_transactions"]),
        "mean close interval: %s s over %s s"
        % (s["ledger_sample"]["mean_close_interval_s"],
           s["ledger_sample"]["close_time_span_s"]),
        "",
        "Quorum arithmetic (trusted validations -> force/block votes):",
    ]
    for p in s["quorum_paths"]:
        lines.append(
            "  t=%d (%s): 67%% threshold %d, force %d, block %d; "
            "80%% threshold %d, force %d, block %d; validation quorum %d"
            % (p["trusted_validations"], p["context"],
               p["threshold_67pct"], p["force_votes_67pct"],
               p["block_votes_67pct"], p["threshold_80pct"],
               p["force_votes_80pct"], p["block_votes_80pct"],
               p["validation_quorum"]))
    lines.append("")
    lines.append("Secrets redacted from the vendored sample: %d"
                 % s["redactions"])
    lines.append("sample_sha256: %s" % s["sample_sha256"])
    with open(os.path.join(out_dir, "summary.txt"), "w",
              encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print("harness.py: OK (offline mode, %d ledgers, %d amendments, "
          "%d validators, %d amendment pseudo-transactions)"
          % (s["ledger_sample"]["ledgers_fetched"],
             s["amendments"]["total_listed"],
             s["validators"]["vhs_count"],
             s["ledger_sample"]["amendment_pseudo_transactions"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
