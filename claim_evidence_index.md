# Claim-to-evidence index

Pinned tree for every source-derived claim: postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`
(`tree_head_matches_pinned: true`, `results/summary.json` line 124).
Live probe fetched 2026-11-13T23:02:58Z from the public read-only
endpoints `https://rpc.testnet.postfiat.org/` and
`https://vhs.testnet.postfiat.org/v1/network/` (108 requests, 0
failed, `results/fetch_log.json`).

Measured claims (M) come from the vendored live sample and the
harness derivation. Source-derived claims (S) come from reading the
pinned tree. They are kept in separate sections so a reviewer can
check each kind independently.

## M — measured claims

| ID | Claim | Evidence |
|----|-------|----------|
| M-01 | 101 amendments listed; 64 enabled, 37 not enabled; 0 with a majority timestamp; 101 supported | `results/summary.json` lines 2–14 (`amendments` block); `results/amendment_table.csv` (101 data rows); `results/amendment_counts.csv` |
| M-02 | `fixAmendmentMajorityCalc` is enabled (post-fix 67% rule is the live rule) | `results/summary.json` line 4; `results/amendment_counts.csv` row `fixAmendmentMajorityCalc_enabled,1` |
| M-03 | PostFiat-specific amendments are `PF_AccountExclusion` and `PF_ValidatorVoteTracking`; 2 total, 0 enabled | `results/summary.json` lines 6–11 |
| M-04 | 66 validators (VHS); 25 in UNL; 65 master key == validation key; 66 signing key != master key | `results/summary.json` lines 127–143 (`validators` block); `results/validator_sample.csv` (66 data rows); `results/validator_counts.csv` |
| M-05 | domain_verified 55; revoked 0; partial 0; 1 validator with agreement_1h missed > 0 | `results/summary.json` lines 127, 130, 132, 133 |
| M-06 | Server versions: 1.0.0: 2, 1.0.4: 9, 1.0.8: 1, 1.0.9: 54 | `results/summary.json` lines 135–140 |
| M-07 | All 64 enabled amendments were enabled at a single ledger (86785) on 2026-02-09T14:31:12Z | `results/summary.json` lines 146–151 (`vhs_vote` block) |
| M-08 | Ledger sample: 100 requested, 100 fetched, 0 missing; 35 transactions, 0 amendment pseudo-transactions; mean close interval 3.03 s over 300 s | `results/summary.json` lines 21–33 (`ledger_sample` block); `results/ledger_sample.csv` (100 rows) |
| M-09 | Quorum arithmetic at full participation (t=66): force 45 / block 22 under the live 67% rule; force 53 / block 14 under the upstream 80% rule; validation quorum 45. Full participation ladder in the same file | `results/attack_path_counts.csv` line 2 (t=66 row); lines 3–7 for t=50/40/30/25/17 |
| M-10 | Probed node manifest: ephemeral key == master key | `results/summary.json` line 36 (`manifest_node.ephemeral_eq_master: true`) |
| M-11 | Probed server: build 1.0.9, network_id 2025, validated ledger 8025564, complete ledgers 7950054–8025564, 21 peers, validation_quorum 17 | `results/summary.json` lines 112–119 (`server_snapshot` block) |
| M-12 | 108 fetch requests, 0 failed; sample SHA-256 `612584c1637dd0b0a0dcc55d89c3e0de37af594bc2f34390ade414fb44891469` | `results/fetch_log.json` (108 entries, all `"ok": true`); `results/summary.json` lines 109–110 |
| M-13 | 0 secrets redacted from the vendored sample (no secret, seed, passphrase, or private-key field appeared in any response) | `results/summary.json` line 109 (`redactions: 0`) |

## S — source-derived claims (pinned tree)

| ID | Claim | Evidence |
|----|-------|----------|
| S-01 | Post-fix amendment majority threshold is 67/100 | `include/xrpl/protocol/SystemParameters.h:85` — `constexpr std::ratio<67, 100> postFixAmendmentMajorityCalcThreshold;` |
| S-02 | An amendment must hold a majority for 2 weeks before it can enable | `include/xrpl/protocol/SystemParameters.h:88` — `defaultAmendmentMajorityTime = std::chrono::weeks{2}` |
| S-03 | Validations are secp256k1-only; a validation is verified by `verifyDigest` over the signing hash | `include/xrpl/protocol/STValidation.h:249-250` (`LogicError("We can only use secp256k1 keys for signing validations")`); `src/libxrpl/protocol/STValidation.cpp:123-146` (`isValid`, `verifyDigest`) |
| S-04 | A validation must carry `sfLedgerHash`, `sfLedgerSequence`, `sfSigningTime`, `sfSigningPubKey`, and `sfSignature` | `src/libxrpl/protocol/STValidation.cpp:61-86` (template, all `soeREQUIRED`) |
| S-05 | Threshold computation: pre-fix `204/256`, post-fix `67/100`, applied to the trusted-validation count | `src/xrpld/app/misc/detail/AmendmentTable.cpp:326-342` (`computeThreshold`) |
| S-06 | Majority test is strict `>` after the fix (pre-fix `>=`) | `src/xrpld/app/misc/detail/AmendmentTable.cpp:368-376` |
| S-07 | `recordVotes` counts only validations from trusted validators; untrusted validations are ignored | `src/xrpld/app/misc/detail/AmendmentTable.cpp:153-265` (trust filter at lines 176–216, `"Ignoring validation from untrusted"` at line 216) |
| S-08 | A node's desired list is the amendments it supports, does not veto, and that are not already enabled | `src/xrpld/app/misc/detail/AmendmentTable.cpp:813-837` (`doValidation`) |
| S-09 | The hold branch: an amendment enables only when `majorityTime + 2 weeks <= closeTime` | `src/xrpld/app/misc/detail/AmendmentTable.cpp:916-923` |
| S-10 | The validated ledger is the authority on enabled amendments and majority timestamps | `src/libxrpl/ledger/View.cpp:1000-1016` (`getEnabledAmendments`); `1017-1046` (`getMajorityAmendments`) |
| S-11 | Enabling is done by the `Change` pseudo-transaction at a flag ledger; enabling an amendment the node does not support halts the server | `src/xrpld/app/tx/detail/Change.cpp:353-370` (enable branch; `setAmendmentBlocked()` at line 370) |
| S-16 | The halt is also enforced at ledger close: a node with any unsupported enabled amendment blocks | `src/xrpld/app/ledger/detail/LedgerMaster.cpp:309-314` (`hasUnsupportedEnabled()` → `setAmendmentBlocked()`) |
| S-12 | A manifest is verified by two signatures (signing key + master key); revocation is a manifest with sequence `0xFFFFFFFF` | `src/xrpld/app/misc/detail/Manifest.cpp:196-213` (`verify`); `226-240` (revoked) |
| S-13 | Veto is admin-only over RPC and persists the vote in `wallet.db` | `src/xrpld/rpc/handlers/Feature1.cpp:78-87` (`rpcNO_PERMISSION` unless admin); `src/xrpld/app/misc/detail/AmendmentTable.cpp:723-761` (`persistVote`, `veto`, `unVeto`) |
| S-14 | `doVoting` runs only when trusted validations reach the node's quorum | `src/xrpld/app/consensus/RCLConsensus.cpp:371` (`validations.size() >= app_.validators().quorum()`) |
| S-15 | Validation quorum is `max(ceil(UNL*0.67), ceil(UNL*0.6))`; the fork deliberately uses 67% where upstream XRPL uses 80% | `src/xrpld/app/misc/detail/ValidatorList.cpp:1898-1900` (comment: "Original XRPL uses 80%, but this fork uses 67% for devnet/testnet"); `1933-1934` (formula) |

## Cross-references

- Threat-model assets A-1..A-7: `threat_model.csv` (rows 2–8); each
  row's `pinned_tree_evidence` column cites the same S rows above,
  and `measured_support` cites the matching M rows.
- Attack trees T-01..T-09: `attack_trees.md` lines 10, 28, 56, 74,
  94, 116, 138, 159, 171. Each tree's leaves cite the S rows above
  and take their numbers from M-09 (`results/attack_path_counts.csv`).
- Headline finding (threat_model.md lines 12–27) is M-02 + M-04 +
  M-07 + M-09 + S-01 + S-02.
