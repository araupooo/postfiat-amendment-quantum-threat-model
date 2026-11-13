# Formal Threat Model for the PFTL Amendment Process Under Quantum Adversaries

Which parts of the amendment process a harvest-now quantum adversary can
attack, what each break would and would not buy, and where the process is
structurally safe. Pinned tree: postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`. Every mechanism below is cited
with a file:line reference into that tree; every number comes from the
live probe in `results/summary.json` (fetch 2026-11-13T23:02:58Z).

**Canonical results page: `docs/index.html`.**

## Headline finding

The amendment process is a **threshold game over secp256k1 signatures**,
and the threshold is 67%, not 80%. With all 66 validators voting, forcing
an amendment to a majority takes **45 broken validator keys** under the
live 67% rule (53 under the upstream 80% rule), and blocking a unanimous
yes vote takes **22** (14 under 80%). The 67% rule therefore makes forcing
easier and blocking harder than upstream — but the number that matters is
still large, and no single broken key can do anything at all: one key is
one vote, and the ledger records the majority, not the individual vote.
The process has never been exercised live on this testnet: all 64 enabled
amendments were enabled at a single ledger (86785, 2026-02-09T14:31:12Z)
and **no amendment currently holds a majority**. The cheapest quantum
attack is therefore not forging a majority at all — it is forging a
majority for an **unsupported** amendment, which makes every node that
does not support it halt with "server blocked".

## 1. Assets

| # | Asset | What it is | Why it matters |
|---|-------|-----------|----------------|
| A-1 | Validator secp256k1 signing keys | The 66 validator keys in the VHS validator set; each signs validations | One broken key = one forged vote (T-01) |
| A-2 | Validator master keys (manifests) | The manifest master key for each validator; authorises ephemeral keys and revocation | A broken master key lets the attacker rotate the validator's key or revoke it (T-05) |
| A-3 | The amendment table | The per-node map of amendment id → state (supported / enabled / vetoed / majority time) | Corrupting it changes what a node votes for and enables |
| A-4 | The validated ledger's amendment record | `sfAmendments` (enabled set) and `sfMajorities` (majority timestamps) in the ledger's amendment entry | The ledger — not any single node — is the authority on majorities and enablement |
| A-5 | The 2-week hold | `defaultAmendmentMajorityTime` = 2 weeks of continuous majority before activation | The only time-based defence in the process; it cannot be shortcut by votes alone |
| A-6 | The veto | A local, admin-only, per-node refusal to vote for an amendment | The only per-node defence against a network majority |
| A-7 | The UNL / trust set | Each node's trusted validator list (25 in the live UNL) and its quorum (17) | A node's view of "majority" is computed over its own trust set, not the whole network |

## 2. Trust boundaries

1. **Ledger vs node.** The validated ledger is the authority on which
   amendments are enabled and which hold a majority
   (`getEnabledAmendments` / `getMajorityAmendments`,
   `src/libxrpl/ledger/View.cpp`, lines 1017–1046). A node's local
   amendment table is only its own view; it cannot enable an amendment
   by itself.
2. **Trusted vs untrusted validators.** Only validations from validators
   in the node's trust set are counted (`TrustedVotes::recordVotes`,
   `src/xrpld/app/misc/detail/AmendmentTable.cpp`, lines 153–265: votes
   from untrusted keys are ignored). A forged validation from a key
   outside the trust set is worthless.
3. **Admin vs public RPC.** Vote counts, thresholds, and vetoes are
   admin-only: `injectJson` reveals `count` / `validations` /
   `threshold` only when `isAdmin`
   (`src/xrpld/app/misc/detail/AmendmentTable.cpp`, lines 1019–1029),
   and vetoing requires admin (`src/xrpld/rpc/handlers/Feature1.cpp`,
   lines 84–92). The public `feature` call used by the live probe
   returns only enabled/supported/majority.
4. **Consensus vs application.** Amendment pseudo-transactions are
   injected only when the node is proposing and the previous ledger was
   a flag ledger, and only if the trusted validations for that ledger
   reach the node's quorum (`src/xrpld/app/consensus/RCLConsensus.cpp`,
   lines 357–385; gate at line 371). A forged vote that never reaches
   a proposing node's quorum never becomes a pseudo-transaction.
5. **Validation vs transaction signatures.** Validations are signed
   with secp256k1 keys only (`include/xrpl/protocol/STValidation.h`,
   lines 249–250, signing gate; lines 201–209, deserialization gate).
   Transaction keys (Ed25519 or secp256k1) are a different key space:
   breaking an account key buys no amendment vote.

## 3. Attacker model

The adversary is a **harvest-now, decrypt-later quantum adversary**:

- **Harvest now.** Every validation ever gossiped is public and
  permanent in the sense that its signature and public key are visible
  on the wire and in the VHS record. The adversary is assumed to have
  recorded all of them. Validations are not recorded in ledgers
  (in-memory only: `src/xrpld/consensus/Validations.h`, lines 306 and
  315–323), so the harvest is of live gossip, not of ledger history.
- **Decrypt later.** At some future point the adversary can forge
  secp256k1 signatures for keys whose public keys it has harvested.
  The model assumes the break is **total per key** (a broken key is
  fully forgeable) and **selective** (the adversary breaks k keys of
  its choosing, not all keys at once). The number k is the parameter
  of every attack path in `attack_trees.md`.
- **No protocol break assumed.** The adversary does not break SHA-256,
  SHA-512Half, or the ledger hash chain, and does not control the
  network's clocks. A forged validation must still carry a valid
  signature, the right ledger hash and sequence, and a key in the
  victim node's trust set — otherwise it is dropped before counting.
- **No physical compromise assumed.** The adversary does not steal keys
  from disk, does not compromise node operators, and does not control
  the admin RPC. Attacks that need operator credentials are out of
  scope (see `assumptions.md`).

## 4. The amendment pipeline (what is being attacked)

1. **Desire.** Each node computes the amendments it supports and does
   not veto, and attaches them as `sfAmendments` to its own validation
   (`AmendmentTableImpl::doValidation`,
   `src/xrpld/app/misc/detail/AmendmentTable.cpp`, lines 813–837;
   attached in `src/xrpld/app/consensus/RCLConsensus.cpp`, lines
   903–915). The desired list is a function of the node's compiled-in
   supported set (`detail::supportedAmendments()`,
   `src/libxrpl/protocol/Feature.cpp`, lines 203–207) minus vetoes.
2. **Vote.** Every flag ledger, each proposing node tallies the trusted
   validations for the previous ledger (`TrustedVotes::getVotes`,
   lines 267–285) and computes the threshold
   (`AmendmentSet::computeThreshold`, lines 326–342): with
   `fixAmendmentMajorityCalc` enabled, threshold =
   floor(trusted × 67 / 100) and a majority needs votes **strictly
   greater** than the threshold (lines 371–376).
3. **Majority signal.** If validators say yes and the ledger says no
   majority yet, the node emits a `ttAMENDMENT` pseudo-transaction
   with the `tfGotMajority` flag (`doVoting`, lines 847–933; flag set
   at lines 902–908). If validators say no and the ledger says
   majority, it emits `tfLostMajority` (lines 910–914). The
   pseudo-transaction is injected into the consensus position
   (`src/xrpld/app/misc/AmendmentTable.h`, lines 148–180).
4. **Recording.** When the pseudo-transaction applies, the ledger's
   amendment entry records the majority with the parent close time
   (`Change::applyAmendment`,
   `src/xrpld/app/tx/detail/Change.cpp`, lines 286–375; majority
   recorded at lines 340–352).
5. **Hold.** The amendment must hold its majority for
   `defaultAmendmentMajorityTime` = 2 weeks
   (`include/xrpl/protocol/SystemParameters.h`, line 88). Only then,
   at a flag ledger, does `doVoting` emit a no-flag pseudo-transaction
   (lines 916–923) whose application enables the amendment
   (`Change.cpp`, lines 355–370) and calls `AmendmentTable::enable`
   (lines 762–781).
6. **Veto.** At any point before enablement, a node operator can veto
   an amendment (admin RPC `feature` with `vetoed: true`,
   `Feature1.cpp`, lines 84–92; `veto()` /
   `persistVote()`, `AmendmentTable.cpp`, lines 723–761). A vetoed
   amendment is never in that node's desired list, so the node never
   votes for it — but a veto is local: it changes one node's vote, not
   the network's tally.

## 5. Attack paths (summary)

Full trees with AND/OR structure are in `attack_trees.md`; quantified
analysis is in `attack_analysis.md`. The paths, with the minimum broken
keys k needed at full participation (66 trusted validations):

| # | Path | k to succeed (67%) | k to succeed (80%) | Verdict |
|---|------|--------------------|--------------------|---------|
| T-01 | Forge one validator's vote | 1 key = 1 vote | 1 key = 1 vote | Enables nothing alone |
| T-02 | Force an amendment to majority | **45** | 53 | The headline attack; needs a large break |
| T-03 | Block a unanimous yes vote | **22** | 14 | 67% makes blocking *harder* than 80% |
| T-04 | Shortcut the 2-week hold | — (not possible by votes) | — | Structurally blocked |
| T-05 | Forge a majority for an unsupported amendment | 45 | 53 | Cheapest *effect*: halts unsupported nodes |
| T-06 | Forge a manifest / revoke a master key | 1 master key | 1 master key | Kills one validator (DoS), buys no vote |
| T-07 | Replay or reorder validations | — (not possible) | — | Bound to ledger hash + sequence |
| T-08 | Abuse the veto | — (admin-only, local) | — | Not remotely reachable |
| T-09 | Collateral: fee / UNL votes | same k as T-02 | same k as T-02 | Same forged validation also votes fees/UNL |

## 6. What the live probe measured

- 101 amendments listed, 64 enabled, 37 not enabled, **0 with a
  majority timestamp** (`feature`, fetch 2026-11-13T23:02:58Z).
- `fixAmendmentMajorityCalc` **enabled** — the 67% strict-greater rule
  is live.
- All 64 enabled amendments share one enablement ledger (86785) and
  one timestamp (2026-02-09T14:31:12Z): the set was enabled together,
  not by successive votes. No amendment has gone through the
  majority → hold → activate path on this network.
- 66 validators (VHS), 25 in the UNL; probed node validation quorum
  **17** (= ceil(25 × 0.67)); 65 of 66 validators have master key ==
  validation key; all 66 use a distinct ephemeral signing key; 1
  validator's master key differs from its validation key.
- 100 sampled ledgers (8025465–8025564): 35 transactions, **0
  amendment pseudo-transactions**; mean close interval 3.03 s.
- The probed node validates with its master key directly (manifest
  ephemeral key == master key, `n9K4Aom…`); it does not appear in the
  VHS validator list.
