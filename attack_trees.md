# Attack Trees for the PFTL Amendment Process

Notation: leaves are numbered L-x. `AND` means all children are needed;
`OR` means any child suffices. `k` = number of validator keys the
adversary has broken (forged secp256k1 signatures for). All thresholds
assume `fixAmendmentMajorityCalc` is enabled (it is, live — see M-05)
and full participation unless stated. Numbers are from
`results/attack_path_counts.csv`.

## T-01 — Forge one validator's amendment vote

Goal: cast a vote for an arbitrary amendment as validator V.

- L-1.1: Break V's secp256k1 validation key (harvested public key
  `sfSigningPubKey`, forged `sfSignature` over the `VAL`-prefixed
  signing hash). Evidence: `STValidation.h:249-250` (secp256k1-only),
  `STValidation.cpp:123-146` (`isValid` / `verifyDigest`).
- L-1.2: V must be in the victim node's trust set, or the vote is
  ignored. Evidence: `AmendmentTable.cpp:153-265` (`recordVotes`
  ignores untrusted keys).
- L-1.3: The forged validation must carry the right ledger hash and
  sequence, or it counts for the wrong ledger. Evidence:
  `STValidation.cpp:61-86` (`sfLedgerHash`, `sfLedgerSequence`
  REQUIRED), `Validations.h` sequence enforcement.
- Result: 1 vote. Enables nothing alone — see T-02 for the count
  needed.

## T-02 — Force an amendment to a majority (the headline attack)

Goal: make the network record a majority for amendment X, then activate
it after the 2-week hold.

- AND:
  - L-2.1: Break k validator keys (T-01 per key).
  - L-2.2: k >= force threshold for the trusted set counted by the
    proposing nodes: **45 of 66** at full participation (threshold
    floor(66 x 67/100) = 44, majority needs votes > 44).
    Evidence: `AmendmentTable.cpp:326-342` (`computeThreshold`),
    `371-376` (strict `>` after the fix),
    `SystemParameters.h:85` (67/100).
  - L-2.3: Sustain the forged votes across flag ledgers until the
    majority is recorded in a validated ledger (the tally is
    re-computed every flag ledger from the latest trusted validations;
    stale votes expire — `recordVotes` timeout handling,
    `AmendmentTable.cpp:219-265`).
  - L-2.4: Wait out the 2-week hold (A-5). The hold is enforced by
    code, not by votes — see T-04.
- Result: X is enabled network-wide after the hold. Cost at full
  participation: 45 broken keys (53 under the upstream 80% rule).
  Under partial participation the number falls: 34 of 50, 27 of 40,
  21 of 30, 17 of 25 (UNL), 12 of 17 (probed node's quorum) — see
  `results/attack_path_counts.csv`. The attacker does not choose the
  participation level; it is set by how many validators are actually
  voting.

## T-03 — Block a legitimate amendment majority

Goal: prevent amendment X from gaining a majority although honest
validators vote yes.

- AND:
  - L-3.1: Break (or silence) enough yes-voting keys that the yes
    count falls to the threshold or below: **22 of 66** at full
    participation (66 - 44), 14 under the upstream 80% rule
    (66 - 52). Evidence: same threshold code as T-02.
  - L-3.2: Keep them suppressed for the whole voting window (votes
    are re-tallied every flag ledger from fresh validations).
- Result: X never gains a majority. Note the asymmetry with T-02: the
  67% rule makes forcing easier (45 vs 53) and blocking harder
  (22 vs 14) than the upstream 80% rule. A quantum adversary that
  can break keys finds it cheaper to *push* an amendment through
  than to *stop* one.

## T-04 — Shortcut the 2-week hold (activation without waiting)

Goal: enable X without holding a majority for two weeks.

- OR (either branch must succeed; both are structurally blocked):
  - L-4.1: Forge the majority timestamp recorded in the ledger's
    amendment entry (`sfMajorities`). BLOCKED: the timestamp is
    written by `Change::applyAmendment` when a `tfGotMajority`
    pseudo-transaction applies (`Change.cpp:340-352`), and the
    pseudo-transaction must be in a validated ledger, which requires
    consensus. Forging a validation cannot write to the ledger.
  - L-4.2: Make `doVoting` emit the no-flag (enable) pseudo-transaction
    early. BLOCKED: the branch requires `hasLedgerMajority &&
    (majorityTime + majorityTime_) <= closeTime`
    (`AmendmentTable.cpp:916-923`), and `majorityTime` comes from the
    ledger (`getMajorityAmendments`, `View.cpp:1028-1046`), not from
    any vote.
- Result: not possible by vote forgery alone. The hold is the one
  part of the process that signatures cannot move.

## T-05 — Forge a majority for an UNSUPPORTED amendment (halt attack)

Goal: make nodes that do not support amendment Y halt with
"server blocked".

- AND:
  - L-5.1: Same as T-02 (45 of 66 broken keys) but for an amendment
    the target nodes do not support.
  - L-5.2: The majority is recorded and the amendment is enabled
    (`Change.cpp:355-370`): `enable()` logs "Unsupported amendment
    activated" and `setAmendmentBlocked()` halts the server
    (`Change.cpp:364-368`).
- Result: every node that does not support Y stops. This is the
  cheapest *effect* per broken key in the whole model: the attacker
  does not need the amendment to be useful, only to be unsupported
  by the victims. The live table has 37 not-enabled amendments, of
  which the two PostFiat-specific ones (`PF_ValidatorVoteTracking`,
  `PF_AccountExclusion`) are supported-but-not-enabled — a forged
  majority for either would activate a PostFiat feature the network
  has not adopted, on top of the halt risk for any node whose build
  lacks it.

## T-06 — Forge a manifest / revoke a validator's master key

Goal: take one validator out of the network (denial of service), or
take over its identity.

- OR:
  - L-6.1: Break the validator's master key, issue a new manifest
    with an attacker-chosen ephemeral key. The manifest is verified
    by two signatures (ephemeral + master),
    `Manifest.cpp:196-213`. Cost: 1 broken master key.
  - L-6.2: Break the master key and publish a revocation manifest
    (sequence `0xFFFFFFFF`), permanently revoking the master key,
    `Manifest.cpp:226-240`. Cost: 1 broken master key.
- Result: one validator silenced or impersonated. Buys no amendment
  vote by itself — a manifest does not vote — but it removes one
  honest vote from the tally, which lowers the T-02/T-03 counts by
  one for that validator. Note the live asymmetry: 65 of 66
  validators have master key == validation key, so for them the
  "validation key" and the "master key" are the same key — breaking
  it breaks both the vote and the manifest. The probed node is the
  extreme case: its manifest ephemeral key equals its master key.

## T-07 — Replay or reorder validations

Goal: reuse an honest validation (or a forged one) across ledgers, or
reorder votes to change the outcome.

- BLOCKED (both branches):
  - L-7.1: Replay across ledgers fails because the signing hash covers
    the ledger hash and sequence (`STValidation::getSigningHash`,
    `HashPrefix::validation`, `HashPrefix.h:78`; `sfLedgerHash` /
    `sfLedgerSequence` REQUIRED, `STValidation.cpp:61-86`).
  - L-7.2: Reordering does not change the tally: votes are counted
    from a set keyed by validator (`TrustedVotes::getVotes`,
    `AmendmentTable.cpp:267-285` — a hash map summed per amendment),
    and `Validations` enforces the largest-sequence invariant per
    validator (`Validations.h:309-312`, `SeqEnforcer`). Order
    independence of the vote tally was also the subject of a
    dedicated regression test in the amendment-vote work; it is not
    re-verified here (see `assumptions.md` A13).
- Result: not possible. The vote tally is a set function, not a
  sequence function.

## T-08 — Abuse the veto

Goal: force a node to stop voting for an amendment (or force it to
vote for one).

- BLOCKED: vetoing is an admin-only RPC action
  (`Feature1.cpp:78-87`) persisted in the node's wallet database
  (`AmendmentTable.cpp:723-761`). It is not reachable by forging a
  signature, and it is local: a veto changes one node's desired
  list, never the network tally. The quantum adversary has no path
  here without operator credentials, which are out of scope.

## T-09 — Collateral: fee votes and UNL votes

Goal: use the same broken validation keys to move fee votes or
negative-UNL votes.

- The same forged validation that carries an amendment vote is also
  the vehicle for fee votes (`FeeVote::doVoting`,
  `RCLConsensus.cpp:373`) and negative-UNL votes
  (`nUnlVote_.doVoting`, `RCLConsensus.cpp:385`), both gated on the
  same quorum (`RCLConsensus.cpp:371`). A break of k keys therefore
  buys k fee votes and k UNL votes for free alongside k amendment
  votes. The fee/UNL consequences are not quantified here (no live
  fee-vote or UNL-vote data was collected); the point is that the
  amendment attack does not pay extra for them.
