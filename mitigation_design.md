# Hybrid ML-DSA mitigation design for the PFTL amendment process

How the amendment process moves from secp256k1-only validation
signatures to hybrid classical + ML-DSA signatures, using the threat
model in `threat_model.md` as the starting point. Pinned tree:
postfiatd main commit
`0085a1ff885d6a446369cf73a4430f75af22be55`. Every file:line citation
below was read in that tree. Every number is labelled **measured**
(from the live probe in this pack, `results/summary.json`),
**derived** (arithmetic from the sibling packs' published numbers —
the source file is named), or **published-estimate** (from a cited
external standard or benchmark, not measured on this network).

## 0. What is being mitigated

The threat model establishes that amendment voting is a threshold
game over secp256k1 signatures under a live 67% rule
(`include/xrpl/protocol/SystemParameters.h:85`) with a 2-week
majority hold (`include/xrpl/protocol/SystemParameters.h:88`). At full participation
(N=66, measured) forcing an amendment to a majority takes 45 broken
validator keys and blocking a unanimous yes vote takes 22
(measured, `results/attack_path_counts.csv`). The cheapest effect
per broken key is forging a majority for an **unsupported**
amendment: the enable branch logs "Unsupported amendment activated:
server blocked" and halts the node
(`src/xrpld/app/tx/detail/Change.cpp:364-368`), and the halt is
re-checked at every ledger close
(`src/xrpld/app/ledger/detail/LedgerMaster.cpp:309-314`).

This design removes the single-scheme dependency. After it, a
quantum adversary that breaks secp256k1 alone can forge the
classical half of a validation but not the ML-DSA half, so a forged
validation fails verification on upgraded nodes. The design does not
change the threshold game itself: the numbers 45 and 22 stay what
they are, but the cost of breaking one key changes from "break
secp256k1" to "break secp256k1 **and** ML-DSA-65".

Two measured facts shape the design:

- 65 of 66 validators have master key == validation key, and all 66
  use a distinct ephemeral signing key (measured,
  `results/summary.json`, validators block). For 65 validators the
  public key already harvested from the wire **is** the master public
  key, so rotating the ephemeral signing key alone does not remove
  the quantum exposure of the manifest authority. The master key
  migrates later (§2.5); the signing key migrates first because it
  is the key that votes.
- No amendment currently holds a majority and none has gone through
  the majority → hold → activate path on this network (measured: 0
  with a majority timestamp; all 64 enabled amendments enabled at a
  single ledger, 86785). The amendment machinery that this design
  relies on for activation is therefore unexercised live, which is
  why §3 puts a soak period before the activation amendment is
  proposed.

## 1. Hybrid classical + ML-DSA validation signatures

### 1.1 Parameter choice: ML-DSA-65

FIPS 204 defines three parameter sets (published-estimate, FIPS 204
Table 2):

| Set | Category | Public key | Private key | Signature |
|-----|----------|-----------|-------------|-----------|
| ML-DSA-44 | 2 | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | 3 | 1,952 B | 4,032 B | 3,309 B |
| ML-DSA-87 | 5 | 2,592 B | 4,896 B | 4,627 B |

**ML-DSA-65 is the migration target.** It is NIST's
general-purpose default and the middle of the cost range.
ML-DSA-44 matches the classical security level the network already
has and lands the migration on the minimum; ML-DSA-87 costs 33%
larger keys and 40% larger signatures for a security level the
consensus path does not need — a validation is useful for one
ledger close, a few seconds (measured mean close interval 3.03 s).
ML-DSA-65 key generation takes a 32-byte random seed
(FIPS 204 §6), so the existing 32-byte-seed backup practice for
classical keys carries over, with the parameter set recorded
alongside the seed.

Classical baseline for comparison (published-estimate): secp256k1
public key 33 B, signature 72 B maximum (DER-encoded).

### 1.2 Dual-sign design

Each validation carries **two** signatures over the same signing
hash:

1. The classical secp256k1 signature in the existing `sfSignature`
   field, verified exactly as today.
2. An ML-DSA-65 signature in a new field, verified by upgraded
   nodes only.

Verification policy by node version during the dual phase:

- Old nodes verify the classical signature and ignore the new
  field. They keep counting the validator toward quorum.
- New nodes verify **both** signatures and reject the validation if
  either fails. A validation with a forged classical half fails on
  both; a validation with a forged ML-DSA half fails on new nodes
  only.

The same dual structure applies to proposals (which carry the same
signing hash and the same 72-byte cap problem, §1.4). The vote
itself rides inside the validation, so a dual-signed validation is
a dual-signed amendment vote: the migration bootstraps its own
evidence.

What the second signature must be bound to: the same signing hash
as the classical signature, so that a valid pair cannot be split
across two different validations. Whether the proposal
suppression ID is computed over the classical signature only or
over both signatures is UNVERIFIED as a design decision (see §6,
open question OQ-3): including the second signature makes old and
new nodes compute different suppression IDs for the same proposal;
excluding it leaves the second signature outside the suppression
key. The choice needs an explicit decision and a test before the
dual phase ships.

### 1.3 Sizes and costs at N=66

All figures below are **derived** from the consensus-signature
migration pack (`results/cost_impact.json`, model `cost_model.py`),
which models N=66 validators, 2 proposal rounds per ledger, and a
4 s ledger close — 198 signature verifications per ledger per node
(66 validations + 132 proposals). Per-ledger, per-node:

| Scenario | Verify CPU | % of 4 s close | Crypto bytes / ledger |
|----------|-----------|----------------|----------------------|
| Classical (secp256k1) | 18.83 ms | 0.47% | 20,790 B (20.3 KiB) |
| ML-DSA-65 | 9.39 ms | 0.23% | 1,041,678 B (1,017.3 KiB) |
| Dual (classical + ML-DSA-65) | 28.22 ms | 0.71% | 1,062,468 B (1,037.6 KiB) |

Per day per node (21,600 ledgers/day at a 4 s close, derived from
the same model):

| Scenario | Crypto bytes / day |
|----------|-------------------|
| Classical | 0.45 GB |
| ML-DSA-65 | 22.5 GB |
| Dual | 22.9 GB |

Verify times used by the model are **published-estimate**
benchmarks, not local measurements: secp256k1 95.1 µs and
ML-DSA-65 47.43 µs per verify. Signing times, also
published-estimate: secp256k1 53.6 µs, ML-DSA-65 126.38 µs per
sign, so a dual-signed validation costs the signing validator
≈ 180 µs of signing CPU (derived: 53.6 + 126.38). No ML-DSA
implementation was available on the machine that built the sibling
pack (OpenSSL 3.0.13 lists no ML-DSA algorithm), so no local
ML-DSA timing exists.

Re-scaled to the **measured** mean close interval of 3.03 s
(measured, this pack, 100 ledgers): ≈ 28,515 ledgers/day, giving
derived per-day costs of 0.59 GB classical, 29.7 GB ML-DSA-65,
30.3 GB dual, and CPU shares of 0.62% / 0.31% / 0.93% of the close
interval. The 4 s model numbers are the primary figures; the 3.03 s
figures are the same model re-scaled to the measured close.

Three consequences:

1. **CPU is not the bottleneck.** ML-DSA verification is faster
   than secp256k1 verification in both published sources, so even
   the dual phase costs under 1% of a ledger close. No
   consensus-timing change is needed.
2. **Bandwidth is the cost.** ML-DSA-65 carries ≈ 50× the
   signature-related bytes of classical per ledger. Operators must
   provision for ≈ 23–30 GB/day/node of signature-related traffic
   during the dual phase, against ≈ 0.45–0.59 GB/day today.
3. **Storage is not the cost.** Validations are ephemeral — they are
   not stored as ledger objects — so the size growth is bandwidth
   plus in-memory validation cache, not permanent ledger storage.
   The durable on-disk cost of this migration is ≈ zero. Manifests
   are the only durable objects that grow (§1.5).

### 1.4 What changes in the validation format and the proposal cap

Four code changes, all in the pinned tree, all verified by reading:

1. **Key-type dispatch.** `KeyType` has only `secp256k1` and
   `ed25519` (`include/xrpl/protocol/KeyType.h:28-31`). Add an
   ML-DSA entry, and teach the length-based `publicKeyType()`
   dispatch to recognise a 1,952-byte ML-DSA-65 public key. The
   encoding of the new key type (new prefix byte vs length rule vs
   explicit type field) is UNVERIFIED as a design decision (see §6,
   OQ-1).
2. **Validation signing gate.** Validations are gated to secp256k1
   in two places: the signing constructor
   (`include/xrpl/protocol/STValidation.h:249-250`,
   `LogicError("We can only use secp256k1 keys for signing
   validations")`) and the deserialization gate
   (`include/xrpl/protocol/STValidation.h:201-209`, which throws on a non-secp256k1
   signing public key). Both need an ML-DSA branch, and the
   validation format needs a second signature field for the ML-DSA
   signature. The classical `sfSignature` field is untouched, so
   old nodes parse dual-signed validations exactly as before —
   **provided** old nodes ignore unknown fields on deserialization,
   which is UNVERIFIED (see §6, OQ-2). If old nodes reject unknown
   fields, the dual phase forks the network instead of migrating
   it; this must be confirmed by reading the deserializer before
   any dual-signed validation ships.
3. **The 72-byte proposal cap.** Proposals store their signature in
   a fixed 72-byte buffer
   (`src/xrpld/app/consensus/RCLCxPeerPos.h:110`,
   `boost::container::static_vector<std::uint8_t, 72>`), enforced by
   a constructor assertion
   (`src/xrpld/app/consensus/RCLCxPeerPos.cpp:37-44`, "The maximum
   allowed size of a signature is 72 bytes") and by an inbound size
   check that rejects any proposal signature outside 64–72 bytes
   (`src/xrpld/overlay/detail/PeerImp.cpp:1791-1799`, "A DER encoded
   signature can't be longer than 72 bytes"). All three must be
   lifted before any ML-DSA proposal can flow — to a size that fits
   the largest ML-DSA signature plus headroom (8 KiB covers
   ML-DSA-87 at 4,627 B). Lift the caps **before** any ML-DSA
   signature exists on the network: the change is inert while all
   signatures are still classical, and it removes the hardest
   blocker early. The 8 KiB figure is a design choice, not a
   measured limit.
4. **Shared signing primitives.** All consensus-path signing and
   verification passes through `sign()` / `verify()` /
   `signDigest()` / `verifyDigest()`. The ML-DSA branch must be
   additive: transaction signature verification shares these
   primitives, so the classical branches stay untouched. The pinned
   OpenSSL is 1.1.1w, which has no ML-DSA (ML-DSA arrived in
   OpenSSL 3.5); upgrading the pinned OpenSSL to 3.5 or later is
   the gating prerequisite, a build-system change, not a protocol
   change.

### 1.5 Manifests

A dual-key manifest vouches for both signing keys under the same
master key. Manifest sizes (derived, sibling migration pack
`results/cost_impact.json`, manifests table): classical 177 B of
signature-related material; dual (classical + ML-DSA-65) 8,747 B
as modelled. That modelled figure assumes the master signature is
also ML-DSA. This design keeps the classical master key (§2.5), so
the corrected dual-manifest size is **5,366 B** (derived: 1,985 B
public keys + 3,309 B ML-DSA ephemeral signature + 72 B classical
master signature). Manifests are published once per rotation, not
per ledger, so this is a one-off cost per validator per rotation,
not a recurring cost.

### 1.6 What stays unchanged

- **Quorum and amendment thresholds.** Vote counting is
  scheme-agnostic: it counts validators, not signature schemes.
  Validation quorum stays 45 of 66 and the amendment minimum stays
  45 of 66 under the live 67% rule (measured; quorum formula
  `max(ceil(UNL × 0.67), ceil(UNL × 0.6))`,
  `src/xrpld/app/misc/detail/ValidatorList.cpp:1933-1934`). The
  67% rule is deliberate for this network, with the in-tree comment
  noting upstream uses 80% and that mainnet should revert to 80%
  (`src/xrpld/app/misc/detail/ValidatorList.cpp:1898-1900`).
- **The 2-week hold.** `defaultAmendmentMajorityTime` stays 2 weeks
  (`include/xrpl/protocol/SystemParameters.h:88`); the hold branch stays
  `majorityTime + 2 weeks <= closeTime`
  (`src/xrpld/app/misc/detail/AmendmentTable.cpp:916-923`).
- **Threshold arithmetic.** `computeThreshold`
  (`src/xrpld/app/misc/detail/AmendmentTable.cpp:326-342`) and the strict-`>` majority test
  after the fix (`src/xrpld/app/misc/detail/AmendmentTable.cpp:368-376`) are untouched.
- **The ledger as authority.** Enabled amendments and majority
  timestamps are read from the validated ledger's amendment entry
  (`src/libxrpl/ledger/View.cpp:1017-1046`), not from any node's
  local table. The amendment pseudo-transaction gate — injected
  only when trusted validations reach the node's quorum
  (`src/xrpld/app/consensus/RCLConsensus.cpp:371`) — is untouched.
- **The veto.** The per-node, admin-only veto
  (`src/xrpld/rpc/handlers/Feature1.cpp:78-87`;
  `src/xrpld/app/misc/detail/AmendmentTable.cpp:723-761`) is unchanged and remains the
  per-node defence (§4.3).

## 2. Key rotation and revocation procedures

### 2.1 The two keys, and which one rotates

A validator has a **master key** (permanent identity, signs
manifests, never signs validations) and an **ephemeral signing key**
(signs validations), bound by a **manifest**: master public key,
ephemeral signing public key, sequence number, optional domain, and
signatures from both keys
(`src/xrpld/app/misc/Manifest.h:30-79`). The manifest is verified by
two signatures (`src/xrpld/app/misc/detail/Manifest.cpp:196-213`).
`ManifestCache` stores, per trusted validator, the most senior
valid manifest it has seen (`src/xrpld/app/misc/Manifest.h:294`), and a manifest with
a sequence number less than or equal to the stored one is rejected
(`src/xrpld/app/misc/detail/Manifest.cpp:411`).

Key material is loaded in exactly one of two configuration forms
(`src/xrpld/app/misc/detail/ValidatorKeys.cpp:40-95`):

- `[validator_token]` — a base64 manifest plus a validation secret.
  The derived secp256k1 public key must equal the manifest's
  signing key or the node fails to start (`src/xrpld/app/misc/detail/ValidatorKeys.cpp:59`).
  This is the form that supports rotation.
- `[validation_seed]` — a base58 seed from which the same key is
  used as both master and signing key
  (`src/xrpld/app/misc/detail/ValidatorKeys.cpp:86`, `keys.emplace(pk, pk, sk)`, sequence 0).
  There is no manifest and **no rotation path**: rotating the key
  changes the validator identity. Any validator still on the seed
  form must migrate to the token form before it can rotate.

### 2.2 Rotating a signing key without changing the master key

1. Generate the new signing key pair and a new manifest **offline**
   with the master key, sequence = old sequence + 1. The master key
   never leaves the offline machine.
2. Publish the new manifest to the validator-list site / gossip
   network **at least 7 days before** activating it, and verify it
   is visible on peers before proceeding. The validator keeps
   signing with the old key in the meantime, because it has not
   restarted with the new token.
3. Restart the validator with the new `[validator_token]`. From
   that moment it signs only with the new key, which peers already
   trust.
4. Confirm the validator's validations are accepted before the next
   batch rotates.

The 7-day overlap is an operational procedure, not a protocol
feature: the pinned code has no dual-signing state — a manifest
carries exactly one signing key, and a higher-sequence manifest
supersedes the old key as soon as a peer sees it. The rotation
schedule (derived, validator key lifecycle pack,
`results/simulation_summary.json`, 56 simulated days, N=66) staggers
rotation in weekly batches of ~1/8 of the validators (9 of 66 per
week), completing a full set rotation in 8 weeks. With a 7-day
overlap the simulation shows **zero** days without a trusted key
even if propagation takes 7 days; with no overlap, a 2-day
propagation delay leaves each rotating validator without a trusted
key for 2 days. A single bad batch (9 validators) leaves 57
signing validators: margin 12 above the 45 quorum at the 67% rule,
margin 4 at the 80% rule. A 7-day single-validator outage leaves
quorum intact with margin 20 at 67% and 12 at 80% (derived, same
simulation). The in-tree guide recommends rotating the signing key
every 6–12 months, and immediately on suspected compromise, on
hardware moves, and on domain changes.

Signing-key rollback is the same operation as a rotation: publish
a new manifest with a higher sequence number reinstating the
previous signing key (or a fresh one). There is no "undo" — only a
forward sequence number. Sequence numbers are effectively
inexhaustible for this purpose: at most 4,294,967,293 tokens per
master key pair (derived, key lifecycle pack).

### 2.3 Revocation

A master key is revoked by a manifest with sequence number
`0xFFFFFFFF` (the maximum `uint32_t`), carrying no signing key
(`src/xrpld/app/misc/detail/Manifest.cpp:226-240`; `src/xrpld/app/misc/Manifest.h:67-79`). Revocation manifests
are loaded from `[validator_key_revocation]` and received as gossip
from peers. Once peers see it, no validation from that master key
is accepted, and **no further manifest for that master key is ever
accepted**, because no higher sequence number exists — the identity
is permanently dead. Recovery means creating a new validator
identity (new master key) and getting it added to UNL publisher
lists; that is a coordination task, not a key operation. Revocation
is the response to a compromised **master** key. A compromised
**signing** key alone is handled by rotation (§2.2), not
revocation, because the master key is still safe.

### 2.4 UNL update procedure

Trust is distributed through validator-list sites, fetched on a
5-minute default refresh interval with a 30-second retry on error
(`src/xrpld/app/misc/detail/ValidatorSite.cpp:34-35`). Adding or
removing a validator from the trusted set is therefore a publisher
operation, not a protocol operation:

- To add a validator (including a new identity after a revocation):
  the UNL publisher adds the validator's master public key to its
  list; nodes pick it up on the next fetch, minutes later in the
  normal case.
- To remove a validator: the publisher removes the key; removal
  propagates on the next list fetch. The negative-UNL protocol can
  also exclude a validator from the effective UNL; the absolute
  minimum quorum floor is 60% of the original UNL size, so
  exclusion never drops the quorum below that floor (derived,
  compromise runbook, key lifecycle pack).
- Multi-day propagation delays are stress cases (validator-list
  site outage, partition), not the normal case. The rotation
  schedule in §2.2 is built on the 5-minute baseline.

### 2.5 In-flight votes during rotation

- A validator's amendment vote is its desired list — the amendments
  it supports, does not veto, and that are not already enabled
  (`src/xrpld/app/misc/detail/AmendmentTable.cpp:813-837`) — attached to its validation.
  Rotation changes the validator's **key**, not its desired list,
  so a rotating validator votes the same way before and after.
- Votes expire 24 hours after a validator's last validation
  (`src/xrpld/app/misc/detail/AmendmentTable.cpp:167-172`, `expiresAfter = 24h`). A validator
  offline for a full day has no live amendment vote. A validator
  that restarts with a new key resumes voting as soon as peers
  trust the new manifest; its recorded vote in the meantime is the
  stale one, expiring after 24 hours.
- While a higher-sequence manifest propagates, peers that have seen
  it reject validations signed with the old key (sequence check,
  `src/xrpld/app/misc/detail/Manifest.cpp:411`); peers that have not seen it still accept the
  old key. There is no instant in which a correctly executed
  rotation leaves the validator with **no** trusted key, provided
  the new manifest was published before activation (§2.2, 7-day
  overlap).
- The tally is re-computed every flag ledger from the latest trusted
  validations (`src/xrpld/app/misc/detail/AmendmentTable.cpp:153-265`, trust filter), and
  `doVoting` runs only when trusted validations reach the node's
  quorum (`src/xrpld/app/consensus/RCLConsensus.cpp:371`). A rotation batch of 9 cannot
  move the tally by more than 9 votes, and cannot break quorum
  (§2.2 margins).
- During the dual-sign phase (§3, phase 1), a validator mid-rotation
  is either classical-only (old manifest) or dual-signed (new
  manifest). Old nodes count both; new nodes count both, verifying
  whichever signatures are present. The dangerous configuration is
  a validator that drops its classical signature while old nodes
  still need it — that is phase 3, gated behind the activation
  amendment, not a rotation step.

### 2.6 The master key itself

This design migrates the **ephemeral signing key** (the key that
signs validations and proposals). The master key stays classical
secp256k1 through phases 1–3: it signs manifests only, rarely, and
offline. That is a deliberate sequencing choice, not an oversight,
and it has a cost: until the master key migrates, a quantum
adversary that breaks secp256k1 can forge a manifest for any
validator whose master public key it has harvested — which, given
the measured 65-of-66 master == validation key fact (§0), is
nearly every validator. The mitigations are rotation discipline
(§2.2: a forged manifest still needs a higher sequence number than
the operator's last issued one, so sequence monitoring in §5
detects it) and, as a later step, a post-quantum master key. The
conservative choice for the long-lived master key is SLH-DSA
(hash-only security assumption), at 7,856–49,856-byte signatures
(published-estimate, FIPS 205), which are acceptable for the rare
manifest-signing operation. ML-DSA is also a candidate for the
master key. The master-key migration is a separate design with a
separate threat model and is not specified here.

## 3. Phased costs

Phase numbering follows the amendment-process framing: phase 0 is
the inventory this pack completes; phase 1 is dual-sign opt-in;
phase 2 is the activation amendment; phase 3 is classical
retirement. (The sibling consensus-signature migration pack splits
phase 1 into two sub-phases — dual-key manifests, then dual
signatures — and numbers activation as phase 3 and retirement as
phase 4; the costs below are the same, re-numbered.)

Costs are per node unless stated otherwise. Bandwidth is
signature-related bytes (public key + signature) per ledger; CPU is
verification CPU per ledger. All cost figures are **derived** from
the sibling migration pack (`results/cost_impact.json`) at N=66, 2
proposal rounds, 4 s close, unless labelled otherwise.

### Phase 0 — Inventory (done, this pack)

- What it is: the threat model, attack trees, and live probe in
  this pack — threshold arithmetic (45 to force, 22 to block),
  validator-set inventory (66 validators, 25 in UNL), version mix,
  and the finding that the majority → hold → activate path has
  never run live on this network.
- Cost: zero network-visible change. No bandwidth, CPU, or storage
  cost. The inventory is the baseline every later phase is measured
  against.

### Phase 1 — Dual-sign opt-in

- What it is: validators generate an ML-DSA-65 key pair alongside
  their secp256k1 key, publish a dual-key manifest (higher sequence
  number), and start attaching both signatures to every validation
  and proposal. Old nodes verify the classical signature and ignore
  the new field; new nodes verify both. Opt-in is per validator:
  dual-signed validators count toward quorum for old and new nodes
  alike, so this phase costs nothing in quorum terms.
- Prerequisites (no network-visible change): upgrade the pinned
  OpenSSL to 3.5 or later; extend key-type dispatch and the
  signing primitives with an ML-DSA branch; lift the 72-byte
  proposal caps (§1.4); extend the offline `validator-keys` tool
  to generate ML-DSA key pairs and sign ML-DSA manifests.
- Bandwidth: 1,062,468 B/ledger (dual row) vs 20,790 B/ledger
  classical — ≈ 51×. Per day: 22.9 GB vs 0.45 GB at a 4 s close;
  30.3 GB vs 0.59 GB re-scaled to the measured 3.03 s close
  (derived). This is the recurring cost operators must provision
  for.
- CPU: 28.22 ms/ledger verify (0.71% of a 4 s close), vs 18.83 ms
  classical. Signing per validation ≈ 180 µs (derived from
  published-estimate sign times). CPU is not the binding cost.
- Storage: ≈ zero durable growth (validations are ephemeral).
  Manifests grow once per rotation: dual manifest 5,366 B vs
  classical 177 B (derived, §1.5).
- Exit criteria: a majority of validators have published dual-key
  manifests; dual-signed objects are a stable majority of observed
  validations/proposals; no increase in dropped proposals or
  validation failures attributable to the new field. Rollback:
  validators stop attaching the ML-DSA signature (a local
  configuration change); a bad dual-key manifest is replaced by a
  higher-sequence classical-only manifest (§2.2).

### Phase 2 — Activation amendment

- What it is: an amendment that flips verification policy — from
  its activation ledger onward, a validation or proposal from a
  validator with a dual-key manifest is valid **only if** its
  ML-DSA signature verifies. The classical signature may still be
  present but is no longer sufficient on its own.
- Activation uses the existing amendment mechanics, unchanged: the
  amendment needs a majority of trusted validators voting for it —
  **45 of 66** under the live 67% rule (53 under the upstream 80%
  rule; measured) — and must hold that majority for **2 weeks**
  before it enables (`include/xrpl/protocol/SystemParameters.h:85,88`). The 2-week hold
  is the network's notice period: it is the window in which laggard
  operators must upgrade or lose the ability to validate. The
  amendment vote itself rides inside validations, so the vote for
  the migration is itself dual-signed.
- Bandwidth: unchanged from phase 1 during the hold (dual row,
  1,062,468 B/ledger). After activation, validators may stop
  attaching the classical signature: cost drops to the pure
  ML-DSA-65 row, 1,041,678 B/ledger (22.5 GB/day at a 4 s close;
  29.7 GB/day at the measured 3.03 s close).
- CPU: after activation, 9.39 ms/ledger verify (0.23% of a 4 s
  close) — **less** than the classical 18.83 ms, because ML-DSA
  verification is faster than secp256k1 verification in the
  published benchmarks.
- Storage: ≈ zero durable growth.
- Exit criteria: amendment enabled; ML-DSA-only validations are
  accepted; classical-only validations from dual-key validators
  are rejected. Rollback before enablement: veto the amendment
  (§4.3). Rollback after enablement: none through the amendment
  mechanism (§4.1).

### Phase 3 — Classical retirement

- What it is: a second amendment removes the classical signature
  requirement entirely and allows nodes to drop classical
  verification for validators that have migrated. Old
  (pre-migration) nodes can no longer verify any validation or
  proposal and fall out of consensus — by this point that is
  intended, and it is why phases 1–2 give them a dual-signature
  window plus a 2-week amendment hold to upgrade.
- Bandwidth: pure ML-DSA-65 row, 1,041,678 B/ledger (22.5 GB/day at
  a 4 s close). No further reduction is available from this design:
  the ML-DSA signature is the floor.
- CPU: 9.39 ms/ledger verify (0.23% of a 4 s close).
- Storage: manifests may drop the classical signing key at the next
  rotation; an ML-DSA-only manifest with a classical master key is
  5,333 B (derived: 1,952 + 3,309 + 72). The master key itself is a
  separate decision (§2.6).
- Exit criteria: no classical-only validator remains in the trusted
  set; the 72-byte proposal caps and the classical branches in the
  shared primitives are dead code pending removal (removal itself
  is a separate, later change).
- Rollback after enablement: none (§4.1). Forward-only.

### Cost summary

| Phase | Bandwidth / ledger | CPU / ledger | Durable storage |
|-------|-------------------|--------------|-----------------|
| 0 inventory | 20,790 B (classical) | 18.83 ms | — |
| 1 dual-sign opt-in | 1,062,468 B | 28.22 ms | +5,189 B per dual manifest |
| 2 activation (after) | 1,041,678 B | 9.39 ms | — |
| 3 retirement | 1,041,678 B | 9.39 ms | — |

All figures derived from the sibling migration pack at N=66, 2
proposal rounds, 4 s close. The phase-1 bandwidth peak (≈ 51×
classical) is the cost the network pays for the whole dual-sign
window; it is the price of keeping old nodes in consensus while
new nodes gain quantum resistance.

## 4. Rollback notes

### 4.1 After the activation amendment, there is no protocol rollback

An enabled amendment stays enabled. The `enable()` path
(`src/xrpld/app/misc/detail/AmendmentTable.cpp:762-781`) sets `s.enabled = true` and, for an
unsupported amendment, sets `unsupportedEnabled_ = true`
(`src/xrpld/app/misc/detail/AmendmentTable.cpp:776`); there is no production code path that
clears an enabled amendment or clears the blocked flag — the only
related clearing operation, `clearAmendmentWarned()`, clears the
warning flag, not the block. Recovery after a bad activation is
therefore **forward-only**: fix the ML-DSA implementation and ship
a new version, or (extreme) coordinate a validator-set restart.
This is why the 2-week hold and the dual-signature soak in phase 1
must be treated as the real safety net, not the amendment
mechanism. The same applies to phase 3: forward-only.

Rollback is cheap and local until the activation amendment enables,
and effectively unavailable after it:

| Situation | Rollback |
|-----------|----------|
| Phase 0 fails | Nothing shipped; no network impact. |
| Phase 1: bad dual-key manifest | Publish a higher-sequence manifest with only the classical key (§2.2). |
| Phase 1: dual signatures cause failures | Validators stop attaching the ML-DSA signature (local config). Old nodes never depended on it. |
| Phase 2: amendment voted but not yet enabled | Veto it (§4.3). |
| Phase 2: amendment enabled, migration broken | **No protocol rollback.** Fix forward: ship a corrected implementation, or coordinate a validator-set restart. |
| Phase 3 | Same as above: forward-only. |

### 4.2 What happens to nodes that do not support the amendment

When the activation amendment (or any amendment) enables, a node
that does not support it halts. The mechanism is exact, from the
pinned tree:

1. `Change::applyAmendment` enables the amendment and, if the node
   does not support it, logs "Unsupported amendment activated:
   server blocked" and calls `setAmendmentBlocked()`
   (`src/xrpld/app/tx/detail/Change.cpp:353-370`, block at lines 364-368).
2. `setAmendmentBlocked()` sets the blocked flag and drops the node
   to CONNECTED operating mode
   (`src/xrpld/app/misc/NetworkOPs.cpp:1840-1844`).
3. The halt is re-checked at every ledger close: a node with any
   unsupported enabled amendment blocks
   (`src/xrpld/app/ledger/detail/LedgerMaster.cpp:309-314`, via `hasUnsupportedEnabled()`,
   `src/xrpld/app/misc/detail/AmendmentTable.cpp:799-802`).

The same mechanism is the threat model's cheapest attack (T-05):
a forged majority for an unsupported amendment halts every node
that does not support it. The migration does not change this
mechanism; it changes who can forge the majority. During phase 2,
the nodes at risk are exactly the nodes that have not upgraded to
a build supporting the activation amendment — which is why the
2-week hold is the notice period, and why §5 monitors the version
mix.

### 4.3 The veto as the per-node defence

Before enablement, any node operator can veto the activation
amendment (admin RPC `feature` with `vetoed: true`,
`src/xrpld/rpc/handlers/Feature1.cpp:78-87`; `veto()` / `persistVote()`,
`src/xrpld/app/misc/detail/AmendmentTable.cpp:723-761`). A vetoed amendment is never in that
node's desired list (`src/xrpld/app/misc/detail/AmendmentTable.cpp:813-837`, which includes
only amendments with `vote == up`), so the node never votes for
it. A veto is local: it changes one node's vote, not the network's
tally, and it is admin-only — it is not reachable by forging a
signature. The veto is the correct response to an activation
amendment proposed too early (for example, before dual-key manifest
coverage reaches the §5 threshold): veto it, and the amendment
cannot gain a majority from that node's vote. After enablement the
veto is useless — it only affects voting, and voting is over.

### 4.4 Recovering a halted node

A node halted with "server blocked" recovers by restarting with a
build that supports the enabled amendment, so that
`hasUnsupportedEnabled()` returns false at the next ledger close
(`src/xrpld/app/ledger/detail/LedgerMaster.cpp:309-314`). Concretely:

1. Confirm the halt reason in the log ("Unsupported amendment
   activated: server blocked", `src/xrpld/app/tx/detail/Change.cpp:364-368`).
2. Upgrade to a build whose supported-amendment set includes the
   enabled amendment (for the migration, the post-activation
   build).
3. Restart. The node re-joins consensus once its validations verify
   under the new rules; its amendment votes resume from its desired
   list, with the 24-hour vote-expiry rule applying as in §2.5.

There is no configuration flag that un-blocks a node while it still
does not support an enabled amendment. An operator that refuses to
support an enabled amendment cannot rejoin consensus — that is the
intended semantics of the halt, not a bug to work around. If the
amendment itself is the problem (a bad activation), the recovery is
the forward-only path of §4.1, not a per-node unblock.

## 5. Monitoring

Monitor from the ledger (the authority on majorities and
enablement, `src/libxrpl/ledger/View.cpp:1017-1046`) and from the validator set, not
from any single node's local table. Baseline values below are
**measured** in this pack unless labelled otherwise.

### 5.1 What to watch

- **Majority timestamps (`sfMajorities`).** Any amendment gaining a
  majority timestamp starts its 2-week clock. Baseline: 0
  amendments with a majority timestamp (measured). The majority
  timestamp is written by `Change::applyAmendment` when a
  `tfGotMajority` pseudo-transaction applies
  (`src/xrpld/app/tx/detail/Change.cpp:340-352`), and read back by `getMajorityAmendments`
  (`src/libxrpl/ledger/View.cpp:1017-1046`).
- **Enablement ledgers (`sfAmendments`).** Which amendments are
  enabled and at which ledger. Baseline: 64 enabled, all at ledger
  86785 on 2026-02-09T14:31:12Z (measured) — the set was enabled
  together, not by successive votes. Any new enablement ledger is
  an event.
- **Amendment vote counts per flag ledger.** How many trusted
  validations vote for each not-yet-enabled amendment, against the
  live threshold (45 of 66, measured). Vote counts are admin-only
  over RPC (`src/xrpld/app/misc/detail/AmendmentTable.cpp:1019-1029` in the threat model);
  the public `feature` call returns only enabled / supported /
  majority.
- **UNL overlap and effective UNL size.** The quorum comment's
  fork-safety bound depends on pairwise UNL overlap
  (`src/xrpld/app/misc/detail/ValidatorList.cpp:1898-1900`, citing Theorem 8 of the XRP
  Ledger consensus analysis). Baseline: 25 validators in the UNL
  (measured), quorum 17 for that UNL. Watch the effective UNL size
  after negative-UNL exclusions against the 60% absolute-minimum
  quorum floor.
- **Validator version mix.** Baseline (measured): 1.0.0: 2, 1.0.4: 9,
  1.0.8: 1, 1.0.9: 54. The version mix is the direct measure of how
  many nodes can verify ML-DSA signatures and how many would halt
  on an unsupported activation.
- **Dual-key manifest coverage.** How many of the 66 validators
  have published a manifest carrying an ML-DSA signing key. This
  is the phase-1 exit metric and the phase-2 go/no-go metric.
- **Manifest sequence numbers.** A sequence jump above the
  operator's own last issued sequence means someone else used the
  master key (derived, compromise runbook, key lifecycle pack).
  Sequence numbers are the only in-protocol compromise detector
  available — nothing in the pinned code alerts on them
  automatically.
- **Validations from superseded keys.** After a rotation,
  validations signed by the old key should stop; if they continue,
  the old key is in someone else's hands (derived, compromise
  runbook).
- **Hybrid-only validator count.** How many validators have dropped
  their classical signature. Old nodes lose the 67% quorum once 22
  validators are ML-DSA-only (14 under the 80% rule; derived,
  sibling migration pack `results/cost_impact.json`, mixed-network
  table). This count must stay at zero until phase 2 has enabled.

### 5.2 Alert thresholds

| Signal | Threshold | Action |
|--------|-----------|--------|
| Any amendment gains a majority timestamp | Immediate alert | Start the 2-week clock; identify the amendment; check whether it is the activation amendment or an unexpected one. |
| Amendment vote count reaches 40 of 66 (within 5 of the 45 majority) | Warning | Pre-activation review: confirm the amendment is expected and the version mix supports it. |
| Dual-key manifest coverage below 45 of 66 when the activation amendment is proposed | Block the proposal | Do not propose phase 2 until coverage reaches the majority that must vote for it. |
| Hybrid-only validators ≥ 1 before phase 2 enables | Immediate alert | Investigate: no validator should drop classical signatures before activation. |
| Hybrid-only validators ≥ 14 | Critical | Old nodes are at the 80%-rule quorum boundary; halt further classical drops. (Derived break points: 14 at 80%, 22 at 67%.) |
| Any validator's manifest sequence jumps above its operator's last issued sequence | Immediate alert | Suspected master-key compromise; containment per §2.3. |
| Validations observed from a superseded signing key | Immediate alert | Suspected signing-key compromise; rotate per §2.2. |
| Effective UNL size falls below the 60% absolute-minimum quorum floor | Critical | UNL publisher intervention; negative-UNL exclusions have gone too far. |
| Pre-migration builds (no ML-DSA support) still validating after the activation amendment enables | Immediate alert | Those nodes will halt (§4.2); they need the upgrade-and-restart recovery (§4.4). |
| Amendment vote counts flap across flag ledgers | Warning | Check for a validator offline > 24 h (vote expiry, `src/xrpld/app/misc/detail/AmendmentTable.cpp:167-172`) or a manifest transition in progress (§2.5). |
| Per-node signature-related bandwidth exceeds 35 GB/day during the dual phase | Warning | Re-check against the 30.3 GB/day derived figure at the measured 3.03 s close; investigate unexpected proposal rounds or close-time shortening. |

## 6. What this design does not cover, and open questions

- **Account transaction signatures.** Out of scope. They share the
  signing primitives, so they benefit from the phase-0 work, but
  migrating them is a separate design (account keys live in ledger
  state, not in manifests).
- **TLS / peer-overlay transport.** Out of scope. The peer overlay
  authenticates with a secp256k1 node key and a session signature;
  migrating it is a separate design.
- **The master key.** Migrates later (§2.6). Until it does, the
  manifest authority stays classical, and sequence monitoring (§5)
  is the detection layer for a forged manifest.
- **OQ-1 — ML-DSA key encoding (UNVERIFIED).** How is an ML-DSA
  public key recognised and serialised: new prefix byte, length
  rule, or explicit type field? No prefix byte is assigned for
  ML-DSA in any standard verified here; the allocation needs a
  deliberate decision.
- **OQ-2 — Unknown fields in deserialized objects (UNVERIFIED).**
  Phase 1 assumes old nodes ignore a new ML-DSA key field in a
  manifest and a new ML-DSA signature field in a validation. This
  was not verified against `STObject` deserialization in this
  pack or in the sibling migration pack. It must be confirmed by
  reading the deserializer before phase 1 ships: if old nodes
  reject unknown fields, phase 1 forks the network.
- **OQ-3 — Proposal suppression ID (UNVERIFIED).** Whether the
  ML-DSA signature is included in the proposal suppression ID
  (§1.2). Either choice needs an explicit decision and a test.
- **OQ-4 — Parameter set.** ML-DSA-65 is recommended (§1.1), but
  the choice between 44/65/87 is a governance decision, not a
  technical inevitability.
- **OQ-5 — Old-node behaviour on unknown key types
  (UNVERIFIED).** If a manifest carries an ML-DSA key and an old
  node encounters it outside the ignored-field path (for example
  in `ValidatorList` trust logic), does it ignore it, reject the
  manifest, or fail? No such path was found, but the trust path was
  not exhaustively traced.
- **OQ-6 — Validation size vs relay policy (UNVERIFIED).** No upper
  bound on validation size was found in the relay path (only the
  50-byte minimum and the overlay cap), but resource-fee and
  relay-suppression behaviour for ≈ 5 KiB validations was not
  measured. The dual-phase soak in phase 1 is the place to find
  out.
- **OQ-7 — Ledger close-time sensitivity.** The cost model uses a
  4 s close (re-scaled here to the measured 3.03 s). If the live
  network closes faster or runs more proposal rounds under load,
  bandwidth per day rises proportionally; live measurement during
  the phase-1 soak would pin it down.
- **Domain attestation (UNVERIFIED).** Whether PostFiat validator
  operators publish a domain attestation equivalent to upstream
  XRPL's `https://<domain>/.well-known/xrp-ledger.toml`, and under
  what filename, was not verified in the pinned tree. Do not assume
  the filename.

## Sources

- This pack: `threat_model.md`, `attack_trees.md`,
  `claim_evidence_index.md`, `results/summary.json`,
  `results/attack_path_counts.csv` (measured claims; fetch
  2026-11-13T23:02:58Z).
- Validator key lifecycle pack: `key_lifecycle.md`,
  `compromise_runbook.md`, `results/simulation_summary.json`
  (rotation schedule, thresholds, compromise procedures; harness
  `rotation_sim.py`, seed 20261113, N=66, 56 simulated days).
- Consensus-signature migration pack: `migration_design.md`,
  `results/cost_impact.json` (cost model `cost_model.py`; ML-DSA
  sizes from FIPS 204 Table 2; verify/sign times from Karatay 2026
  and the pqc-vc-rust benchmark summary, both published-estimate).
- Pinned source tree: postfiatd main commit
  `0085a1ff885d6a446369cf73a4430f75af22be55`. Every file:line
  citation in this document was read in that tree.
