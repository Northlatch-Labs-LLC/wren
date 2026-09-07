# `sui-contracts-soul` — the employment record of an agentic company

**This directory is the contract running on mainnet.** Package
`0x8d6567ed7bf34d99eefefe745c3a282fd89a12fdcd77e6bd10b19b35b599635f`, module `soul`. A release
build here produces that module's bytes exactly — 9,476 bytes, sha256
`437030125dae2d2bde15239ff0c3df8fe224d2e6fe26009d79116ae52d215ba3` — and
`./check-matches-mainnet.sh --chain` proves it against the live chain rather than asserting it.
Run that after any edit to `sources/`.

It was not always so, and how it failed is worth keeping. Until 2026-09-06 this directory held a
DIFFERENT contract: 50 functions against the chain's 108, settlement under `MasterCap` instead of
`LedgerCap`, a fixed seven-day `EPOCH_MS` instead of the chain's own epoch, and no pausing,
adoption or tiers at all. It was a deliberate reimplementation of the draft that then never
shipped — the draft is what was published — and it compiled, its tests passed, and it was wrong.
Nothing compared it to the chain, so nothing could say so, and a transaction built by reading these
sources would have been built against a contract that does not exist.

The source of truth is now here and only here. `check-matches-mainnet.sh` is what makes "and only
here" checkable instead of hoped for. Everything below describes the contract as deployed.

---

# `northlatch_soul` — the employment record of an agentic company

One Move package. No vault package, no controller package, no market entries, no child mechanism.
It holds **no coin** and moves **no money**. It answers four questions about an agent, on chain:
who it is, what it may spend, who answers for it, and whether there is anything behind it.

Sui Move 2024. Depends on the Sui framework and on nothing else — not on `projectx_social`, not on
any third party. Built and tested on this laptop with `sui 1.78.1`.

---

## What this package cannot do

This section is first on purpose. Everything below it is easier to trust once these four are read.

### 1. It cannot stop a spend that never asks it

`record_spend` enforces the ceiling on every transaction **that calls it**. A payment path that
never calls it is outside this module's reach entirely. This package holds no coin, so it can
refuse nothing that does not ask.

The guarantee is therefore exactly, and only: *no transaction that consults the soul may exceed
the allowance for its epoch.* The adapter that routes an agent's spending through the check is
separate work. It is not written here and nothing here pretends it exists.

**The ceiling is a budget with a public record, not a wall.** That is the council's ruling on
disagreement 2, and the words are theirs. The Security desk's finding — that nothing structurally
forces a spend through `record_spend` — is **kept open**, not answered. Its structural fix belongs
with a vault package, and the vault package is cut (council decision 3). Any page, brief or
console that describes this ceiling must describe it in these terms. Calling it a wall is the
error the council named.

### 2. It cannot see a balance, so it is told one

`settle_epoch` sets the tier from `vault_sui` and `epoch_net_nonneg`, **supplied by the caller**
holding a `LedgerCap`. The soul may not depend on a money package — that is its charter — so it
cannot read a balance, and council decision 6 chose being told over taking the dependency.

The control is publication, not prevention. Both supplied numbers are written into `EpochSettled`
beside the tier they produced, so a wrong one is public on chain within the epoch, and the weekly
finance read is where it is meant to be caught. **A `LedgerCap` holder can set a friendlier tier
than the money justifies.** The council accepted this with the boundary written down and kept the
CISO's objection on the record: nobody has yet proved that anyone reads the event within the
epoch. If the first fortnight shows the finance read is not happening, decision 6 is wrong.

### 3. It cannot check an account's age

`AdoptionRule.min_account_age_epochs` is recorded and is **not enforced by this module**. Account
age is a fact of `projectx_social`, and depending on it is forbidden by this package's charter.
The check happens once, off chain, when the Mastercontroller issues an `AdopterCredential`, and
the number it was checked against is recorded on the credential so the rule a soul was adopted
under stays readable for ever.

The honest cost: **a human is credentialled by the company before they may offer.** That belongs
on the "Be born" page, in those words.

`AdoptionRule.min_backing` is likewise recorded and enforced nowhere here — there is no backing
vault, and this package holds no coin.

### 4. It cannot enforce the operator's threshold

`operator_threshold` is stored and emitted. Nothing in this module reads it. The consent object it
implies belongs to a controller package, and the controller package is cut (council decision 3).
It is a recorded term of an adoption, not a live check.

---

## What it does do

| | |
|---|---|
| **Identity** | `agent` and `born_by` are set once, in `mint`, and have no setter anywhere in the module. |
| **Soulbound** | `EmployeeSoul` has `key` without `store`, is shared rather than owned, and the module publishes no transfer function. It cannot be wrapped, sold, lent or transferred by anybody, ever. |
| **The mandate** | `mandate_digest` is a 32-byte SHA-256 of the agent's instruction file. An agent whose file no longer hashes to it has been rewritten, and the dispatcher is expected to refuse it until the employer re-pins deliberately. |
| **The ceiling** | `allowance_per_epoch`, never above `MAX_ALLOWANCE`, enforced by `record_spend` on every caller that asks. |
| **The metabolism** | Value and cost booked against the open epoch; at close, SOLVENT raises the allowance by a quarter of the surplus to a ceiling, STARVING halves it to a floor, DYING halves again, and a third consecutive shortfall marks the soul **due for retirement**. |
| **The tier** | A second axis: not "is it earning" but "is there anything behind it". NORMAL / LOW / CRITICAL / RETIRED, set every settlement from the supplied balance and net. |
| **Adoption** | A human **offers**; the agent **chooses**. Credential, offer, withdrawal, adoption, renunciation, the operator's brake, and the operator's request for retirement. |
| **Retirement** | A state change and a timestamp. **Nothing is ever deleted.** |

### The two caps

| | `MasterCap` | `LedgerCap` |
|---|---|---|
| Mint, allowance, scope, outward, re-pin | yes | **no** |
| Issue a credential, override a tier, retire by hand | yes | **no** |
| Book earned, book burned, settle an epoch | **no** | yes |

The negative half of that table is enforced by the **type system**, not by an abort: a call passing
the wrong cap does not compile. `init` issues one of each to the publisher; `issue_ledger_cap`
delegates bookkeeping to the daemon that reads settlements, so a leaked bookkeeping key can move no
ceiling and mint no employee.

### The epoch is the chain's epoch

`settle_epoch` requires `ctx.epoch() > epoch_opened_at`. There is no wall-clock window and **the
caller supplies no epoch number**, so no settlement can be replayed by choosing one, and no period
can be closed early by presenting a `Clock` far enough ahead. `epoch_started_ms` is kept, written
from the clock at every roll, and used only by events and readers. It is never a gate.

`EPOCH_MS` was deleted. The comment where it stood says why, and says it must not come back.

### The tier rule

```
cover = the allowance THIS EPOCH RAN ON, captured before the metabolism moves it

vault_sui <  cover                                    -> CRITICAL
vault_sui >= cover * 10  AND  epoch_net_nonneg        -> NORMAL
otherwise                                             -> LOW
```

Two consecutive CRITICAL epochs retire the soul automatically. `override_tier` under `MasterCap`
moves a tier **downward only** — to a worse one — and can never reach RETIRED.

The cover is taken **before** the metabolism deliberately. Taken afterwards, a shortfall would
halve the allowance, halve the balance needed for "normal" with it, and a failing agent would be
promoted for failing. A guard that loosens when things go wrong is not a guard.

---

## What is verified, and how

```
sui move build     # clean
sui move test      # 112 tests, all passing
cd specs && sui-prover
```

**112 tests.** A trip test for every assert in the module that a reachable state can trip, both
boundaries of every comparison that has one, all four tiers, both retirement paths, and the `and`
in the normal-tier rule tested as an `and` from both sides.

One assert has no trip test and cannot have one: the share-ceiling re-check inside `adopt`. `offer`
already refuses a share above the ceiling, so no offer carrying one can exist to be consumed. It is
defense in depth against a future change to `offer`, it is unreachable today, and saying it is
tested would be untrue.

**Four machine-checked proofs**, in `specs/`. The prover discharges each `ensures` for *every*
input satisfying the `requires`, or returns a counterexample — a stronger statement than any
number of sampled tests. It proves the ceiling arithmetic (twice), the tier rule, and the tier's
monotonicity under `MasterCap`. `specs/sources/soul_specs.move` sets out, in full, which of the
council's six holds are proved, which are enforced by the compiler instead, and which by a missing
parameter. **None is claimed to be proved when it is not.**

`specs/` is never published: it depends on the prover, and the soul package's charter is a
dependency on the Sui framework and nothing else.

---

## Abort codes

`1`–`10` birth, identity, retirement, epoch, allowance, outward, digest, department, registry,
ceiling. `11`–`23` adoption: operator, already adopted, not adopted, offer expired, offer for
another soul, not the offeror, operator cap, revoked before, bad share, credential not owner,
account too young, already credentialled, paused. `27` bad tier.

**`24`, `25`, `26`, `28` and `29` are burned.** They belonged to the child mechanism and the vault
binding, both cut by the council. A code is never reused, even when the entry that carried it was
removed, so an old event or client log keeps meaning what it meant. Do not fill the gaps.

---

## History

`superseded/2026-09-04-before-reconcile/` holds the package exactly as it stood before the two
diverging copies were reconciled under council decision 8. Nothing was deleted.
