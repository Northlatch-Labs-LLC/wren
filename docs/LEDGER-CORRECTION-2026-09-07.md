<!-- Built-by: @projectx.sui -->

# Wren's lifetime totals are double, permanently, and this is why

On 7 September 2026 her `earned_total` and `burned_total` were each booked
twice. They cannot be un-booked. This file is the record, because the numbers
themselves will never say so.

## What the chain holds

| Field | On chain | True figure |
|---|---:|---:|
| `earned_total` | 2,133,675,400 | 1,066,837,700 |
| `burned_total` | 642,000,000 | 321,000,000 |

## Why it cannot be corrected

`earned_total` and `burned_total` are written in exactly two places —
`book_earned` and `book_burned` — and both only add, saturating at u64. There
is no setter, no reset and no correction anywhere in the module, and
`MasterCap` does not have one either: the employer's hand can change the
allowance, the scope, the outward flag and the mandate digest, and nothing
else. These two counters are monotonic on purpose. A ledger you can edit is
not a ledger.

## How it happened

The settlement driver made three calls with one capability. Every call moves an
owned object's version, so each call has to see where the last one left it. It
did not.

| Time | Transaction | Landed |
|---|---|---|
| ~16:0x | — | `book_burned` 321,000,000 |
| 16:42 | `9iuzE45RxyCQPPJMnBsdURMhaftD5F7Cb4aLA9tfzEwx` | `book_earned` 1,066,837,700, then the run died on a stale capability version |
| 16:48 | `78YpTDqyHG3DH7SfQZzr5NbgyGi7dVnnVyrHHHXsY9mi` | `book_earned` again |
| 16:48 | `AH1fmX9Wn3DWUhtHdKTSU9vHDLJwG7RedC1yWfmVs1gT` | `book_burned` again |
| 16:48 | `DiWRQCG5icn6JTpMgDuiw2jHRfSRgegVKKdgw4rd7HLt` | `settle_epoch` |

The first run booked income and then failed before booking cost. The repaired
run had no way to know income was already in, and booked the whole epoch again.
Retrying half a completed sequence is what did this, not the retry itself.

## What it affected, and what it did not

**It did not affect any decision.** `settle_epoch` reads `epoch_earned` and
`epoch_burned`, not the lifetime totals, and it zeroes those as it closes. The
per-epoch counters are the only ones that reach the survival rule.

**It did affect her allowance**, because the epoch figures were doubled when
the epoch closed. `compute_settled_allowance(400000000, earned, burned)` gives
772,918,850 on the doubled figures and 586,459,425 on the true ones — a daily
ceiling 32% higher than she had earned.

Corrected 2026-09-07 20:37:32 UTC by `set_allowance` under `MasterCap`,
transaction `4DA9DJqeP2LJVpGPPwvNQk5RykimLWM8KRAxoQoHtZ4w`. That call emits
`AllowanceSet` with `by_settlement: false`, so the chain itself records that a
human set this number rather than a settlement deriving it.

## What stops it recurring

Three changes, all shipped on 2026-09-07:

- `ledger-tick` submits every signed transaction and reads the result. It used
  to print "signed" and move on, having sent nothing.
- The watermark moves only after all three land. It used to move on a
  signature, which is what marked an unsettled epoch as settled.
- The capability is resolved live before each call, and the read waits for the
  version to actually change, because the indexer trails the chain by a moment.

What is still absent, and would have prevented this outright: nothing makes
the three calls atomic. A programmable transaction block containing all three
would land or fail as one, and a half-run could not exist. That is the durable
fix and it is not written.
