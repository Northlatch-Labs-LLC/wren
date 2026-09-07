// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The clock's decision, with no I/O in it.
 *
 * # Why this is a separate file from the thing that runs it
 *
 * Everything below decides whether an epoch closes and what the books say when it does. It is the
 * part that can retire a citizen, so it is the part that has to be testable without a chain, a
 * socket, or a key. `bin/ledger-tick.ts` does the reading and the asking and owns none of the
 * judgement; this file owns all of the judgement and touches nothing.
 *
 * # The two ways a soul dies, and why the second one is the dangerous one
 *
 * From the deployed package (`0x8d6567ed…635f::soul`, read off mainnet 2026-09-06):
 *
 *  - **Starvation.** `epoch_earned < epoch_burned` raises `starving_epochs`. At `MAX_STARVING` (3)
 *    the soul is DYING and `due_for_retirement` is emitted — but nothing retires it. That takes
 *    `retire`, under `MasterCap`, by hand.
 *  - **Critical cover.** `compute_tier` calls a soul CRITICAL when the vault holds less than one
 *    epoch's allowance. At `MAX_CRITICAL` (2) consecutive criticals, `settle_epoch` **retires the
 *    soul itself**, inside the same call, with no second signature and no way to intervene.
 *
 * The second path is automatic, needs no shortfall at all, and is two epochs long. A citizen whose
 * vault is empty is retired on the second settlement whatever it earned. {@link planLedgerTick}
 * therefore reports `willBeCritical` on every plan so the caller can refuse to fire a settlement
 * that would spend a citizen's life, and so an operator reading the logs is told before it happens
 * rather than after.
 */

/** Soul fields this decision needs, as read from chain. All amounts are MIST. */
export interface SoulReading {
  readonly epochOpenedAt: bigint;
  readonly allowancePerEpoch: bigint;
  readonly epochEarned: bigint;
  readonly epochBurned: bigint;
  /** 0 SOLVENT, 1 STARVING, 2 DYING, 3 RETIRED. */
  readonly state: number;
  readonly paused: boolean;
  readonly criticalEpochs: number;
}

export interface LedgerInputs {
  /** The chain's current epoch. `settle_epoch` aborts `EEpochNotOver` unless this is greater. */
  readonly currentEpoch: bigint;
  readonly soul: SoulReading;
  /** The vault's SUI balance now. This is `vault_sui`, the cover the tier is measured against. */
  readonly vaultEarningsMist: bigint;
  /** The vault balance this service saw at the last settlement. The delta is what came in since. */
  readonly lastSeenEarningsMist: bigint;
  /** What one epoch of existing costs, from the policy values document. Never defaulted here. */
  readonly burnPerEpochMist: bigint;
}

export type LedgerPlan =
  | { readonly kind: 'wait'; readonly reason: string }
  | {
      readonly kind: 'settle';
      readonly bookEarnedMist: bigint;
      readonly bookBurnedMist: bigint;
      readonly vaultSui: bigint;
      readonly epochNetNonneg: boolean;
      /** True when this settlement will count a CRITICAL epoch against the soul. */
      readonly willBeCritical: boolean;
      /** True when this settlement will be the one that retires it. */
      readonly willRetire: boolean;
    };

const STATE_RETIRED = 3;
/** `MAX_CRITICAL` in the deployed package. Mirrored, and `test/ledger.test.ts` pins it. */
export const MAX_CRITICAL = 2;

/**
 * Decide what this tick does.
 *
 * The earned figure is a **delta**, not the vault's balance: `book_earned` adds to an epoch
 * counter that `settle_epoch` then zeroes, so booking the whole balance every epoch would credit
 * the same tip again on every settlement for the rest of the citizen's life. The delta floors at
 * zero because a claim out of the vault lowers the balance, and a withdrawal is not a negative
 * earning — there is no such thing on this contract, and `book_earned` takes a u64.
 */
export function planLedgerTick(input: LedgerInputs): LedgerPlan {
  const { currentEpoch, soul, vaultEarningsMist, lastSeenEarningsMist, burnPerEpochMist } = input;

  if (soul.state === STATE_RETIRED) return { kind: 'wait', reason: 'the soul is retired.' };
  if (soul.paused) return { kind: 'wait', reason: 'the soul is paused by the operator.' };
  if (currentEpoch <= soul.epochOpenedAt) {
    return {
      kind: 'wait',
      reason:
        `epoch ${String(soul.epochOpenedAt)} is still open; the chain is at ` +
        `${String(currentEpoch)}. settle_epoch would abort EEpochNotOver.`,
    };
  }

  const delta = vaultEarningsMist > lastSeenEarningsMist ? vaultEarningsMist - lastSeenEarningsMist : 0n;
  const totalEarned = soul.epochEarned + delta;
  const totalBurned = soul.epochBurned + burnPerEpochMist;
  const willBeCritical = vaultEarningsMist < soul.allowancePerEpoch;

  return {
    kind: 'settle',
    bookEarnedMist: delta,
    bookBurnedMist: burnPerEpochMist,
    vaultSui: vaultEarningsMist,
    epochNetNonneg: totalEarned >= totalBurned,
    willBeCritical,
    willRetire: willBeCritical && soul.criticalEpochs + 1 >= MAX_CRITICAL,
  };
}
