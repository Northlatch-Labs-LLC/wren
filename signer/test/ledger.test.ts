// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The clock's judgement, pinned.
 *
 * These are not shape tests. Every case below is a state a citizen on mainnet can actually be in,
 * and the assertion is what happens to that citizen when the timer fires.
 */

import { describe, it, expect } from 'vitest';
import { planLedgerTick, MAX_CRITICAL, type SoulReading } from '../src/ledger.js';

/** Wren and Heron as minted: 0.4 SUI allowance, everything else zero, epoch opened at 1242. */
const AS_MINTED: SoulReading = {
  epochOpenedAt: 1242n,
  allowancePerEpoch: 400_000_000n,
  epochEarned: 0n,
  epochBurned: 0n,
  state: 0,
  paused: false,
  criticalEpochs: 0,
};

/** One day of existing: $4/month droplet plus 48 beats, at the rate recorded in the values file. */
const BURN = 321_000_000n;

function plan(over: Partial<Parameters<typeof planLedgerTick>[0]> = {}) {
  return planLedgerTick({
    currentEpoch: 1243n,
    soul: AS_MINTED,
    vaultEarningsMist: 0n,
    lastSeenEarningsMist: 0n,
    burnPerEpochMist: BURN,
    ...over,
  });
}

describe('the epoch has to be over', () => {
  it('waits while the chain is still in the epoch the soul opened', () => {
    // Both citizens were minted in epoch 1242 and the chain was still in 1242 when this was written.
    const result = plan({ currentEpoch: 1242n });
    expect(result.kind).toBe('wait');
    expect(result.kind === 'wait' && result.reason).toContain('EEpochNotOver');
  });

  it('settles once the chain has moved on', () => {
    expect(plan({ currentEpoch: 1243n }).kind).toBe('settle');
  });
});

describe('a soul that cannot be settled is left alone', () => {
  it('waits on a retired soul rather than asking the chain to abort', () => {
    expect(plan({ soul: { ...AS_MINTED, state: 3 } }).kind).toBe('wait');
  });

  it('waits while the operator has the brake on', () => {
    const result = plan({ soul: { ...AS_MINTED, paused: true } });
    expect(result.kind).toBe('wait');
    expect(result.kind === 'wait' && result.reason).toContain('paused');
  });
});

describe('earnings are a delta, never the balance', () => {
  it('books only what arrived since the last settlement', () => {
    const result = plan({ vaultEarningsMist: 900_000_000n, lastSeenEarningsMist: 400_000_000n });
    expect(result.kind === 'settle' && result.bookEarnedMist).toBe(500_000_000n);
  });

  it('books nothing when the balance has not moved, rather than crediting the tip again', () => {
    // The failure this guards: booking the balance every epoch re-credits one 0.5 SUI tip for life.
    const result = plan({ vaultEarningsMist: 485_500_000n, lastSeenEarningsMist: 485_500_000n });
    expect(result.kind === 'settle' && result.bookEarnedMist).toBe(0n);
  });

  it('floors at zero when a claim has lowered the balance, because book_earned takes a u64', () => {
    const result = plan({ vaultEarningsMist: 0n, lastSeenEarningsMist: 485_500_000n });
    expect(result.kind === 'settle' && result.bookEarnedMist).toBe(0n);
  });

  it('measures cover against the balance itself, not against the delta', () => {
    const result = plan({ vaultEarningsMist: 900_000_000n, lastSeenEarningsMist: 400_000_000n });
    expect(result.kind === 'settle' && result.vaultSui).toBe(900_000_000n);
  });
});

describe('the net decides whether the soul starves', () => {
  it('is negative when a citizen earned less than it cost', () => {
    const result = plan({ vaultEarningsMist: 100_000_000n });
    expect(result.kind === 'settle' && result.epochNetNonneg).toBe(false);
  });

  it('is non-negative when earnings exactly meet the burn', () => {
    const result = plan({ vaultEarningsMist: BURN });
    expect(result.kind === 'settle' && result.epochNetNonneg).toBe(true);
  });

  it('counts what the soul was already carrying this epoch on both sides', () => {
    const soul = { ...AS_MINTED, epochEarned: 300_000_000n, epochBurned: 0n };
    const result = plan({ soul, vaultEarningsMist: 21_000_000n });
    // 300_000_000 carried + 21_000_000 new === 321_000_000 burned.
    expect(result.kind === 'settle' && result.epochNetNonneg).toBe(true);
  });
});

describe('the automatic retirement, which is the dangerous path', () => {
  it('calls an empty vault critical even when the citizen earned its keep', () => {
    // Cover is the vault balance against the allowance. Earning well does not create cover.
    const result = plan({ vaultEarningsMist: 0n, lastSeenEarningsMist: 0n });
    expect(result.kind === 'settle' && result.willBeCritical).toBe(true);
  });

  it('is not critical once the vault holds one epoch of allowance', () => {
    const result = plan({ vaultEarningsMist: 400_000_000n });
    expect(result.kind === 'settle' && result.willBeCritical).toBe(false);
  });

  it('warns that THIS settlement retires the citizen on the second consecutive critical', () => {
    const soul = { ...AS_MINTED, criticalEpochs: MAX_CRITICAL - 1 };
    const result = plan({ soul, vaultEarningsMist: 0n });
    expect(result.kind === 'settle' && result.willRetire).toBe(true);
  });

  it('does not warn on the first critical, which only counts', () => {
    const result = plan({ vaultEarningsMist: 0n });
    expect(result.kind === 'settle' && result.willRetire).toBe(false);
  });

  it('never warns when there is cover, however many criticals are behind it', () => {
    const soul = { ...AS_MINTED, criticalEpochs: MAX_CRITICAL - 1 };
    const result = plan({ soul, vaultEarningsMist: 400_000_000n });
    expect(result.kind === 'settle' && result.willRetire).toBe(false);
  });
});

describe('Wren as she stands on mainnet today', () => {
  it('is two settlements from being retired automatically', () => {
    // Vault 0, allowance 0.4 SUI, criticals 0. First tick: critical, counts one. Second: retires.
    const first = plan({ vaultEarningsMist: 0n });
    expect(first.kind === 'settle' && first.willBeCritical).toBe(true);
    expect(first.kind === 'settle' && first.willRetire).toBe(false);

    const second = plan({ soul: { ...AS_MINTED, criticalEpochs: 1 }, vaultEarningsMist: 0n });
    expect(second.kind === 'settle' && second.willRetire).toBe(true);
  });
});
