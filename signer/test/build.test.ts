// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * What the purse builds from an intent.
 *
 * The load-bearing assertion here is the absence of an `UnresolvedObject` input. An unresolved
 * input means `Transaction.build()` goes to the chain to resolve it, and that resolution is a
 * second observation of the world: the purse would evaluate a policy against one reading and sign
 * bytes assembled from another. The registration-then-call pattern in `build.ts` is what keeps it
 * absent, and it is quiet enough that a refactor could lose it with nothing else failing.
 */

import { describe, expect, it } from 'vitest';
import { fixedGas, buildIntent } from '../src/build.js';
import { parseIntent } from '../src/intent.js';
import {
  CAP_ID,
  CHAIN,
  GAS_COIN_ID,
  SET_CONTENT_PRICE,
  SUI_TYPE,
  VAULT_ID,
  policyFor,
  priceIntentFor,
} from './helpers.js';

const SENDER = `0x${'d'.repeat(64)}`;
const GAS = fixedGas({
  price: 1000n,
  payment: [{ objectId: GAS_COIN_ID, version: '1', digest: '11111111111111111111111111111111' }],
});

function build(intentValue: unknown) {
  const parsed = parseIntent(intentValue);
  if (!parsed.ok) throw new Error(parsed.reason);
  const built = buildIntent({
    intent: parsed.intent,
    chain: CHAIN,
    policy: policyFor(SENDER),
    sender: SENDER,
    gas: GAS,
  });
  if (!built.ok) throw new Error(built.refused.reason);
  return built.value.getData();
}

describe('a price intent', () => {
  it('becomes one set_content_price move call with the policy-named target and coin type', () => {
    const data = build(priceIntentFor());
    expect(data.commands).toHaveLength(1);
    const call = data.commands[0]!.MoveCall!;
    expect(`${call.package}::${call.module}::${call.function}`).toBe(SET_CONTENT_PRICE);
    expect(call.typeArguments).toEqual([SUI_TYPE]);
  });

  it('takes both objects as fully-resolved references — no UnresolvedObject input', () => {
    const data = build(priceIntentFor());
    const unresolved = data.inputs.filter((input) => input.$kind === 'UnresolvedObject');
    expect(unresolved).toHaveLength(0);

    const shared = data.inputs.find((i) => i.Object?.SharedObject !== undefined)?.Object?.SharedObject;
    expect(shared?.objectId).toBe(VAULT_ID);
    expect(shared?.initialSharedVersion).toBe('3');
    expect(shared?.mutable).toBe(true);

    const owned = data.inputs.find((i) => i.Object?.ImmOrOwnedObject !== undefined)?.Object?.ImmOrOwnedObject;
    expect(owned?.objectId).toBe(CAP_ID);
    expect(owned?.version).toBe('5');
  });

  it('registers each object exactly once, however many arguments name it', () => {
    const data = build(priceIntentFor());
    const objectInputs = data.inputs.filter((input) => input.$kind === 'Object');
    expect(objectInputs).toHaveLength(2);
  });

  it('sets the sender and a gas budget the policy would allow', () => {
    const data = build(priceIntentFor());
    expect(data.sender).toBe(SENDER);
    expect(data.gasData.budget).toBe(policyFor(SENDER).maxGasBudgetMist);
  });
});

describe('a settle_atomic intent puts the whole settlement in one transaction', () => {
  /*
    The three calls were three transactions until 2026-09-07, when the first landed, the second was
    refused, and the repaired run booked the income a second time. `earned_total` is permanently
    double: `book_earned` only adds and the module has no correction, not even under MasterCap.

    These tests pin the two properties that make the atomic form correct rather than merely
    convenient — that all three calls are in ONE transaction, and that `settle_epoch` is LAST.
    Order is not cosmetic here: `settle_epoch` zeroes `epoch_earned` and `epoch_burned`, so a
    booking after it lands in the next epoch and is invisible in the one it belonged to.
  */
  const SOUL_PACKAGE = `0x${'9'.repeat(64)}`;
  const LEDGER_CAP = `0x${'a'.repeat(64)}`;
  const REGISTRY = `0x${'b'.repeat(64)}`;
  const SOUL = `0x${'c'.repeat(64)}`;

  const base = {
    kind: 'settle_atomic' as const,
    packageId: SOUL_PACKAGE,
    ledgerCap: { objectId: LEDGER_CAP, version: '2', digest: '11111111111111111111111111111111' },
    registry: { objectId: REGISTRY, initialSharedVersion: '1', mutable: true },
    soul: { objectId: SOUL, initialSharedVersion: '1', mutable: true },
    clock: { objectId: '0x6', initialSharedVersion: '1', mutable: false },
    vaultSui: '5000000000',
    epochNetNonneg: true,
  };

  const targets = (intent: unknown): string[] =>
    build(intent).commands.map((c) => {
      const m = c.MoveCall!;
      return `${m.module}::${m.function}`;
    });

  it('is one transaction carrying book_earned, book_burned and settle_epoch, in that order', () => {
    expect(targets({ ...base, bookEarnedMist: '1000', bookBurnedMist: '500' })).toEqual([
      'soul::book_earned',
      'soul::book_burned',
      'soul::settle_epoch',
    ]);
  });

  it('omits a booking with nothing to book, and still settles last', () => {
    expect(targets({ ...base, bookBurnedMist: '500' })).toEqual([
      'soul::book_burned',
      'soul::settle_epoch',
    ]);
    expect(targets({ ...base, bookEarnedMist: '1000' })).toEqual([
      'soul::book_earned',
      'soul::settle_epoch',
    ]);
    expect(targets(base)).toEqual(['soul::settle_epoch']);
  });

  it('settle_epoch is never anything but the last command', () => {
    for (const extra of [{}, { bookEarnedMist: '1' }, { bookBurnedMist: '1' }, { bookEarnedMist: '1', bookBurnedMist: '2' }]) {
      const list = targets({ ...base, ...extra });
      expect(list[list.length - 1]).toBe('soul::settle_epoch');
      expect(list.filter((t) => t === 'soul::settle_epoch')).toHaveLength(1);
    }
  });

  it('registers the capability once, however many calls use it', () => {
    const data = build({ ...base, bookEarnedMist: '1000', bookBurnedMist: '500' });
    const capInputs = data.inputs.filter((i) => i.Object?.ImmOrOwnedObject?.objectId === LEDGER_CAP);
    expect(capInputs).toHaveLength(1);
  });
});

describe('a settle_epoch intent', () => {
  /*
    There is no TypeScript client for the soul package anywhere in the estate (the CTO's F1). The
    call is assembled from the Move signature and this test pins the argument order to it:

      public fun settle_epoch(
          _: &LedgerCap, registry: &mut SoulRegistry, soul: &mut EmployeeSoul,
          vault_sui: u64, epoch_net_nonneg: bool, clock: &Clock, ctx: &TxContext,
      )
  */
  const SOUL_PACKAGE = `0x${'9'.repeat(64)}`;
  const LEDGER_CAP = `0x${'a'.repeat(64)}`;
  const REGISTRY = `0x${'b'.repeat(64)}`;
  const SOUL = `0x${'c'.repeat(64)}`;

  const intent = {
    kind: 'settle_epoch',
    packageId: SOUL_PACKAGE,
    ledgerCap: { objectId: LEDGER_CAP, version: '2', digest: '11111111111111111111111111111111' },
    registry: { objectId: REGISTRY, initialSharedVersion: '1', mutable: true },
    soul: { objectId: SOUL, initialSharedVersion: '1', mutable: true },
    clock: { objectId: '0x6', initialSharedVersion: '1', mutable: false },
    vaultSui: '5000000000',
    epochNetNonneg: true,
  };

  it('targets soul::settle_epoch on the package the intent names', () => {
    const data = build(intent);
    const call = data.commands[0]!.MoveCall!;
    expect(`${call.package}::${call.module}::${call.function}`).toBe(`${SOUL_PACKAGE}::soul::settle_epoch`);
  });

  it('passes the arguments in the Move signature order', () => {
    const data = build(intent);
    const call = data.commands[0]!.MoveCall!;
    expect(call.arguments).toHaveLength(6);
    const idAt = (position: number): string | undefined => {
      const argument = call.arguments[position]!;
      if (argument.$kind !== 'Input') return undefined;
      const input = data.inputs[argument.Input]!;
      return input.Object?.ImmOrOwnedObject?.objectId ?? input.Object?.SharedObject?.objectId;
    };
    expect(idAt(0)).toBe(LEDGER_CAP);
    expect(idAt(1)).toBe(REGISTRY);
    expect(idAt(2)).toBe(SOUL);
    expect(idAt(5)).toBe('0x0000000000000000000000000000000000000000000000000000000000000006');
  });

  it('resolves every object, here too', () => {
    const data = build(intent);
    expect(data.inputs.filter((input) => input.$kind === 'UnresolvedObject')).toHaveLength(0);
  });
});
