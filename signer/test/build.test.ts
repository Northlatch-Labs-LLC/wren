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
