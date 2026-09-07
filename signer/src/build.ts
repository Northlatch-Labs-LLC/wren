// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * Intent to transaction. The model never supplies transaction bytes.
 *
 * # Why the purse builds and the container does not
 *
 * The container is the untrusted side: it runs a model that reads the internet. If it handed over
 * bytes, everything downstream — the simulation, the policy rules, the audit line — would be
 * judging an artefact chosen by whatever text the model last read. The policy would still refuse
 * anything outside the allow-lists, but the *shape* of what is signed would be the attacker's, and
 * every unexamined corner of that shape (a second command appended after the one the policy looked
 * at; a pure input the evaluator has no rule for) would be theirs too.
 *
 * So the container sends a fact — "price this key at this much" — and this file decides what a
 * transaction expressing that fact looks like. There is exactly one shape per intent kind and it is
 * written here.
 *
 * # Gas
 *
 * `GasPort` exists because gas is the deployment's decision, not the model's and not this file's.
 * The default asks the node: it sets the budget from the policy document's own `maxGasBudgetMist`
 * — the ceiling the evaluator is going to check anyway, so the transaction is never built asking
 * for more than the policy would allow — and leaves price and coin selection to `Transaction.build`.
 *
 * A deployment that pins a gas coin passes {@link fixedGas}. That is not only a test seam: this
 * purse serves one agent with one address, and two beats that overlap (a slow node, a timer that
 * fired while the last beat was still running) would otherwise have the node select the same coin
 * twice and one of the two transactions would fail on an equivocated object. Pinning is the fix
 * where a deployment can afford to hold a dedicated gas coin.
 */

import { Transaction } from '@mysten/sui/transactions';
import { tx as builders } from '@projectx-social/sdk';
import type { PolicyDoc } from '@projectx-social/policy';
import type { ChainConfig } from './chain.js';
import { allow, refuse, type Outcome } from './outcome.js';
import type { Intent, OwnedObjectRef, SharedObjectRef } from './intent.js';

/** One fully-resolved gas coin. Same shape `Transaction.setGasPayment` takes. */
export interface GasCoinRef {
  readonly objectId: string;
  readonly version: string;
  readonly digest: string;
}

export interface GasPort {
  /** Called once on a freshly built transaction, before it is handed to the policy signer. */
  readonly apply: (tx: Transaction, policy: PolicyDoc) => void;
}

/**
 * The default: budget from the policy, everything else from the node at build time.
 *
 * The budget is taken from `maxGasBudgetMist` rather than from a constant here so that raising the
 * ceiling is a policy redeploy — visible in the audit chain's `policyHash` — and not an edit to
 * this file that no entry would record.
 */
export const nodeGas: GasPort = {
  apply: (tx, policy) => {
    tx.setGasBudget(BigInt(policy.maxGasBudgetMist));
  },
};

/** A pinned gas coin and price. Nothing about the transaction then needs the network to assemble. */
export function fixedGas(args: {
  readonly price: bigint;
  readonly payment: readonly GasCoinRef[];
}): GasPort {
  return {
    apply: (tx, policy) => {
      tx.setGasBudget(BigInt(policy.maxGasBudgetMist));
      tx.setGasPrice(args.price);
      tx.setGasPayment([...args.payment]);
    },
  };
}

function shared(tx: Transaction, ref: SharedObjectRef): void {
  tx.sharedObjectRef({
    objectId: ref.objectId,
    initialSharedVersion: ref.initialSharedVersion,
    mutable: ref.mutable,
  });
}

function owned(tx: Transaction, ref: OwnedObjectRef): void {
  tx.objectRef({ objectId: ref.objectId, version: ref.version, digest: ref.digest });
}

/**
 * Build the transaction an intent describes.
 *
 * # The registration-then-call pattern, and why it is not a trick
 *
 * `setContentPrice` from the SDK takes object **ids** and calls `tx.object(id)`, which would add an
 * `UnresolvedObject` input and make `build()` go to the chain. Registering the fully-resolved
 * references on the same transaction first means `tx.object(id)` finds them: `Transaction.object`
 * looks an input up by object id before adding one
 * (`@mysten/sui@2.27.1 src/transactions/Transaction.ts:394`, read on this branch).
 *
 * That is a documented behaviour of the library and not a coincidence, but it is quiet enough that
 * a refactor could lose it without anything failing loudly — the transaction would simply start
 * doing a chain read. `test/build.test.ts` asserts there is no `UnresolvedObject` input in the
 * result, which fails the moment it is lost.
 *
 * The alternative, writing the move call out here, would put a second copy of the `set_content_price`
 * argument order in the estate. When the contract's signature changes, one of the two copies is
 * updated and the other silently prices the wrong thing.
 */
export function buildIntent(args: {
  readonly intent: Intent;
  readonly chain: ChainConfig;
  readonly policy: PolicyDoc;
  readonly sender: string;
  readonly gas: GasPort;
}): Outcome<Transaction> {
  const { intent, chain, policy, sender, gas } = args;
  const tx = new Transaction();
  tx.setSender(sender);

  try {
    switch (intent.kind) {
      case 'post':
      case 'price': {
        shared(tx, intent.vault);
        owned(tx, intent.cap);
        builders.setContentPrice(
          { config: chain, tx },
          {
            coinType: intent.coinType,
            vaultId: intent.vault.objectId,
            capId: intent.cap.objectId,
            contentKey: new Uint8Array(Buffer.from(intent.contentKey, 'utf8')),
            price: BigInt(intent.priceMist),
          },
        );
        break;
      }

      case 'settle_epoch': {
        /*
          northlatch_soul::settle_epoch, from the Move signature:

            public fun settle_epoch(
                _: &LedgerCap, registry: &mut SoulRegistry, soul: &mut EmployeeSoul,
                vault_sui: u64, epoch_net_nonneg: bool, clock: &Clock, ctx: &TxContext,
            )

          `ctx` is supplied by the runtime and is not an argument here. The order below is that
          signature's order and `test/build.test.ts` pins it.
        */
        owned(tx, intent.ledgerCap);
        shared(tx, intent.registry);
        shared(tx, intent.soul);
        shared(tx, intent.clock);
        tx.moveCall({
          target: `${intent.packageId}::soul::settle_epoch`,
          arguments: [
            tx.object(intent.ledgerCap.objectId),
            tx.object(intent.registry.objectId),
            tx.object(intent.soul.objectId),
            tx.pure.u64(BigInt(intent.vaultSui)),
            tx.pure.bool(intent.epochNetNonneg),
            tx.object(intent.clock.objectId),
          ],
        });
        break;
      }

      case 'record_spend': {
        /*
          From the deployed package, read off mainnet 2026-09-06:

            public fun record_spend(soul: &mut EmployeeSoul, amount: u64, ctx: &TxContext)

          `ctx` is supplied by the runtime and is not an argument here. No capability: the contract
          asserts `ctx.sender() == soul.agent`, so the sender is the permission.
          `test/build.test.ts` pins this order against that signature.
        */
        shared(tx, intent.soul);
        tx.moveCall({
          target: `${intent.packageId}::soul::record_spend`,
          arguments: [tx.object(intent.soul.objectId), tx.pure.u64(BigInt(intent.amountMist))],
        });
        break;
      }

      case 'book_earned':
      case 'book_burned': {
        /*
          From the deployed package, read off mainnet 2026-09-06:

            public fun book_earned(_: &LedgerCap, soul: &mut EmployeeSoul, amount: u64)
            public fun book_burned(_: &LedgerCap, soul: &mut EmployeeSoul, amount: u64)

          One shape, two targets. The two are built together because their argument order is the
          same signature; the target name is the only difference, and deriving it from the intent
          kind means the two can never drift apart into different orders.
        */
        owned(tx, intent.ledgerCap);
        shared(tx, intent.soul);
        tx.moveCall({
          target: `${intent.packageId}::soul::${intent.kind}`,
          arguments: [
            tx.object(intent.ledgerCap.objectId),
            tx.object(intent.soul.objectId),
            tx.pure.u64(BigInt(intent.amountMist)),
          ],
        });
        break;
      }

      case 'statement': {
        // Never a transaction: the purse signs a statement as a personal message (statement.ts).
        return refuse('intent-unbuildable', 'a statement intent builds no transaction.');
      }

      default: {
        const exhaustive: never = intent;
        return refuse('intent-unbuildable', `no builder for ${JSON.stringify(exhaustive)}.`);
      }
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return refuse(
      'intent-unbuildable',
      `the intent passed the schema and could still not be assembled into a transaction: ${detail}. ` +
        `Nothing was simulated and nothing was signed.`,
    );
  }

  gas.apply(tx, policy);
  return allow(tx);
}
