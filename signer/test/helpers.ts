// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * Test fixtures. Every key here is generated in this process and thrown away with the temp
 * directory; nothing reads `~/.sui`, nothing reads the pile, and nothing touches the network.
 *
 * The simulation responses are in the exact shape `@mysten/sui` 2.27.1's gRPC transport produces —
 * the same shape `packages/signer/test/helpers.ts` recorded from mainnet on 2026-08-31, with the
 * commands and inputs changed to the ones a `creator::set_content_price` call actually has. The
 * padded coin type, the signed decimal amount string, the two-level object input enum and the
 * digest living on `effects` rather than on the transaction are all kept, because a fixture that
 * "looks right" makes the translation assert against a fiction.
 */

import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import type { SuiGrpcClient } from '@mysten/sui/grpc';
import { ok } from '@projectx-social/sdk';
import type { PolicyDoc } from '@projectx-social/policy';
import type { SerializedSignature, SimulationPort, Signer } from '@projectx-social/signer';
import type { ChainConfig } from '../src/chain.js';
import type { Intent } from '../src/intent.js';

export const SUI_TYPE = `0x${'0'.repeat(63)}2::sui::SUI`;
export const PACKAGE = `0x${'0'.repeat(62)}c5`;
export const SET_CONTENT_PRICE = `${PACKAGE}::creator::set_content_price`;
export const VAULT_ID = `0x${'1'.repeat(64)}`;
export const CAP_ID = `0x${'2'.repeat(64)}`;
export const GAS_COIN_ID = `0x${'7'.repeat(64)}`;
export const STRANGER = `0x${'b'.repeat(64)}`;
export const DIGEST = '2Wm1kXwYxPjkjVqT1rvHi9oqmvSZY3md6eirK8WheHbR';
export const OBSERVED_AT_MS = 1_788_000_000_000;

export function throwawayKeypair(): Ed25519Keypair {
  return Ed25519Keypair.generate();
}

/** Wrap a raw keypair as one of the signer package's `Signer`s, without a secret string. */
export function signerFor(keypair: Ed25519Keypair): Signer {
  return {
    address: keypair.toSuiAddress(),
    scheme: 'ed25519',
    signPersonalMessage: async (bytes: Uint8Array) =>
      ok<SerializedSignature>((await keypair.signPersonalMessage(bytes)).signature),
    signTransaction: async (bytes: Uint8Array) =>
      ok<SerializedSignature>((await keypair.signTransaction(bytes)).signature),
  };
}

export async function temporaryDirectory(prefix = 'heron-purse-'): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

export const CHAIN: ChainConfig = {
  network: 'localnet',
  grpcUrl: 'https://fullnode.example.invalid:443',
  packageId: PACKAGE,
  latestPackageId: PACKAGE,
  platformId: `0x${'3'.repeat(64)}`,
  registryId: `0x${'4'.repeat(64)}`,
};

/** A policy that permits exactly the `price`/`post` intent below, and nothing else. */
export function policyFor(agentAddress: string, overrides: Partial<PolicyDoc> = {}): PolicyDoc {
  return {
    version: 1,
    agentAddress,
    outflowCeilings: [{ coinType: SUI_TYPE, maxPerPeriod: '10000000', periodMs: 86_400_000 }],
    allowedTargets: [SET_CONTENT_PRICE],
    allowedTypeArguments: [SUI_TYPE],
    allowedRecipients: [agentAddress],
    allowedObjects: [VAULT_ID, CAP_ID],
    maxGasBudgetMist: '20000000',
    allowedCommandKinds: ['MoveCall'],
    ...overrides,
  };
}

export function priceIntentFor(overrides: Partial<Extract<Intent, { kind: 'price' }>> = {}): Intent {
  return {
    kind: 'price',
    coinType: SUI_TYPE,
    vault: { objectId: VAULT_ID, initialSharedVersion: '3', mutable: true },
    cap: { objectId: CAP_ID, version: '5', digest: '11111111111111111111111111111111' },
    contentKey: 'the-first-post',
    priceMist: '250000000',
    ...overrides,
  };
}

export function postIntentFor(): Intent {
  return {
    kind: 'post',
    coinType: SUI_TYPE,
    vault: { objectId: VAULT_ID, initialSharedVersion: '3', mutable: true },
    cap: { objectId: CAP_ID, version: '5', digest: '11111111111111111111111111111111' },
    contentKey: 'the-first-post',
    bodyDigestSha256: 'a'.repeat(64),
    priceMist: '250000000',
  };
}

export interface ResponseOverrides {
  /** The agent's own SUI balance change, signed decimal. Gas by default. */
  readonly agentAmount?: string;
  /** Append a TransferObjects command to a stranger. */
  readonly transferToStranger?: boolean;
  readonly gasBudget?: string;
  readonly sender?: string;
}

/**
 * A simulation response for a `creator::set_content_price` transaction.
 *
 * Inputs: the vault as a shared object (two-level enum, per FINDING 4 in `evidence.ts`), the cap as
 * an `ImmOrOwnedObject`, and two pure inputs — the content key and the price. Commands: the one
 * move call. The digest is on `effects`, per FINDING 3.
 */
export function setPriceResponse(agentAddress: string, overrides: ResponseOverrides = {}) {
  const addressBytes = Buffer.from(agentAddress.slice(2), 'hex');
  const strangerBytes = Buffer.from(STRANGER.slice(2), 'hex');

  const inputs: unknown[] = [
    {
      $kind: 'Object',
      Object: {
        $kind: 'SharedObject',
        SharedObject: { objectId: VAULT_ID, initialSharedVersion: '3', mutable: true },
      },
    },
    {
      $kind: 'Object',
      Object: {
        $kind: 'ImmOrOwnedObject',
        ImmOrOwnedObject: { objectId: CAP_ID, version: '5', digest: '11111111111111111111111111111111' },
      },
    },
    { $kind: 'Pure', Pure: { bytes: Buffer.from('the-first-post', 'utf8').toString('base64') } },
    { $kind: 'Pure', Pure: { bytes: 'AAAAAAAAAAA=' } },
  ];

  const commands: unknown[] = [
    {
      $kind: 'MoveCall',
      MoveCall: {
        package: PACKAGE,
        module: 'creator',
        function: 'set_content_price',
        typeArguments: [SUI_TYPE],
        arguments: [
          { $kind: 'Input', Input: 0 },
          { $kind: 'Input', Input: 1 },
          { $kind: 'Input', Input: 2 },
          { $kind: 'Input', Input: 3 },
        ],
      },
    },
  ];

  if (overrides.transferToStranger === true) {
    inputs.push({ $kind: 'Pure', Pure: { bytes: strangerBytes.toString('base64') } });
    commands.push({
      $kind: 'TransferObjects',
      TransferObjects: {
        objects: [{ $kind: 'NestedResult', NestedResult: [0, 0] }],
        address: { $kind: 'Input', Input: 4 },
      },
    });
  }

  void addressBytes;

  return {
    $kind: 'Transaction',
    Transaction: {
      status: { success: true, error: null },
      balanceChanges: [
        { coinType: SUI_TYPE, address: agentAddress, amount: overrides.agentAmount ?? '-1188000' },
      ],
      effects: {
        transactionDigest: DIGEST,
        gasUsed: {
          computationCost: '100000',
          storageCost: '988000',
          storageRebate: '0',
          nonRefundableStorageFee: '0',
        },
      },
      transaction: {
        sender: overrides.sender ?? agentAddress,
        gasData: {
          budget: overrides.gasBudget ?? '1188000',
          owner: overrides.sender ?? agentAddress,
          payment: [],
          price: '100',
        },
        inputs,
        commands,
      },
    },
  };
}

/** A client that answers the SDK gate with whatever response the test supplies. */
export function stubClient(response: unknown): SuiGrpcClient {
  return { simulateTransaction: async () => response } as unknown as SuiGrpcClient;
}

/** A simulation port that answers with a recorded response, over the real reader, with no network. */
export function stubPort(response: unknown, sender: string): SimulationPort {
  return {
    observe: async ({ transactionBytes }) => {
      if (transactionBytes.byteLength === 0) throw new Error('nothing was built');
      const { readSimulation } = await import('@projectx-social/signer');
      return readSimulation(response, sender);
    },
  };
}

/* ------------------------------------------------------- the LedgerCap arm, for the A3 fixtures */

/**
 * The unpublished soul package, and the four objects `soul::settle_epoch` takes.
 *
 * These are fixture ids, not addresses: the soul package has no `Published.toml` and no object id
 * anywhere in the estate, which is exactly why `policy/heron-ledger.json` names its package as a
 * substitution the deploy fills. The Clock is `0x6` because that one really is fixed.
 */
export const SOUL_PACKAGE = `0x${'0'.repeat(62)}5e`;
export const SETTLE_EPOCH = `${SOUL_PACKAGE}::soul::settle_epoch`;
export const RECORD_SPEND = `${SOUL_PACKAGE}::soul::record_spend`;
export const LEDGER_CAP_ID = `0x${'8'.repeat(64)}`;
export const REGISTRY_ID = `0x${'9'.repeat(64)}`;
export const SOUL_ID = `0x${'a'.repeat(64)}`;
export const CLOCK_ID = '0x6';

export function settleEpochIntentFor(
  overrides: Partial<Extract<Intent, { kind: 'settle_epoch' }>> = {},
): Intent {
  return {
    kind: 'settle_epoch',
    packageId: SOUL_PACKAGE,
    ledgerCap: { objectId: LEDGER_CAP_ID, version: '11', digest: '11111111111111111111111111111111' },
    registry: { objectId: REGISTRY_ID, initialSharedVersion: '2', mutable: true },
    soul: { objectId: SOUL_ID, initialSharedVersion: '2', mutable: true },
    clock: { objectId: CLOCK_ID, initialSharedVersion: '1', mutable: false },
    vaultSui: '4000000000',
    epochNetNonneg: true,
    ...overrides,
  };
}

/**
 * A simulation response for a `soul::settle_epoch` transaction.
 *
 * The same recorded shape as {@link setPriceResponse} — two-level object input enum, signed decimal
 * amount, digest on `effects` — with the inputs and the one command that `settle_epoch` actually
 * has. It exists so a content policy can be shown refusing a **well-formed** settlement rather than
 * a malformed one; a fixture that was rejected by the schema would prove nothing about the policy.
 */
export function settleEpochResponse(agentAddress: string, overrides: ResponseOverrides = {}) {
  return {
    $kind: 'Transaction',
    Transaction: {
      status: { success: true, error: null },
      balanceChanges: [
        { coinType: SUI_TYPE, address: agentAddress, amount: overrides.agentAmount ?? '-1188000' },
      ],
      effects: {
        transactionDigest: DIGEST,
        gasUsed: {
          computationCost: '100000',
          storageCost: '988000',
          storageRebate: '0',
          nonRefundableStorageFee: '0',
        },
      },
      transaction: {
        sender: overrides.sender ?? agentAddress,
        gasData: {
          budget: overrides.gasBudget ?? '1188000',
          owner: overrides.sender ?? agentAddress,
          payment: [],
          price: '100',
        },
        inputs: [
          {
            $kind: 'Object',
            Object: {
              $kind: 'ImmOrOwnedObject',
              ImmOrOwnedObject: {
                objectId: LEDGER_CAP_ID,
                version: '11',
                digest: '11111111111111111111111111111111',
              },
            },
          },
          {
            $kind: 'Object',
            Object: {
              $kind: 'SharedObject',
              SharedObject: { objectId: REGISTRY_ID, initialSharedVersion: '2', mutable: true },
            },
          },
          {
            $kind: 'Object',
            Object: {
              $kind: 'SharedObject',
              SharedObject: { objectId: SOUL_ID, initialSharedVersion: '2', mutable: true },
            },
          },
          { $kind: 'Pure', Pure: { bytes: 'AAAAAAAAAAA=' } },
          { $kind: 'Pure', Pure: { bytes: 'AQ==' } },
          {
            $kind: 'Object',
            Object: {
              $kind: 'SharedObject',
              SharedObject: { objectId: CLOCK_ID, initialSharedVersion: '1', mutable: false },
            },
          },
        ],
        commands: [
          {
            $kind: 'MoveCall',
            MoveCall: {
              package: SOUL_PACKAGE,
              module: 'soul',
              function: 'settle_epoch',
              typeArguments: [],
              arguments: [
                { $kind: 'Input', Input: 0 },
                { $kind: 'Input', Input: 1 },
                { $kind: 'Input', Input: 2 },
                { $kind: 'Input', Input: 3 },
                { $kind: 'Input', Input: 4 },
                { $kind: 'Input', Input: 5 },
              ],
            },
          },
        ],
      },
    },
  };
}
