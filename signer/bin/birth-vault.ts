#!/usr/bin/env -S npx tsx
// Built-by: @projectx.sui
/**
 * Open Heron's SocialAccount and CreatorVault<SUI> on the projectx_social package, as Heron's
 * 1-of-2 multisig address, with the hot key as the one member this laptop holds.
 *
 * Two transactions, because `creator::open_vault` takes the SocialAccount object that
 * `account::open` creates. Each is built with the SDK's own builders (packages/sdk/src/tx.ts),
 * simulated against the node, and only then signed and executed. Gas is paid from Heron's address
 * balance: an empty gas payment and a ValidDuring expiration, the shape @mysten/sui's own executor
 * uses for that mode, because Heron's address holds a balance and no coin object yet.
 *
 * The hot key is read through the purse's own loader (`--key-file`, 0600, no symlink, never argv,
 * never env). Nothing here prints a secret; it prints addresses, ids and digests.
 *
 * usage: birth-vault.ts --key-file <path> --multisig <doc> --chain <doc> --handle <handle>
 *                       [--referrer <address>] [--values <path>] [--values-prefix HERON] [--dry-run]
 * --dry-run builds and simulates both steps as far as the chain state allows and executes nothing.
 * --values merges <PREFIX>_VAULT_ID and <PREFIX>_CREATOR_CAP_ID into that JSON file when the vault
 * exists; the prefix is HERON unless --values-prefix names another agent's (WREN).
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { Transaction } from '@mysten/sui/transactions';
import { createClient, tx as builders, type ProjectXSocialConfig } from '@projectx-social/sdk';
import { loadChainConfig } from '../src/chain.js';
import { loadHotKey, refuseKeyInProcessSurface } from '../src/key.js';
import { loadMultisigDoc, wrapAsMultisig } from '../src/multisig-file.js';

const SUI = '0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI';
const GAS_BUDGET = 30_000_000n;
const GRAPHQL = 'https://graphql.mainnet.sui.io/graphql';

interface Args {
  readonly keyFile: string;
  readonly multisig: string;
  readonly chain: string;
  readonly handle: string;
  readonly referrer: string | null;
  readonly values: string | null;
  readonly valuesPrefix: string;
  readonly dryRun: boolean;
}

const VALUES_PREFIX = /^[A-Z][A-Z0-9_]{0,15}$/;

function parseArgs(argv: readonly string[]): Args | string {
  const map = new Map<string, string>();
  let dryRun = false;
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i]!;
    if (flag === '--dry-run') { dryRun = true; continue; }
    if (!['--key-file', '--multisig', '--chain', '--handle', '--referrer', '--values', '--values-prefix'].includes(flag)) return `${flag} is not a flag this takes.`;
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) return `${flag} needs a value.`;
    map.set(flag, value);
    i += 1;
  }
  for (const required of ['--key-file', '--multisig', '--chain', '--handle']) {
    if (!map.has(required)) return `${required} is required.`;
  }
  const referrer = map.get('--referrer') ?? null;
  if (referrer !== null && !/^0x[0-9a-fA-F]{64}$/.test(referrer)) return '--referrer is not a full Sui address.';
  const valuesPrefix = map.get('--values-prefix') ?? 'HERON';
  if (!VALUES_PREFIX.test(valuesPrefix)) return '--values-prefix is an upper-case substitution prefix such as HERON or WREN.';
  return {
    keyFile: map.get('--key-file')!,
    multisig: map.get('--multisig')!,
    chain: map.get('--chain')!,
    handle: map.get('--handle')!,
    referrer,
    values: map.get('--values') ?? null,
    valuesPrefix,
    dryRun,
  };
}

function say(line: string): void {
  process.stderr.write(`birth-vault: ${line}\n`);
}

/**
 * An object's Move type, read over gRPC from the node the transaction was sent to. Not GraphQL:
 * the indexer behind it lags the node by seconds, and the first real run (2026-09-05) executed the
 * account transaction and then found none of its three created objects there.
 */
async function typeOf(client: ReturnType<typeof createClient>, objectId: string): Promise<string> {
  for (let attempt = 0; attempt < 10; attempt += 1) {
    try {
      const response = await client.core.getObject({ objectId });
      const type = (response as { object?: { type?: string } }).object?.type;
      if (typeof type === 'string' && type !== '') return type;
    } catch {
      // not there yet
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  return '';
}

/** An object's fields as JSON, from the GraphQL indexer, with a wait for it to catch up. */
async function fieldsOf(objectId: string): Promise<Record<string, unknown>> {
  const query = `{ object(address: "${objectId}") { asMoveObject { contents { json } } } }`;
  for (let attempt = 0; attempt < 15; attempt += 1) {
    const response = await fetch(GRAPHQL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query }) });
    const body = (await response.json()) as { data?: { object?: { asMoveObject?: { contents?: { json?: Record<string, unknown> } } } } };
    const json = body.data?.object?.asMoveObject?.contents?.json;
    if (json !== undefined && json !== null) return json;
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
  return {};
}

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));
  if (typeof parsed === 'string') { say(parsed); return 1; }
  const args = parsed;

  const surface = refuseKeyInProcessSurface({ argv: process.argv, env: process.env });
  if (!surface.ok) { say(surface.refused.reason); return 1; }

  const chain = await loadChainConfig(args.chain);
  if (!chain.ok) { say(chain.refused.reason); return 1; }
  const config = chain.value as ProjectXSocialConfig;
  if (config.network !== 'mainnet') { say(`refused - the chain document is ${config.network}, and a citizen's vault is a mainnet object`); return 1; }

  const key = await loadHotKey({ keyFile: args.keyFile, argv: process.argv, env: process.env });
  if (!key.ok) { say(key.refused.reason); return 1; }
  const doc = await loadMultisigDoc(args.multisig);
  if (!doc.ok) { say(doc.refused.reason); return 1; }
  const wrapped = wrapAsMultisig(doc.value.doc, key.value.signer);
  if (!wrapped.ok) { say(wrapped.refused.reason); return 1; }
  const signer = wrapped.value.signer;
  const address = signer.address;
  say(`signing as ${address} (multisig ${wrapped.value.threshold}-of-${wrapped.value.memberCount}, hot member ${key.value.signer.address})`);

  const client = createClient(config);
  const accountType = `${config.packageId}::account::SocialAccount`;
  const capType = `${config.packageId}::creator::CreatorCap`;

  const owned = async (type: string): Promise<string | null> => {
    const page = await client.core.listOwnedObjects({ owner: address, type, limit: 5 });
    return page.objects[0]?.objectId ?? null;
  };

  const validDuring = async (): Promise<{ ValidDuring: { minEpoch: string; maxEpoch: string; minTimestamp: null; maxTimestamp: null; chain: string; nonce: number } }> => {
    const [{ systemState }, { chainIdentifier }] = await Promise.all([client.core.getCurrentSystemState(), client.core.getChainIdentifier()]);
    const epoch = BigInt(systemState.epoch);
    return { ValidDuring: { minEpoch: String(epoch), maxEpoch: String(epoch + 1n), minTimestamp: null, maxTimestamp: null, chain: chainIdentifier, nonce: (Math.random() * 4294967296) >>> 0 } };
  };

  const run = async (label: string, tx: Transaction): Promise<{ digest: string; created: string[] } | null> => {
    tx.setSender(address);
    tx.setGasPayment([]);
    tx.setGasBudget(GAS_BUDGET);
    tx.setExpiration(await validDuring());
    const bytes = await tx.build({ client });
    const simulated = await client.core.simulateTransaction({ transaction: bytes, include: { effects: true } });
    if (simulated.$kind !== 'Transaction') {
      say(`${label}: the simulation did not produce a transaction: ${JSON.stringify(simulated).slice(0, 400)}`);
      return null;
    }
    const simulatedEffects = simulated.Transaction.effects;
    const status = simulatedEffects.status;
    if (!status.success) {
      say(`${label}: the simulation failed: ${JSON.stringify(status.error)}`);
      return null;
    }
    const gas = simulatedEffects.gasUsed;
    say(`${label}: simulated clean; gas computation ${gas.computationCost} storage ${gas.storageCost} rebate ${gas.storageRebate}`);
    if (args.dryRun) {
      say(`${label}: --dry-run, not signed, not sent`);
      return { digest: '(dry-run)', created: [] };
    }
    const signature = await signer.signTransaction(bytes);
    if (!signature.ok) { say(`${label}: ${signature.failure.detail}`); return null; }
    const executed = await client.core.executeTransaction({ transaction: bytes, signatures: [signature.value], include: { effects: true } });
    if (executed.$kind !== 'Transaction') {
      say(`${label}: the node did not accept the transaction: ${JSON.stringify(executed).slice(0, 400)}`);
      return null;
    }
    const digest = executed.Transaction.digest;
    await client.core.waitForTransaction({ digest });
    const effects = executed.Transaction.effects;
    if (!effects.status.success) {
      say(`${label}: executed ${digest} but the effects report failure: ${JSON.stringify(effects.status.error)}`);
      return null;
    }
    const created = effects.changedObjects.filter((c: { idOperation: string }) => c.idOperation === 'Created').map((c: { objectId: string }) => c.objectId);
    say(`${label}: executed ${digest}; created ${created.length} object(s)`);
    return { digest, created };
  };

  // --- step A: the SocialAccount -------------------------------------------------------------
  let accountId = await owned(accountType);
  const digests: Record<string, string> = {};
  if (accountId !== null) {
    say(`account: ${address} already holds a SocialAccount ${accountId}; not opening another`);
  } else {
    const tx = builders.openAccount({ config }, { handle: args.handle, referrer: args.referrer });
    const result = await run(`account "${args.handle}"`, tx);
    if (result === null) return 1;
    digests['account'] = result.digest;
    if (args.dryRun) {
      say('vault: cannot be simulated until the account exists (open_vault takes the account object); the dry run stops here');
      process.stdout.write(`${JSON.stringify({ address, dryRun: true }, null, 2)}\n`);
      return 0;
    }
    for (const id of result.created) {
      if ((await typeOf(client, id)).endsWith('::account::SocialAccount')) accountId = id;
    }
    if (accountId === null) { say('account: the transaction created no SocialAccount this script can find'); return 1; }
    say(`account: SocialAccount ${accountId}`);
  }

  // --- step B: the vault -----------------------------------------------------------------------
  let capId = await owned(capType);
  let vaultId: string | null = null;
  if (capId !== null) {
    const fields = await fieldsOf(capId);
    vaultId = typeof fields['vault'] === 'string' ? (fields['vault'] as string) : null;
    say(`vault: ${address} already holds CreatorCap ${capId} for vault ${vaultId ?? '(unread)'}; not opening another`);
  } else {
    const tx = new Transaction();
    const [payment] = tx.splitCoins(tx.gas, [0]);
    builders.openCreatorVault({ config, tx }, { coinType: SUI, accountId, paymentCoin: payment!, sender: address });
    const result = await run('vault', tx);
    if (result === null) return 1;
    digests['vault'] = result.digest;
    if (args.dryRun) {
      process.stdout.write(`${JSON.stringify({ address, accountId, dryRun: true }, null, 2)}\n`);
      return 0;
    }
    for (const id of result.created) {
      const type = await typeOf(client, id);
      if (type.endsWith('::creator::CreatorCap')) capId = id;
      if (type.includes('::creator::CreatorVault<')) vaultId = id;
    }
    if (capId === null || vaultId === null) { say(`vault: created objects ${result.created.join(' ')} hold no CreatorCap/CreatorVault pair this script can find`); return 1; }
    say(`vault: CreatorVault ${vaultId}, CreatorCap ${capId}`);
  }

  const out = { address, accountId, vaultId, creatorCapId: capId, digests };
  process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);

  if (args.values !== null && vaultId !== null && capId !== null) {
    const values = JSON.parse(readFileSync(args.values, 'utf8')) as Record<string, string>;
    values[`${args.valuesPrefix}_VAULT_ID`] = vaultId;
    values[`${args.valuesPrefix}_CREATOR_CAP_ID`] = capId;
    writeFileSync(args.values, `${JSON.stringify(values, null, 2)}\n`);
    say(`values: ${args.valuesPrefix}_VAULT_ID and ${args.valuesPrefix}_CREATOR_CAP_ID written to ${args.values}`);
  }
  return 0;
}

main().then((code) => process.exit(code), (error) => { say(String(error instanceof Error ? error.message : error)); process.exit(1); });
