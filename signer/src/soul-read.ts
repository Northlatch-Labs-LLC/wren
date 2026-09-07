// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * Reading the soul, the vault and the epoch off chain.
 *
 * # Why GraphQL and not the SDK
 *
 * There is no TypeScript client for the soul package anywhere in the estate — the CTO's finding F1,
 * still true on this branch. Sui's JSON-RPC on public fullnodes is deprecated. So these are
 * GraphQL reads, written once, here.
 *
 * # A failed read is never a value
 *
 * Every function returns `Outcome`. Nothing in this file has a fallback, a `?? 0`, or a catch that
 * returns an empty object, and nothing may grow one: the caller settles a citizen's epoch on these
 * numbers, and a zero that means "the node did not answer" is indistinguishable from a zero that
 * means "this citizen earned nothing" — one of which retires it.
 */

import { allow, refuse, type Outcome } from './outcome.js';
import type { SoulReading } from './ledger.js';

/** Milliseconds. A settlement runs once a day; there is no reason to wait longer than this. */
const READ_TIMEOUT_MS = 30_000;

async function graphql(endpoint: string, query: string): Promise<Outcome<unknown>> {
  const controller = new AbortController();
  const timer = setTimeout(() => {
    controller.abort();
  }, READ_TIMEOUT_MS);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ query }),
      signal: controller.signal,
    });
    if (!response.ok) {
      return refuse('chain-unreadable', `${endpoint} answered ${String(response.status)}.`);
    }
    const body = (await response.json()) as { data?: unknown; errors?: readonly { message: string }[] };
    if (body.errors && body.errors.length > 0) {
      return refuse('chain-unreadable', `${endpoint}: ${body.errors.map((e) => e.message).join('; ')}`);
    }
    if (body.data === undefined || body.data === null) {
      return refuse('chain-unreadable', `${endpoint} answered with no data.`);
    }
    return allow(body.data);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return refuse('chain-unreadable', `${endpoint} could not be read: ${detail}.`);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * A u64 that arrived as JSON. Refused rather than coerced: `Number` loses precision above 2^53 and
 * every amount here is money.
 */
function u64(value: unknown, field: string): Outcome<bigint> {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    return refuse('chain-unreadable', `${field} was not a u64 decimal string: ${JSON.stringify(value)}`);
  }
  return allow(BigInt(value));
}

export async function readCurrentEpoch(endpoint: string): Promise<Outcome<bigint>> {
  const read = await graphql(endpoint, 'query { epoch { epochId } }');
  if (!read.ok) return read;
  const id = (read.value as { epoch?: { epochId?: unknown } }).epoch?.epochId;
  if (typeof id !== 'number' || !Number.isSafeInteger(id) || id < 0) {
    return refuse('chain-unreadable', `epochId was not a whole number: ${JSON.stringify(id)}`);
  }
  return allow(BigInt(id));
}

export async function readSoul(endpoint: string, soulId: string): Promise<Outcome<SoulReading>> {
  const read = await graphql(
    endpoint,
    `query { object(address: "${soulId}") { asMoveObject { contents { json } } } }`,
  );
  if (!read.ok) return read;
  const json = (
    read.value as { object?: { asMoveObject?: { contents?: { json?: Record<string, unknown> } } } }
  ).object?.asMoveObject?.contents?.json;
  if (!json) return refuse('chain-unreadable', `${soulId} is not a Move object with contents.`);

  const opened = u64(json.epoch_opened_at, 'epoch_opened_at');
  if (!opened.ok) return opened;
  const allowance = u64(json.allowance_per_epoch, 'allowance_per_epoch');
  if (!allowance.ok) return allowance;
  const earned = u64(json.epoch_earned, 'epoch_earned');
  if (!earned.ok) return earned;
  const burned = u64(json.epoch_burned, 'epoch_burned');
  if (!burned.ok) return burned;
  if (typeof json.state !== 'number') return refuse('chain-unreadable', 'state was not a number.');
  if (typeof json.paused !== 'boolean') return refuse('chain-unreadable', 'paused was not a boolean.');
  if (typeof json.critical_epochs !== 'number') {
    return refuse('chain-unreadable', 'critical_epochs was not a number.');
  }

  return allow({
    epochOpenedAt: opened.value,
    allowancePerEpoch: allowance.value,
    epochEarned: earned.value,
    epochBurned: burned.value,
    state: json.state,
    paused: json.paused,
    criticalEpochs: json.critical_epochs,
  });
}

/** The vault's SUI balance: `vault_sui`, the cover the tier is measured against. */
export async function readVaultEarnings(endpoint: string, vaultId: string): Promise<Outcome<bigint>> {
  const read = await graphql(
    endpoint,
    `query { object(address: "${vaultId}") { asMoveObject { contents { json } } } }`,
  );
  if (!read.ok) return read;
  const json = (
    read.value as { object?: { asMoveObject?: { contents?: { json?: Record<string, unknown> } } } }
  ).object?.asMoveObject?.contents?.json;
  if (!json) return refuse('chain-unreadable', `${vaultId} is not a Move object with contents.`);
  return u64(json.earnings, 'earnings');
}

/**
 * What one transaction actually cost, in MIST.
 *
 * `computationCost + storageCost - storageRebate`, which is the number the sender's balance
 * actually moved by. The rebate is subtracted rather than ignored because Sui refunds storage when
 * objects are consumed, and a transaction that freed more than it wrote costs less than nothing —
 * `null` is returned for that case rather than a negative, since a spend is a u64 on chain and
 * "this beat cost nothing" is a true and unremarkable answer.
 *
 * Read AFTER submission, from the chain, never estimated. An estimate booked against an allowance
 * is a number the operator cannot check against anything.
 */
/**
 * The live version and digest of an OWNED object.
 *
 * A shared object is referenced by the version it was shared at, which never changes. An owned
 * object is referenced by its current version and digest, and **both change every time it is
 * used**. So a capability's version cannot be pinned in a policy or a unit file: it is correct for
 * exactly one transaction and stale for every one after.
 *
 * That is not a hypothetical. Wren's `LEDGER_CAP_VERSION` was pinned at 978614786. The first
 * settlement call that landed bumped the cap to 978614793, and the next call in the same run was
 * refused with "provided version doesn't match" — a settlement half-booked: the cost written to
 * her soul and the income not.
 *
 * The build stays fully resolved and offline, which is the property that matters: this read
 * happens before the intent is composed, not inside `build()`.
 */
export async function readOwnedRef(
  endpoint: string,
  objectId: string,
): Promise<Outcome<{ version: string; digest: string }>> {
  const read = await graphql(endpoint, `query { object(address: "${objectId}") { version digest } }`);
  if (!read.ok) return read;
  const object = (read.value as { object?: { version?: unknown; digest?: unknown } }).object;
  if (object === null || object === undefined) {
    return refuse('chain-unreadable', `${endpoint}: object ${objectId} was not found. Nothing was composed.`);
  }
  const { version, digest } = object;
  if (typeof version !== 'number' && typeof version !== 'string') {
    return refuse('chain-unreadable', `${endpoint}: object ${objectId} returned no version. Nothing was composed.`);
  }
  if (typeof digest !== 'string' || digest === '') {
    return refuse('chain-unreadable', `${endpoint}: object ${objectId} returned no digest. Nothing was composed.`);
  }
  return allow({ version: String(version), digest });
}

export async function readTransactionGasMist(
  endpoint: string,
  digest: string,
): Promise<Outcome<bigint | null>> {
  const read = await graphql(
    endpoint,
    `query { transactionEffects(digest: "${digest}") { gasEffects { gasSummary { computationCost storageCost storageRebate } } } }`,
  );
  if (!read.ok) return read;
  const summary = (
    read.value as {
      transactionEffects?: { gasEffects?: { gasSummary?: Record<string, unknown> } };
    }
  ).transactionEffects?.gasEffects?.gasSummary;
  if (!summary) {
    return refuse('chain-unreadable', `${digest} has no gas summary yet; it may not be indexed.`);
  }
  const computation = u64(summary['computationCost'], 'computationCost');
  if (!computation.ok) return computation;
  const storage = u64(summary['storageCost'], 'storageCost');
  if (!storage.ok) return storage;
  const rebate = u64(summary['storageRebate'], 'storageRebate');
  if (!rebate.ok) return rebate;

  const net = computation.value + storage.value - rebate.value;
  return allow(net > 0n ? net : null);
}
