// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The clock's hand: close yesterday's epoch, book what it earned and what it cost, settle it.
 *
 * # What runs this
 *
 * `<agent>-ledger.timer`, daily. A different unit, a different systemd user, a different credential
 * and a different policy document from the beat: the settlement key may call `settle_epoch`,
 * `book_earned` and `book_burned` and nothing else, and the content key may call
 * `set_content_price` and `record_spend` and nothing else. One signer per money path, so a
 * settlement can never consume the content ceiling and a compromised beat cannot settle.
 *
 * # Why it refuses to retire a citizen on its own
 *
 * `settle_epoch` retires the soul itself after `MAX_CRITICAL` (2) consecutive critical epochs, in
 * the same call, with no second signature. A timer that fires that call unattended is a timer that
 * ends a citizen's life at 03:00 with nobody in the room. So when the plan says this settlement is
 * the one that would retire, this exits 4 and does nothing. `--allow-retire` is the operator
 * saying, in the unit file or by hand, that they mean it.
 *
 * Exit codes: 0 settled, 0 nothing to do, 3 refused, 4 would retire and was not allowed to, 1 error.
 */

import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import { loadChainConfig } from '../src/chain.js';
import { askPurse } from '../src/client.js';
import { planLedgerTick } from '../src/ledger.js';
import { readCurrentEpoch, readOwnedRef, readSoul, readVaultEarnings } from '../src/soul-read.js';
import { createClient } from '@projectx-social/sdk';

const FLAGS = [
  '--agent',
  '--chain',
  '--socket',
  '--graphql',
  '--package',
  '--registry',
  '--registry-version',
  '--soul',
  '--soul-version',
  '--vault',
  '--ledger-cap',
  '--ledger-cap-version',
  '--ledger-cap-digest',
  '--clock',
  '--clock-version',
  '--burn-per-epoch-mist',
  '--state',
] as const;

const values = new Map<string, string>();
let allowRetire = false;
const argv = process.argv.slice(2);
for (let i = 0; i < argv.length; i += 1) {
  const flag = argv[i]!;
  if (flag === '--allow-retire') {
    allowRetire = true;
    continue;
  }
  if (!FLAGS.includes(flag as (typeof FLAGS)[number])) {
    console.error(
      `ledger-tick: ${flag} is not a flag this takes. It takes: ${FLAGS.join(' ')} [--allow-retire].`,
    );
    process.exit(1);
  }
  const value = argv[i + 1];
  if (value === undefined || value.startsWith('--')) {
    console.error(`ledger-tick: ${flag} needs a value.`);
    process.exit(1);
  }
  values.set(flag, value);
  i += 1;
}
for (const flag of FLAGS) {
  if (!values.has(flag)) {
    console.error(
      `ledger-tick: ${flag} is required. Nothing is defaulted here: every one of these names an ` +
        `object on mainnet or the cost of a day.`,
    );
    process.exit(1);
  }
}

const agent = values.get('--agent')!;
const prefix = `${agent}-ledger`;
const burnRaw = values.get('--burn-per-epoch-mist')!;
if (!/^(0|[1-9][0-9]{0,19})$/.test(burnRaw)) {
  console.error(`${prefix}: --burn-per-epoch-mist is a u64 written as a decimal string.`);
  process.exit(1);
}
const burnPerEpochMist = BigInt(burnRaw);

const chain = await loadChainConfig(values.get('--chain')!);
if (!chain.ok) {
  console.error(`${prefix}: ${chain.refused.reason}`);
  process.exit(1);
}

const endpoint = values.get('--graphql')!;
const statePath = values.get('--state')!;

const epoch = await readCurrentEpoch(endpoint);
if (!epoch.ok) {
  console.error(`${prefix}: ${epoch.refused.reason}`);
  process.exit(1);
}
const soul = await readSoul(endpoint, values.get('--soul')!);
if (!soul.ok) {
  console.error(`${prefix}: ${soul.refused.reason}`);
  process.exit(1);
}
const vault = await readVaultEarnings(endpoint, values.get('--vault')!);
if (!vault.ok) {
  console.error(`${prefix}: ${vault.refused.reason}`);
  process.exit(1);
}

/*
  The balance this service saw at the last settlement. A missing file is a first run and reads as
  zero; a file that exists and cannot be parsed is NOT a first run and must not be treated as one,
  because reading it as zero would book the whole vault as this epoch's earnings.
*/
let lastSeenEarningsMist = 0n;
try {
  const raw = await readFile(statePath, 'utf8');
  const parsed = JSON.parse(raw) as { lastSeenEarningsMist?: unknown };
  if (
    typeof parsed.lastSeenEarningsMist !== 'string' ||
    !/^(0|[1-9][0-9]{0,19})$/.test(parsed.lastSeenEarningsMist)
  ) {
    console.error(
      `${prefix}: ${statePath} exists but its lastSeenEarningsMist is not a u64 string. Refusing to guess.`,
    );
    process.exit(1);
  }
  lastSeenEarningsMist = BigInt(parsed.lastSeenEarningsMist);
} catch (error) {
  if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
    console.error(`${prefix}: ${statePath} could not be read: ${(error as Error).message}`);
    process.exit(1);
  }
}

const plan = planLedgerTick({
  currentEpoch: epoch.value,
  soul: soul.value,
  vaultEarningsMist: vault.value,
  lastSeenEarningsMist,
  burnPerEpochMist,
});

if (plan.kind === 'wait') {
  console.log(`${prefix}: nothing to do — ${plan.reason}`);
  process.exit(0);
}

console.log(
  `${prefix}: epoch ${String(soul.value.epochOpenedAt)} closing at chain epoch ${String(epoch.value)}; ` +
    `earned ${String(plan.bookEarnedMist)} burned ${String(plan.bookBurnedMist)} ` +
    `cover ${String(plan.vaultSui)} against allowance ${String(soul.value.allowancePerEpoch)}; ` +
    `net ${plan.epochNetNonneg ? 'non-negative' : 'NEGATIVE'}${plan.willBeCritical ? '; CRITICAL' : ''}`,
);

if (plan.willRetire && !allowRetire) {
  console.error(
    `${prefix}: REFUSING. This settlement is the second consecutive critical epoch, so settle_epoch ` +
      `would retire ${agent} inside the same call. The vault holds ${String(plan.vaultSui)} MIST ` +
      `against an allowance of ${String(soul.value.allowancePerEpoch)} MIST. Give the citizen cover, ` +
      `lower the allowance, or pass --allow-retire if ending it is what you mean.`,
  );
  process.exit(4);
}

const packageId = values.get('--package')!;
/*
  The cap's IDENTITY is pinned; its version is not, and must not be.

  `--ledger-cap-version` and `--ledger-cap-digest` still arrive from the unit file, and they are
  still checked below, because an operator declaring which capability this settlement may use is
  the point. But an owned object's version and digest change every time it is used, so what the
  unit file pins is only ever the state the cap was in when the unit was written.

  Wren's was pinned at 978614786. `book_burned` landed and moved it to 978614793, and `book_earned`
  in the same run was refused with "provided version doesn't match": the cost booked against her
  soul and the income not. That is the worst possible half of a settlement to land.

  So the ref is read from the chain immediately before each call, and the pinned pair is used to
  assert the cap is the one the operator named, not to compose the transaction.
*/
const ledgerCapId = values.get('--ledger-cap')!;
const pinnedCapVersion = values.get('--ledger-cap-version')!;

/*
  Read the capability, and when a previous call has just moved it, WAIT for the move to be visible.

  The GraphQL endpoint is an indexer, not the fullnode: it trails the chain by a moment. Asking it
  for the cap immediately after a transaction lands returns the version from before that
  transaction, and the next call is then refused against a version that is already spent. That is
  not a hypothetical either — it is what happened at 16:42, one second after `book_earned` landed:
  provided 978614793, actual 978614794.

  So `after` is the version this settlement has just consumed, and the read retries until it sees
  something newer. Bounded: sixteen tries at 750ms is twelve seconds, far longer than the indexer
  needs, and a settlement that cannot see its own last transaction after twelve seconds is a
  settlement that should stop rather than compose against a stale reference.
*/
async function liveLedgerCap(after?: string): Promise<{ objectId: string; version: string; digest: string }> {
  const endpoint = values.get('--graphql')!;
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const read = await readOwnedRef(endpoint, ledgerCapId);
    if (!read.ok) {
      console.error(`${prefix}: the settlement capability could not be read — ${read.refused.reason}`);
      process.exit(1);
    }
    if (after === undefined || BigInt(read.value.version) > BigInt(after)) {
      return { objectId: ledgerCapId, version: read.value.version, digest: read.value.digest };
    }
    await new Promise((resolve) => setTimeout(resolve, 750));
  }
  console.error(
    `${prefix}: the settlement capability is still at version ${after} twelve seconds after the ` +
      `transaction that moved it. Nothing further has been composed; the epoch is not settled.`,
  );
  process.exit(1);
}

const firstCap = await liveLedgerCap();
if (BigInt(firstCap.version) < BigInt(pinnedCapVersion)) {
  /*
    Older than the unit file's pin means this is not the object the operator declared — a rollback,
    a different network, or a wrong id. Newer is normal and expected: it means the cap has been
    used since the unit was written, which is exactly what a working settlement does.
  */
  console.error(
    `${prefix}: capability ${ledgerCapId} is at version ${firstCap.version}, older than the ` +
      `${pinnedCapVersion} this unit was installed against. Refusing rather than composing ` +
      `against an object that is not the one named.`,
  );
  process.exit(3);
}
const ledgerCap = firstCap;
const soulRef = {
  objectId: values.get('--soul')!,
  initialSharedVersion: values.get('--soul-version')!,
  mutable: true,
};

/*
  Every ask in order. A refusal anywhere stops the rest: a half-booked epoch must not be settled.

  The intent is composed by a function rather than held as a value, because each call moves the
  capability and the next one has to see where it moved to.
*/
type Cap = { objectId: string; version: string; digest: string };
const asks: { readonly what: string; readonly intent: (cap: Cap) => unknown }[] = [];
if (plan.bookEarnedMist > 0n) {
  asks.push({
    what: 'book_earned',
    intent: (cap) => ({
      kind: 'book_earned',
      packageId,
      ledgerCap: cap,
      soul: soulRef,
      amountMist: String(plan.bookEarnedMist),
    }),
  });
}
if (plan.bookBurnedMist > 0n) {
  asks.push({
    what: 'book_burned',
    intent: (cap) => ({
      kind: 'book_burned',
      packageId,
      ledgerCap: cap,
      soul: soulRef,
      amountMist: String(plan.bookBurnedMist),
    }),
  });
}
asks.push({
  what: 'settle_epoch',
  intent: (cap) => ({
    kind: 'settle_epoch',
    packageId,
    ledgerCap: cap,
    registry: {
      objectId: values.get('--registry')!,
      initialSharedVersion: values.get('--registry-version')!,
      mutable: true,
    },
    soul: soulRef,
    clock: {
      objectId: values.get('--clock')!,
      initialSharedVersion: values.get('--clock-version')!,
      mutable: false,
    },
    vaultSui: String(plan.vaultSui),
    epochNetNonneg: plan.epochNetNonneg,
  }),
});

const socketPath = values.get('--socket')!;

/*
  Signed is not settled.

  This loop used to ask the purse for a signature, print "<what> signed.", and move on. Nothing
  submitted the signed bytes to anything. On 2026-09-07 at 03:34 it signed `book_earned`,
  `book_burned` and `settle_epoch`, printed "epoch settled", wrote its watermark and exited 0 —
  and the chain recorded none of it. The settlement account had never sent a transaction in its
  life. `bin/beat-phase2.ts` had a submit port from the day it was written; this file never did.

  So: submit, read the effects, and treat anything but SUCCESS as a failure. The three envelope
  shapes are the same three `packages/agent/src/tx.ts` reads, for the same reason it reads them.
*/
const client = createClient(chain.value);

async function submitSigned(txBytesB64: string, signature: string): Promise<string> {
  const result = (await client.executeTransaction({
    transaction: Uint8Array.from(Buffer.from(txBytesB64, 'base64')),
    signatures: [signature],
  })) as { Transaction?: { digest?: string }; transaction?: { digest?: string }; digest?: string };
  const digest = result.Transaction?.digest ?? result.transaction?.digest ?? result.digest;
  if (typeof digest !== 'string' || digest === '') {
    throw new Error(
      'the transaction was submitted and the node returned no digest in any envelope this client ' +
        'knows. Check the chain before retrying — it may well have succeeded.',
    );
  }
  return digest;
}

const landed: string[] = [];
/** The cap version this settlement has already spent. Null until the first call lands. */
let usedVersion: string | null = null;
for (const ask of asks) {
  const cap: Cap = usedVersion === null ? ledgerCap : await liveLedgerCap(usedVersion);
  const answer = await askPurse({ socketPath, intent: ask.intent(cap) });
  if (!answer.ok) {
    console.error(`${prefix}: ${ask.what} — ${answer.refused.reason}`);
    process.exit(3);
  }
  if (!answer.value.ok) {
    console.error(`${prefix}: ${ask.what} refused — ${JSON.stringify(answer.value)}`);
    process.exit(3);
  }
  const signed = answer.value as { ok: true; txBytesB64: string; signature: string };
  let digest: string;
  try {
    digest = await submitSigned(signed.txBytesB64, signed.signature);
  } catch (thrown) {
    /*
      Exit 1, not 3. A refusal is the policy saying no and nothing being sent; this is a
      transaction that may well be on chain. The watermark below is not written, so the next run
      recomputes the whole settlement from the chain rather than skipping it.
    */
    console.error(
      `${prefix}: ${ask.what} was signed and the submit threw: ` +
        `${thrown instanceof Error ? thrown.message : String(thrown)} ` +
        `Nothing has been recorded as settled. Check the chain before running this again.`,
    );
    process.exit(1);
  }
  usedVersion = cap.version;
  landed.push(`${ask.what}=${digest}`);
  console.log(`${prefix}: ${ask.what} landed ${digest}`);
}

/*
  Written only after all three transactions LANDED, not merely after they were signed.

  The earlier version wrote it after signing. On 2026-09-07 that moved the watermark to 0.9697 SUI
  for a settlement that never reached the chain, so the next run would have seen a zero delta and
  booked nothing — the first day's earnings marked counted while the soul still read zero. Signing
  is not landing, and a watermark is a claim about the chain, so only the chain may move it.
*/
await mkdir(dirname(statePath), { recursive: true });
await writeFile(
  statePath,
  `${JSON.stringify({ lastSeenEarningsMist: String(plan.vaultSui), settledAtEpoch: String(epoch.value) }, null, 2)}\n`,
  'utf8',
);
console.log(`${prefix}: epoch settled — ${landed.join(' ')}`);
process.exit(0);
