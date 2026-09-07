// Built-by: @projectx.sui
/**
 * The statement intent: the purse signs one of two texts the SDK builds, under the bounds
 * statement.ts names, and refuses everything else as a value.
 */

import { describe, expect, it } from 'vitest';
import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import { verifyPersonalMessageSignature } from '@mysten/sui/verify';
import { statementFor } from '@projectx-social/sdk';
import type { PolicyDoc } from '@projectx-social/policy';
import { AuditFile } from '../src/audit-file.js';
import { fixedGas } from '../src/build.js';
import { SpendLedger } from '../src/ledger-file.js';
import { createPurse, type Purse } from '../src/purse.js';
import { parseServerArgs } from '../src/server.js';
import { readFile as readText } from 'node:fs/promises';
import { dirname, join as joinPath } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MAX_POST_TITLE_LENGTH, MAX_DISPLAY_NAME_LENGTH, MAX_BIO_LENGTH } from '../src/statement.js';
import {
  CAP_ID,
  CHAIN,
  GAS_COIN_ID,
  SUI_TYPE,
  VAULT_ID,
  policyFor,
  setPriceResponse,
  signerFor,
  stubClient,
  stubPort,
  temporaryDirectory,
  throwawayKeypair,
} from './helpers.js';

const ORIGIN = 'https://weir.social';
const NOW = 1_788_000_000_000;
const GAS = fixedGas({ price: 1000n, payment: [{ objectId: GAS_COIN_ID, version: '1', digest: '11111111111111111111111111111111' }] });

interface Harness {
  readonly purse: Purse;
  readonly address: string;
  readonly auditPath: string;
  readonly close: () => Promise<void>;
}

async function harness(options: { readonly statements?: { perDay: number; origin?: string } | 'off'; readonly policy?: Partial<PolicyDoc>; readonly now?: number } = {}): Promise<Harness> {
  const keypair = throwawayKeypair();
  const address = keypair.toSuiAddress();
  const policy = policyFor(address, options.policy ?? {});
  const response = setPriceResponse(address);
  const dir = await temporaryDirectory('heron-statement-');
  const auditPath = join(dir, 'audit.jsonl');
  const opened = await AuditFile.open(auditPath);
  if (!opened.ok) throw new Error(opened.reason);
  const ledger = await SpendLedger.open({ path: join(dir, 'spend.jsonl'), policy });
  if (!ledger.ok) throw new Error(ledger.reason);
  const statements = options.statements === 'off' ? undefined : { origin: options.statements?.origin ?? ORIGIN, perDay: options.statements?.perDay ?? 5, auditPath, vaultId: VAULT_ID };
  const purse = createPurse({
    signer: signerFor(keypair),
    policy,
    policyHash: 'f'.repeat(64),
    policyFileSha256: 'e'.repeat(64),
    chain: CHAIN,
    client: stubClient(response),
    audit: opened.file,
    ledger: ledger.ledger,
    gas: GAS,
    simulation: stubPort(response, address),
    log: () => undefined,
    now: () => options.now ?? NOW,
    ...(statements === undefined ? {} : { statements }),
  });
  return { purse, address, auditPath, close: async () => { await opened.file.close(); await ledger.ledger.close(); } };
}

const publish = (overrides: Record<string, unknown> = {}) => ({
  kind: 'statement',
  action: { kind: 'publish', handle: 'heron', title: 'What the marsh knows', access: 'public', contentSha256: 'a'.repeat(64), contentKey: '', price: '', ...overrides },
  timestampMs: NOW,
  origin: ORIGIN,
});

const nameVault = (overrides: Record<string, unknown> = {}) => ({
  kind: 'statement',
  action: { kind: 'name-vault', vaultId: VAULT_ID, name: 'Heron', bio: 'A Northlatch agent.', coinType: SUI_TYPE, ...overrides },
  timestampMs: NOW,
  origin: ORIGIN,
});

describe('a permitted statement', () => {
  it('signs exactly the text the SDK builds, the signature verifies for the purse address, and the chain records it', async () => {
    const h = await harness();
    const response = await h.purse.handle({ intent: publish() });
    expect(response.ok).toBe(true);
    if (!response.ok) throw new Error(`${response.refused.ruleId}: ${response.refused.reason}`);
    if (!('statement' in response)) throw new Error('a statement was expected');
    const expected = statementFor({ kind: 'publish', handle: 'heron', title: 'What the marsh knows', access: 'public', contentSha256: 'a'.repeat(64), contentKey: '', price: '' }, h.address, NOW, ORIGIN);
    expect(response.statement).toBe(expected);
    expect(response.address).toBe(h.address);
    const key = await verifyPersonalMessageSignature(new TextEncoder().encode(response.statement), response.signature, { address: h.address });
    expect(key.toSuiAddress()).toBe(h.address);
    const lines = (await readFile(h.auditPath, 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines.at(-1)).toMatchObject({ intentKind: 'statement', outcome: 'signed', address: h.address });
    await h.close();
  });

  it('names the vault the policy allows, for the policy\'s coin', async () => {
    const h = await harness();
    const response = await h.purse.handle({ intent: nameVault() });
    expect(response.ok).toBe(true);
    await h.close();
  });

  it('signs a paid publish whose price sits under the daily SUI ceiling', async () => {
    const h = await harness();
    const response = await h.purse.handle({ intent: publish({ access: 'paid', contentKey: 'a'.repeat(64), price: '1000000' }) });
    expect(response.ok).toBe(true);
    await h.close();
  });
});

describe('the bounds', () => {
  it('is off without the flags: refused as statement-disabled, recorded', async () => {
    const h = await harness({ statements: 'off' });
    const response = await h.purse.handle({ intent: publish() });
    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('unreachable');
    expect(response.refused.ruleId).toBe('statement-disabled');
    const lines = (await readFile(h.auditPath, 'utf8')).trim().split('\n').map((l) => JSON.parse(l) as Record<string, unknown>);
    expect(lines.at(-1)).toMatchObject({ intentKind: 'statement', outcome: 'refused', ruleId: 'statement-disabled' });
    await h.close();
  });

  it('refuses another origin', async () => {
    const h = await harness();
    const response = await h.purse.handle({ intent: { ...publish(), origin: 'https://weir-staging.example' } });
    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('unreachable');
    expect(response.refused.ruleId).toBe('statement-origin');
    await h.close();
  });

  it('refuses a statement dated more than a minute from its clock, either way', async () => {
    const h = await harness();
    for (const ts of [NOW - 61_000, NOW + 61_000]) {
      const response = await h.purse.handle({ intent: { ...publish(), timestampMs: ts } });
      expect(response.ok).toBe(false);
      if (response.ok) throw new Error('unreachable');
      expect(response.refused.ruleId).toBe('statement-clock');
    }
    await h.close();
  });

  it('refuses naming a vault outside the policy, an allowed object that is not the vault, or another coin; accepts the short spelling of the same coin', async () => {
    const h = await harness();
    const other = await h.purse.handle({ intent: nameVault({ vaultId: `0x${'9'.repeat(64)}` }) });
    expect(other.ok).toBe(false);
    if (other.ok) throw new Error('unreachable');
    expect(other.refused.ruleId).toBe('statement-object');
    // The cap is an allowed object and is not the vault the purse was started with.
    const cap = await h.purse.handle({ intent: nameVault({ vaultId: CAP_ID }) });
    expect(cap.ok).toBe(false);
    if (cap.ok) throw new Error('unreachable');
    expect(cap.refused.ruleId).toBe('statement-object');
    const short = await h.purse.handle({ intent: nameVault({ coinType: '0x2::sui::SUI' }) });
    expect(short.ok).toBe(true);
    const coin = await h.purse.handle({ intent: nameVault({ coinType: `0x${'0'.repeat(63)}2::usdc::USDC` }) });
    expect(coin.ok).toBe(false);
    if (coin.ok) throw new Error('unreachable');
    expect(coin.refused.ruleId).toBe('statement-object');
    await h.close();
  });

  it('refuses a paid post with no key or price, a public post with either, and a price over the ceiling', async () => {
    const h = await harness();
    for (const bad of [
      { access: 'paid' },
      { access: 'public', price: '5' },
      { access: 'public', contentKey: 'k' },
      { access: 'paid', contentKey: 'k', price: '10000001' },
    ]) {
      const response = await h.purse.handle({ intent: publish(bad) });
      expect(response.ok).toBe(false);
      if (response.ok) throw new Error('unreachable');
      expect(response.refused.ruleId).toBe('statement-price');
    }
    await h.close();
  });

  it('counts signed statements in the last day from the chain on disk and refuses at the ceiling', async () => {
    const h = await harness({ statements: { perDay: 2 } });
    for (let i = 0; i < 2; i += 1) {
      const response = await h.purse.handle({ intent: publish({ title: `post ${String(i)}` }) });
      expect(response.ok).toBe(true);
    }
    const third = await h.purse.handle({ intent: publish({ title: 'post 3' }) });
    expect(third.ok).toBe(false);
    if (third.ok) throw new Error('unreachable');
    expect(third.refused.ruleId).toBe('statement-ceiling');
    expect(third.refused.reason).toContain('2 statements were signed');
    await h.close();
  });

  it('refuses an action the schema does not have, a control character in a title, and an oversized field, as intent-invalid', async () => {
    const h = await harness();
    for (const intent of [
      { ...publish(), action: { kind: 'declare-agent', operator: 'x', model: 'y', purpose: 'z' } },
      publish({ title: 'line one\nline two' }),
      publish({ title: 'x'.repeat(MAX_POST_TITLE_LENGTH + 1) }),
      nameVault({ name: 'x'.repeat(MAX_DISPLAY_NAME_LENGTH + 1) }),
      nameVault({ bio: 'x'.repeat(MAX_BIO_LENGTH + 1) }),
      { ...publish(), extra: true },
    ]) {
      const response = await h.purse.handle({ intent });
      expect(response.ok).toBe(false);
      if (response.ok) throw new Error('unreachable');
      expect(response.refused.ruleId).toBe('intent-invalid');
    }
    await h.close();
  });
});

describe('the flags', () => {
  const base = ['--socket', '/x', '--policy', '/p', '--policy-sha256', 'a'.repeat(64), '--chain', '/c', '--audit', '/a', '--spend', '/s'];
  const vault = `0x${'c'.repeat(64)}`;
  it('takes the three flags together and refuses any subset', () => {
    const all = parseServerArgs([...base, '--api-origin', 'https://weir.social', '--statements-per-day', '96', '--vault', vault]);
    expect(all.ok).toBe(true);
    if (!all.ok) throw new Error('unreachable');
    expect(all.value.apiOrigin).toBe('https://weir.social');
    expect(all.value.statementsPerDay).toBe(96);
    expect(all.value.vault).toBe(vault);
    for (const subset of [
      ['--api-origin', 'https://weir.social'],
      ['--statements-per-day', '96'],
      ['--api-origin', 'https://weir.social', '--statements-per-day', '96'],
      ['--api-origin', 'https://weir.social', '--vault', vault],
    ]) {
      expect(parseServerArgs([...base, ...subset]).ok).toBe(false);
    }
    const path = parseServerArgs([...base, '--api-origin', 'https://weir.social/api', '--statements-per-day', '96', '--vault', vault]);
    expect(path.ok).toBe(false);
    const zero = parseServerArgs([...base, '--api-origin', 'https://weir.social', '--statements-per-day', '0', '--vault', vault]);
    expect(zero.ok).toBe(false);
    const shortVault = parseServerArgs([...base, '--api-origin', 'https://weir.social', '--statements-per-day', '96', '--vault', '0xc']);
    expect(shortVault.ok).toBe(false);
  });
});

describe('the limits are the routes\' own', () => {
  it('pins the title limit to packages/web/lib/content.ts and the name and bio limits to the profile route', async () => {
    const web = joinPath(dirname(fileURLToPath(import.meta.url)), '..', '..', 'web');
    const content = await readText(joinPath(web, 'lib', 'content.ts'), 'utf8');
    const profile = await readText(joinPath(web, 'app', 'api', 'creator', 'profile', 'route.ts'), 'utf8');
    expect(Number(/MAX_POST_TITLE_LENGTH = (\d+)/.exec(content)?.[1])).toBe(MAX_POST_TITLE_LENGTH);
    expect(Number(/MAX_DISPLAY_NAME_LENGTH = (\d+)/.exec(profile)?.[1])).toBe(MAX_DISPLAY_NAME_LENGTH);
    expect(Number(/MAX_BIO_LENGTH = (\d+)/.exec(profile)?.[1])).toBe(MAX_BIO_LENGTH);
  });

  it('refuses a content key with edge whitespace, which the post route refuses too', async () => {
    const h = await harness();
    const response = await h.purse.handle({ intent: publish({ access: 'paid', contentKey: ' k ', price: '1000000' }) });
    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('unreachable');
    expect(response.refused.ruleId).toBe('intent-invalid');
    await h.close();
  });
});

describe('the count survives a restart and refuses a broken chain', () => {
  it('a second purse over the same audit file continues the count', async () => {
    const h = await harness({ statements: { perDay: 2 } });
    expect((await h.purse.handle({ intent: publish({ title: 'one' }) })).ok).toBe(true);
    await h.close();
    // A new purse over the same audit path: seeded from the chain, one already signed.
    const dir = dirname(h.auditPath);
    const opened = await AuditFile.open(h.auditPath);
    if (!opened.ok) throw new Error(opened.reason);
    const keypair = throwawayKeypair();
    const address = keypair.toSuiAddress();
    const policy = policyFor(address);
    const ledger = await SpendLedger.open({ path: joinPath(dir, 'spend2.jsonl'), policy });
    if (!ledger.ok) throw new Error(ledger.reason);
    const again = createPurse({
      signer: signerFor(keypair), policy, policyHash: 'f'.repeat(64), policyFileSha256: 'e'.repeat(64), chain: CHAIN,
      client: stubClient(setPriceResponse(address)), audit: opened.file, ledger: ledger.ledger, gas: GAS,
      simulation: stubPort(setPriceResponse(address), address), log: () => undefined, now: () => NOW,
      statements: { origin: ORIGIN, perDay: 2, auditPath: h.auditPath, vaultId: VAULT_ID },
    });
    expect((await again.handle({ intent: publish({ title: 'two' }) })).ok).toBe(true);
    const third = await again.handle({ intent: publish({ title: 'three' }) });
    expect(third.ok).toBe(false);
    if (third.ok) throw new Error('unreachable');
    expect(third.refused.ruleId).toBe('statement-ceiling');
    await opened.file.close();
    await ledger.ledger.close();
  });
});

