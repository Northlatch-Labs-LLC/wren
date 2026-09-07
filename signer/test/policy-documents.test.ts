// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The two shipped policy documents, read from `policy/` and evaluated.
 *
 * A3 from Security's review of 2026-09-05: "`settle_epoch` is separated by a policy document that
 * does not exist". The binary that holds the hot key can build a `LedgerCap` call — `intent.ts`
 * carries the kind on purpose, because the settlement signer is this same program with a different
 * key — and the only thing that stops it is the deployed document's `allowedTargets`. Until this
 * file existed, no document was on the branch and no test asserted the separation, so decision 6's
 * "one signer per money path" was a sentence in a comment.
 *
 * Three properties are asserted here, each against the real loader and the real evaluator:
 *
 *  1. The content document refuses a **well-formed** `settle_epoch`, by target.
 *  2. The ledger document refuses `post` and `price`, by target.
 *  3. A document naming both arms stops the purse at start, before a key is held open.
 *
 * # Why the documents are loaded and rendered rather than written inline
 *
 * A fixture that restated the document would pass while the shipped file said something else. The
 * files in `policy/` are read here byte for byte; the only thing this file changes is the four
 * addresses and the soul package id, which are `<ANGLE_BRACKET>` substitutions because **no Heron
 * key exists yet** and **the soul package is unpublished** — the same convention, and the same
 * reason, as `<POLICY_SHA256>` in `systemd/heron-purse.service`.
 */

import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { MultiSigPublicKey } from '@mysten/sui/multisig';
import { publicKeyFromSuiBytes } from '@mysten/sui/verify';
import { loadMultisigDoc } from '../src/multisig-file.js';
import type { PolicyDoc } from '@projectx-social/policy';
import { AuditFile } from '../src/audit-file.js';
import { fixedGas } from '../src/build.js';
import { SpendLedger } from '../src/ledger-file.js';
import { loadPinnedPolicy, refuseMixedMoneyPaths } from '../src/policy-file.js';
import { createPurse, type Purse } from '../src/purse.js';
import { startPurse } from '../src/server.js';
import {
  CHAIN,
  CLOCK_ID,
  GAS_COIN_ID,
  LEDGER_CAP_ID,
  REGISTRY_ID,
  SETTLE_EPOCH,
  SET_CONTENT_PRICE,
  SOUL_ID,
  SOUL_PACKAGE,
  policyFor,
  postIntentFor,
  priceIntentFor,
  setPriceResponse,
  settleEpochIntentFor,
  settleEpochResponse,
  signerFor,
  stubClient,
  stubPort,
  temporaryDirectory,
  throwawayKeypair,
} from './helpers.js';

const POLICY_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'policy');

const GAS = fixedGas({
  price: 1000n,
  payment: [{ objectId: GAS_COIN_ID, version: '1', digest: '11111111111111111111111111111111' }],
});

/** The substitutions `digitalocean/deploy.sh` fills. Fixture values stand in for them here. */
function rendered(text: string, agentAddress: string): string {
  return text
    .replaceAll('<HERON_ADDRESS>', agentAddress)
    .replaceAll('<LEDGER_ADDRESS>', agentAddress)
    .replaceAll('<OPERATOR_ADDRESS>', `0x${'d'.repeat(64)}`)
    .replaceAll('<TREASURY_ADDRESS>', `0x${'e'.repeat(64)}`)
    .replaceAll('<HERON_VAULT_ID>', `0x${'1'.repeat(64)}`)
    .replaceAll('<HERON_CREATOR_CAP_ID>', `0x${'2'.repeat(64)}`)
    .replaceAll('<SOUL_PACKAGE_ID>', SOUL_PACKAGE)
    .replaceAll('<LEDGER_CAP_ID>', LEDGER_CAP_ID)
    .replaceAll('<SOUL_REGISTRY_ID>', REGISTRY_ID)
    .replaceAll('<HERON_SOUL_ID>', SOUL_ID)
    .replaceAll('<CLOCK_ID>', CLOCK_ID);
}

/** Load one of the shipped documents through the real loader, rendered for a throwaway address. */
async function shipped(name: string, agentAddress: string): Promise<PolicyDoc> {
  const raw = await readFile(join(POLICY_DIR, name), 'utf8');
  const dir = await temporaryDirectory('heron-policy-');
  const path = join(dir, name);
  const text = rendered(raw, agentAddress);
  await writeFile(path, text, 'utf8');
  const pin = createHash('sha256').update(text, 'utf8').digest('hex');

  const loaded = await loadPinnedPolicy({ path, expectedSha256: pin });
  if (!loaded.ok) throw new Error(`${name} did not load: ${loaded.refused.reason}`);
  return loaded.value.doc;
}

interface Harness {
  readonly purse: Purse;
  readonly close: () => Promise<void>;
}

async function purseOver(policy: PolicyDoc, response: unknown, address: string): Promise<Harness> {
  const dir = await temporaryDirectory();
  const audit = await AuditFile.open(join(dir, 'audit.jsonl'));
  if (!audit.ok) throw new Error(audit.reason);
  const ledger = await SpendLedger.open({ path: join(dir, 'spend.jsonl'), policy });
  if (!ledger.ok) throw new Error(ledger.reason);

  return {
    purse: createPurse({
      signer: signerFor(keypairsByAddress.get(address)!),
      policy,
      policyHash: 'f'.repeat(64),
      policyFileSha256: 'e'.repeat(64),
      chain: CHAIN,
      client: stubClient(response),
      audit: audit.file,
      ledger: ledger.ledger,
      gas: GAS,
      simulation: stubPort(response, address),
      log: () => undefined,
    }),
    close: async () => {
      await audit.file.close();
      await ledger.ledger.close();
    },
  };
}

const keypairsByAddress = new Map<string, Ed25519Keypair>();
function throwaway(): string {
  const keypair = throwawayKeypair();
  const address = keypair.toSuiAddress();
  keypairsByAddress.set(address, keypair);
  return address;
}

describe('policy/heron-content.json — the content arm', () => {
  it('refuses a well-formed settle_epoch, by target', async () => {
    const address = throwaway();
    const policy = await shipped('heron-content.json', address);
    const h = await purseOver(policy, settleEpochResponse(address), address);

    const response = await h.purse.handle({ intent: settleEpochIntentFor() });

    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('unreachable');
    expect(response.refused.ruleId).toBe('move-call-target');
    expect(response.refused.reason).toContain('settle_epoch');
    await h.close();
  });

  it('names three recipients, SUI only, and the 0.4 SUI epoch ceiling', async () => {
    const address = throwaway();
    const policy = await shipped('heron-content.json', address);

    expect(policy.allowedRecipients).toHaveLength(3);
    expect(policy.allowedRecipients[0]).toBe(address);
    expect(policy.allowedTypeArguments).toEqual([`0x${'0'.repeat(63)}2::sui::SUI`]);
    expect(policy.outflowCeilings).toHaveLength(1);
    expect(policy.outflowCeilings[0]!.maxPerPeriod).toBe('400000000');
    expect(policy.maxGasBudgetMist).toBe('20000000');
  });

  it('allows the post and price entry and record_spend, and nothing else', async () => {
    const policy = await shipped('heron-content.json', throwaway());
    expect(policy.allowedTargets).toHaveLength(2);
    expect(policy.allowedTargets.some((t) => t.endsWith('::creator::set_content_price'))).toBe(true);
    expect(policy.allowedTargets.some((t) => t.endsWith('::soul::record_spend'))).toBe(true);
    expect(policy.allowedTargets.some((t) => t.endsWith('::soul::settle_epoch'))).toBe(false);
  });

  it('pins the package on every target — no bare module::function', async () => {
    const policy = await shipped('heron-content.json', throwaway());
    for (const target of policy.allowedTargets) {
      expect(target).toMatch(/^0x[0-9a-f]{1,64}::[a-z_]+::[a-z_]+$/);
    }
  });
});

describe('policy/heron-ledger.json — the LedgerCap service', () => {
  it('refuses a price intent, by target', async () => {
    const address = throwaway();
    const policy = await shipped('heron-ledger.json', address);
    const h = await purseOver(policy, setPriceResponse(address), address);

    const response = await h.purse.handle({ intent: priceIntentFor() });

    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('unreachable');
    expect(response.refused.ruleId).toBe('move-call-target');
    await h.close();
  });

  it('refuses a post intent, by target', async () => {
    const address = throwaway();
    const policy = await shipped('heron-ledger.json', address);
    const h = await purseOver(policy, setPriceResponse(address), address);

    const response = await h.purse.handle({ intent: postIntentFor() });

    expect(response.ok).toBe(false);
    if (response.ok) throw new Error('unreachable');
    expect(response.refused.ruleId).toBe('move-call-target');
    await h.close();
  });

  it('names the three LedgerCap calls and nothing else', async () => {
    const policy = await shipped('heron-ledger.json', throwaway());
    expect(policy.allowedTargets).toEqual([
      SETTLE_EPOCH,
      SETTLE_EPOCH.replace('::settle_epoch', '::book_earned'),
      SETTLE_EPOCH.replace('::settle_epoch', '::book_burned'),
    ]);
  });
});

describe('one signer per money path', () => {
  /*
    Decision 6 keeps the caps on separate keys and separate services. Two documents that each keep
    to one arm are only half of that: the half that fails is an operator pasting both target sets
    into one file to "simplify the deploy", at which point one key signs both money paths and a
    settlement can consume the content ceiling.

    The purse refuses to start on such a document. At start, not per transaction: a purse that
    caught it per transaction would already be holding the key.
  */
  async function startWith(
    targets: readonly string[],
  ): Promise<Awaited<ReturnType<typeof startPurse>> & { socketPath: string }> {
    const dir = await temporaryDirectory();
    const keypair = Ed25519Keypair.generate();
    const address = keypair.toSuiAddress();

    const keyPath = join(dir, 'heron-hot');
    await writeFile(keyPath, `${keypair.getSecretKey()}\n`, { mode: 0o600 });

    const policyPath = join(dir, 'heron-policy.json');
    const text = `${JSON.stringify(policyFor(address, { allowedTargets: [...targets] }), null, 2)}\n`;
    await writeFile(policyPath, text, 'utf8');

    const chainPath = join(dir, 'chain.json');
    await writeFile(chainPath, JSON.stringify(CHAIN), 'utf8');

    const socketPath = join(dir, 'purse.sock');
    const outcome = await startPurse({
      server: {
        socket: socketPath,
        policy: policyPath,
        policySha256: createHash('sha256').update(text, 'utf8').digest('hex'),
        chain: chainPath,
        audit: join(dir, 'audit.jsonl'),
        spend: join(dir, 'spend.jsonl'),
        keyFile: keyPath,
      },
      argv: ['node', 'server.js'],
      env: {},
      log: () => undefined,
    });
    return Object.assign(outcome, { socketPath });
  }

  it('refuses to start on a document that allows a content entry and settle_epoch', async () => {
    const started = await startWith([
      `0x${'0'.repeat(62)}c5::creator::set_content_price`,
      SETTLE_EPOCH,
    ]);

    expect(started.ok).toBe(false);
    if (started.ok) throw new Error('unreachable');
    expect(started.refused.reason).toContain('One signer per money path');
    expect(started.refused.reason).toContain('settle_epoch');
  });

  it('starts on a document that keeps to the content arm', async () => {
    const started = await startWith([`0x${'0'.repeat(62)}c5::creator::set_content_price`]);
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.refused.reason);
    await started.value.stop();
  });

  it('starts on a document that keeps to settle_epoch', async () => {
    const started = await startWith([SETTLE_EPOCH]);
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.refused.reason);
    await started.value.stop();
  });
});

describe('policy/heron-multisig.json, the committed members document', () => {
  /*
    Heron's real members: the hot key born 2026-09-05 and the brake key read from the chain. The
    address is what the SDK derives from them, computed here rather than restated, and compared to
    the one written in the estate's records so the document and the records cannot drift apart.
  */
  const HERON_ADDRESS = '0xe8345fea67b57baf5461446852c4badeb8936e2af7cc390fc5c16be0337ddd70';
  const HOT_ADDRESS = '0x51704a474f342e9f50a408f8be090b05ae73b17b98a0f8f7597abb62ec4310b0';
  const BRAKE_ADDRESS = '0x4668e5bf1dfd48129d6037d027c344577163f9685389be1f43a8a8e9ce726c9a';

  it('loads through the real loader, has two members at weight 1 and threshold 1', async () => {
    const loaded = await loadMultisigDoc(join(POLICY_DIR, 'heron-multisig.json'));
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error('unreachable');
    expect(loaded.value.doc.threshold).toBe(1);
    expect(loaded.value.doc.members.map((m) => [m.name, m.weight])).toEqual([['hot', 1], ['brake', 1]]);
  });

  it('derives the address the records name, from the members the records name', async () => {
    const loaded = await loadMultisigDoc(join(POLICY_DIR, 'heron-multisig.json'));
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    const keys = loaded.value.doc.members.map((m) => publicKeyFromSuiBytes(m.publicKey));
    expect(keys[0]!.toSuiAddress()).toBe(HOT_ADDRESS);
    expect(keys[1]!.toSuiAddress()).toBe(BRAKE_ADDRESS);
    const derived = MultiSigPublicKey.fromPublicKeys({
      threshold: loaded.value.doc.threshold,
      publicKeys: loaded.value.doc.members.map((m, i) => ({ publicKey: keys[i]!, weight: m.weight })),
    });
    expect(derived.toSuiAddress()).toBe(HERON_ADDRESS);
  });
});

describe('policy/heron-content-pre-soul.json, the document the purse runs under before the soul exists', () => {
  const HERON_ADDRESS = '0xe8345fea67b57baf5461446852c4badeb8936e2af7cc390fc5c16be0337ddd70';

  it('loads through the real pinned loader with no substitution left in it', async () => {
    const path = join(POLICY_DIR, 'heron-content-pre-soul.json');
    const text = await readFile(path, 'utf8');
    expect(text).not.toContain('<');
    const loaded = await loadPinnedPolicy({ path, expectedSha256: createHash('sha256').update(text, 'utf8').digest('hex') });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    expect(loaded.value.doc.agentAddress).toBe(HERON_ADDRESS);
    expect(loaded.value.doc.allowedObjects).toEqual([]);
    expect(loaded.value.doc.allowedRecipients).toEqual([HERON_ADDRESS]);
  });

  it('refuses a price intent at the object allowlist, so a purse under it signs nothing until the vault exists', async () => {
    const path = join(POLICY_DIR, 'heron-content-pre-soul.json');
    const text = await readFile(path, 'utf8');
    const loaded = await loadPinnedPolicy({ path, expectedSha256: createHash('sha256').update(text, 'utf8').digest('hex') });
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    const dir = await temporaryDirectory();
    const audit = await AuditFile.open(join(dir, 'audit.jsonl'));
    if (!audit.ok) throw new Error(audit.reason);
    const ledger = await SpendLedger.open({ path: join(dir, 'spend.jsonl'), policy: loaded.value.doc });
    if (!ledger.ok) throw new Error(ledger.reason);
    // The signer stands in for the multisig; only the address matters to the policy.
    const signer = { ...signerFor(throwawayKeypair()), address: HERON_ADDRESS };
    const response = setPriceResponse(HERON_ADDRESS);
    // The real v5 package, so the built target matches the document's and the refusal is the
    // objects rule's, not the target rule's.
    const V5 = '0xdc6dbb96885ba049c5d860d0b775b9e968cf9053a227861ae006f22e352884b5';
    const purse: Purse = createPurse({
      signer,
      policy: loaded.value.doc,
      policyHash: loaded.value.policyHash,
      policyFileSha256: loaded.value.fileSha256,
      chain: { ...CHAIN, latestPackageId: V5 },
      client: stubClient(response),
      audit: audit.file,
      ledger: ledger.ledger,
      gas: GAS,
      simulation: stubPort(response, HERON_ADDRESS),
      log: () => undefined,
    });
    const answered = await purse.handle({ intent: priceIntentFor() });
    expect(answered.ok).toBe(false);
    if (answered.ok) throw new Error('unreachable');
    // The recorded simulation calls the fixture package, so under the document as committed the
    // target rule speaks first. The claim under test is the EMPTY object list: with the fixture's
    // target admitted and nothing else changed, the refusal is the objects rule's.
    expect(answered.refused.ruleId).toBe('move-call-target');
    const targetAdmitted: Purse = createPurse({
      signer,
      policy: { ...loaded.value.doc, allowedTargets: [SET_CONTENT_PRICE] },
      policyHash: loaded.value.policyHash,
      policyFileSha256: loaded.value.fileSha256,
      chain: CHAIN,
      client: stubClient(response),
      audit: audit.file,
      ledger: ledger.ledger,
      gas: GAS,
      simulation: stubPort(response, HERON_ADDRESS),
      log: () => undefined,
    });
    const objectsRefused = await targetAdmitted.handle({ intent: priceIntentFor() });
    expect(objectsRefused.ok).toBe(false);
    if (objectsRefused.ok) throw new Error('unreachable');
    expect(objectsRefused.refused.ruleId).toBe('object-input');
    await audit.file.close();
  });
});

describe('policy/heron-chain.mainnet.json, the chain document the purse reads on the host', () => {
  it('loads through the real loader and names the packages Published.toml records', async () => {
    const { loadChainConfig } = await import('../src/chain.js');
    const loaded = await loadChainConfig(join(POLICY_DIR, 'heron-chain.mainnet.json'));
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    expect(loaded.value.network).toBe('mainnet');
    const published = await readFile(join(POLICY_DIR, '..', '..', '..', 'sui-contracts', 'Published.toml'), 'utf8');
    const publishedAt = /published-at = "(0x[0-9a-f]+)"/.exec(published)?.[1];
    const originalId = /original-id = "(0x[0-9a-f]+)"/.exec(published)?.[1];
    expect(loaded.value.latestPackageId).toBe(publishedAt);
    expect(loaded.value.packageId).toBe(originalId);
    // The platform and registry are the shared objects the original package's publish transaction
    // created (DbB4fSp7GV9C2UTRWe2T7f8G7ddT8fo4QjnnBtLddpct, read from mainnet 2026-09-05).
    expect(loaded.value.platformId).toBe('0x3f695b2c32714e2359c4bb9515598d8dd765b216148c5b8fa818073d52b50f36');
    expect(loaded.value.registryId).toBe('0x1a3fb4ac25458d7524be064a2b7e1586ccd9ed09c0d5b351621e3b101e1203a0');
  });
});

describe('policy/heron-content.mainnet.json, the rendered content policy the purse runs under once the vault exists', () => {
  it('equals the render of the template with the committed values, pre-soul, and loads through the pinned loader', async () => {
    const { renderPolicy } = await import('../bin/render-policy.js');
    const template = await readFile(join(POLICY_DIR, 'heron-content.json'), 'utf8');
    const values = JSON.parse(await readFile(join(POLICY_DIR, 'heron-values.json'), 'utf8')) as Record<string, string>;
    const rendered = renderPolicy(template, values, true);
    expect(rendered.ok).toBe(true);
    if (!rendered.ok) throw new Error(rendered.reason);
    const committed = await readFile(join(POLICY_DIR, 'heron-content.mainnet.json'), 'utf8');
    expect(committed).toBe(rendered.text);
    const loaded = await loadPinnedPolicy({ path: join(POLICY_DIR, 'heron-content.mainnet.json'), expectedSha256: createHash('sha256').update(committed, 'utf8').digest('hex') });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    expect(loaded.value.doc.agentAddress).toBe('0xe8345fea67b57baf5461446852c4badeb8936e2af7cc390fc5c16be0337ddd70');
    expect(loaded.value.doc.allowedObjects).toEqual([
      '0x0c3f3a6174293544f3ac61e466d9ebe62edb88cca2f3674cbd9311df8e736b68',
      '0xea9ba87eb3a50e9113bc08aba8a4fb227d28371335ebcab43a235c316357d0d0',
      '0x0000000000000000000000000000000000000000000000000000000000000006',
    ]);
    expect(loaded.value.doc.allowedTargets).toEqual(['0xdc6dbb96885ba049c5d860d0b775b9e968cf9053a227861ae006f22e352884b5::creator::set_content_price']);
  });
});

/*
  The settlement set is enumerated by capability in policy-file.ts, and the note there argues that
  such a list is safe precisely because its staleness REFUSES rather than admits. That argument is
  only worth the words if it is a test, so here it is: a soul call this file has never heard of,
  and the one soul call that belongs to the other arm, are both refused beside settle_epoch.
*/
describe('the settlement set is by capability, and its staleness fails closed', () => {
  const SOUL = '0x000000000000000000000000000000000000000000000000000000000000005e::soul';

  it('refuses record_spend beside settle_epoch, though both are in the soul module', () => {
    // record_spend takes no capability: the contract asserts ctx.sender() == soul.agent, so it is
    // signed by the hot key that publishes. Grouping by module would have merged the two paths.
    const refusal = refuseMixedMoneyPaths([`${SOUL}::settle_epoch`, `${SOUL}::record_spend`]);
    expect(refusal).not.toBeNull();
    expect(refusal).toContain('record_spend');
  });

  it('refuses a LedgerCap call it has never heard of, rather than admitting it', () => {
    const refusal = refuseMixedMoneyPaths([`${SOUL}::settle_epoch`, `${SOUL}::book_something_new`]);
    expect(refusal).not.toBeNull();
  });

  it('allows the three it does know, in any order', () => {
    expect(
      refuseMixedMoneyPaths([`${SOUL}::book_burned`, `${SOUL}::settle_epoch`, `${SOUL}::book_earned`]),
    ).toBeNull();
  });

  it('still refuses a content entry beside them', () => {
    const refusal = refuseMixedMoneyPaths([
      `${SOUL}::settle_epoch`,
      '0xdc6dbb96885ba049c5d860d0b775b9e968cf9053a227861ae006f22e352884b5::creator::set_content_price',
    ]);
    expect(refusal).not.toBeNull();
    expect(refusal).toContain('set_content_price');
  });

  it('says nothing about a document with no settlement call at all', () => {
    expect(refuseMixedMoneyPaths([`${SOUL}::record_spend`])).toBeNull();
  });
});
