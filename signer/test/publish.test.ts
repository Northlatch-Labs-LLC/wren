// Built-by: @projectx.sui
/**
 * The publish plan, end to end against stub ports: the setup read, the one-time naming, the price
 * for a paid post, the publish statement, and the state file on every path.
 */

import { describe, expect, it } from 'vitest';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { publishContentSha256 } from '@projectx-social/agent';
import { runPhaseTwo } from '../src/beat.js';
import { contentDigest, parsePublishPlan, runPublishPlan, MAX_POST_BODY_LENGTH, MAX_POST_PREVIEW_LENGTH, type PublishPorts } from '../src/publish.js';
import type { PurseResponse } from '../src/protocol.js';
import { temporaryDirectory } from './helpers.js';

const ADDRESS = `0x${'e'.repeat(64)}`;
const VAULT = `0x${'c'.repeat(64)}`;
const CAP = `0x${'d'.repeat(64)}`;
const ORIGIN = 'https://weir.social';
const SUI = '0x0000000000000000000000000000000000000000000000000000000000000002::sui::SUI';

interface Seen {
  readonly asked: unknown[];
  readonly requests: { method: string; url: string; body?: unknown; headers?: Record<string, string> }[];
  submitted: number;
  priceReads: number;
}

function ports(options: { named?: boolean; stage?: string; refuse?: string; postStatus?: number; alreadyPriced?: string | null; submitThrows?: boolean } = {}): { ports: PublishPorts; seen: Seen } {
  const seen: Seen = { asked: [], requests: [], submitted: 0, priceReads: 0 };
  const p: PublishPorts = {
    ask: async (intent) => {
      seen.asked.push(intent);
      const kind = (intent as { kind: string }).kind;
      if (options.refuse !== undefined && kind === options.refuse) {
        return { ok: true, value: { ok: false, refused: { ruleId: 'statement-ceiling', reason: 'the ceiling' } } as PurseResponse };
      }
      if (kind === 'statement') {
        return { ok: true, value: { ok: true, statement: 'Weir\n...', statementSha256: 'a'.repeat(64), signature: 'sig', address: ADDRESS, timestampMs: 1_788_000_000_000 } as PurseResponse };
      }
      return { ok: true, value: { ok: true, digest: 'PriceDigest', txBytesB64: 'AA==', signature: 'sig' } as PurseResponse };
    },
    http: {
      request: async (input) => {
        seen.requests.push(input);
        if (input.url.endsWith(`/api/creator?owner=${ADDRESS}`)) {
          return { status: 200, json: { stage: options.stage ?? 'ready', handle: 'heron', vaults: [{ vaultId: VAULT, capId: CAP, coinType: SUI, handle: options.named === true ? 'heron' : null }] } };
        }
        if (input.url.endsWith('/api/creator/profile')) return { status: 200, json: { handle: 'heron' } };
        if (input.url.endsWith('/api/posts')) return { status: options.postStatus ?? 200, json: options.postStatus === undefined ? { post: { id: 'post-1', access: 'public' } } : { error: 'only the vault owner may publish to this profile' } };
        return { status: 404, json: null };
      },
    },
    chain: {
      sharedRef: async (objectId) => ({ objectId, initialSharedVersion: '3', mutable: true }),
      ownedRef: async (objectId) => ({ objectId, version: '7', digest: '11111111111111111111111111111111' }),
      // Not priced, unless a test says otherwise: the ordinary case is a new body nobody has priced.
      priceOf: async () => { seen.priceReads += 1; return options.alreadyPriced ?? null; },
    },
    submit: async () => {
      seen.submitted += 1;
      if (options.submitThrows === true) throw new Error('the node hung up');
      return 'OnChainDigest';
    },
    now: () => 1_788_000_000_000,
  };
  return { ports: p, seen };
}

const plan = (overrides: Record<string, unknown> = {}) => ({ kind: 'publish-plan', title: 'What the marsh knows', preview: 'A short preview.', text: 'The whole text.', access: 'public', ...overrides });

describe('the plan', () => {
  it('computes the same content digest the agent library and the route do', () => {
    expect(contentDigest('A short preview.', 'The whole text.')).toBe(publishContentSha256('A short preview.', 'The whole text.'));
  });

  it('refuses a plan that is paid without a price, public with one, over the limits, or with an extra field', () => {
    for (const bad of [
      plan({ access: 'paid' }),
      plan({ access: 'public', priceMist: '5' }),
      plan({ title: 'two\nlines' }),
      plan({ preview: 'x'.repeat(MAX_POST_PREVIEW_LENGTH + 1) }),
      plan({ text: 'x'.repeat(MAX_POST_BODY_LENGTH + 1) }),
      plan({ extra: 1 }),
    ]) {
      expect(parsePublishPlan(bad).ok).toBe(false);
    }
    expect(parsePublishPlan(plan()).ok).toBe(true);
    // The price band, both edges: 0.01 SUI and 0.1 SUI in, one MIST outside either out.
    expect(parsePublishPlan(plan({ access: 'paid', priceMist: '10000000' })).ok).toBe(true);
    expect(parsePublishPlan(plan({ access: 'paid', priceMist: '100000000' })).ok).toBe(true);
    expect(parsePublishPlan(plan({ access: 'paid', priceMist: '9999999' })).ok).toBe(false);
    expect(parsePublishPlan(plan({ access: 'paid', priceMist: '100000001' })).ok).toBe(false);
    expect(parsePublishPlan(plan({ access: 'paid', priceMist: '99999999999999999999' })).ok).toBe(false);
  });

  it('refuses a raw statement intent in the intent file: statements are built only from a plan', async () => {
    const dir = await temporaryDirectory('heron-plan-');
    const runs = join(dir, 'runs');
    const state = join(dir, 'state');
    await mkdir(join(runs, 'B0'), { recursive: true });
    await writeFile(join(runs, 'B0', 'intent.json'), JSON.stringify({
      kind: 'statement',
      action: { kind: 'name-vault', vaultId: VAULT, name: 'evil', bio: 'evil', coinType: SUI },
      timestampMs: 1_788_000_000_000,
      origin: ORIGIN,
    }), 'utf8');
    const { ports: p, seen } = ports({ named: true });
    const result = await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: 'B0', ask: { ask: p.ask } });
    expect(result.state).toMatchObject({ outcome: 'refused', ruleId: 'intent-invalid-locally' });
    expect(result.state.error).toContain('built only by the publish plan');
    expect(seen.asked).toEqual([]);
  });
});

describe('a public post on an unnamed vault', () => {
  it('names the vault once with a statement, then publishes with a second statement, and returns the post id', async () => {
    const { ports: p, seen } = ports();
    const parsed = parsePublishPlan(plan());
    if (!parsed.ok) throw new Error(parsed.reason);
    const result = await runPublishPlan({ plan: parsed.plan, address: ADDRESS, origin: ORIGIN, beatId: 'B1', ports: p, profile: { name: 'Heron', bio: 'bio' } });
    expect(result).toMatchObject({ outcome: 'published', postId: 'post-1', handle: 'heron', named: true });
    expect(seen.asked.map((a) => (a as { kind: string; action?: { kind: string } }).action?.kind)).toEqual(['name-vault', 'publish']);
    const publishAsked = seen.asked[1] as { action: { access: string; contentKey: string; price: string; contentSha256: string; handle: string } };
    expect(publishAsked.action).toMatchObject({ access: 'public', contentKey: '', price: '', handle: 'heron', contentSha256: contentDigest('A short preview.', 'The whole text.') });
    expect(seen.requests.map((r) => `${r.method} ${r.url.replace(ORIGIN, '')}`)).toEqual([`GET /api/creator?owner=${ADDRESS}`, 'POST /api/creator/profile', 'POST /api/posts']);
    const post = seen.requests[2]!;
    expect(post.body).toMatchObject({ handle: 'heron', author: ADDRESS, access: 'public', signature: 'sig', timestampMs: 1_788_000_000_000 });
    expect(post.body).not.toHaveProperty('contentKey');
    expect(post.headers).toMatchObject({ 'idempotency-key': 'heron-beat-B1' });
    expect(seen.submitted).toBe(0);
  });
});

describe('a paid post on a named vault', () => {
  it('prices the content key on chain first, submits, then publishes with the key and price bound', async () => {
    const { ports: p, seen } = ports({ named: true });
    const parsed = parsePublishPlan(plan({ access: 'paid', priceMist: '20000000' }));
    if (!parsed.ok) throw new Error(parsed.reason);
    const result = await runPublishPlan({ plan: parsed.plan, address: ADDRESS, origin: ORIGIN, beatId: 'B2', ports: p, profile: { name: 'Heron', bio: 'bio' } });
    expect(result).toMatchObject({ outcome: 'published', postId: 'post-1', named: false, priceDigest: 'OnChainDigest' });
    const kinds = seen.asked.map((a) => { const x = a as { kind: string; action?: { kind: string } }; return x.kind === 'statement' ? x.action!.kind : x.kind; });
    expect(kinds).toEqual(['post', 'publish']);
    const price = seen.asked[0] as { vault: { objectId: string; initialSharedVersion: string }; cap: { objectId: string; version: string }; contentKey: string; bodyDigestSha256: string; priceMist: string };
    const digest = contentDigest('A short preview.', 'The whole text.');
    expect(price).toMatchObject({ vault: { objectId: VAULT, initialSharedVersion: '3' }, cap: { objectId: CAP, version: '7' }, contentKey: digest, bodyDigestSha256: digest, priceMist: '20000000' });
    expect(seen.submitted).toBe(1);
    const publishAsked = seen.asked[1] as { action: { contentKey: string; price: string; access: string } };
    expect(publishAsked.action).toMatchObject({ access: 'paid', contentKey: digest, price: '20000000' });
    const post = seen.requests.at(-1)!;
    expect(post.body).toMatchObject({ access: 'paid', contentKey: digest, price: '20000000' });
  });
});

describe('what stops it', () => {
  it('a purse that signs as another address than the beat was started for is an error, and nothing is posted', async () => {
    const { ports: p, seen } = ports({ named: true });
    // The setup answers for any owner; the purse stub still signs as ADDRESS, which is not this beat's.
    const request = p.http.request;
    const anyOwner: PublishPorts['http'] = { request: async (input) => request(input.url.includes('/api/creator?owner=') ? { ...input, url: `${ORIGIN}/api/creator?owner=${ADDRESS}` } : input) };
    const parsed = parsePublishPlan(plan());
    if (!parsed.ok) throw new Error(parsed.reason);
    const result = await runPublishPlan({ plan: parsed.plan, address: `0x${'f'.repeat(64)}`, origin: ORIGIN, beatId: 'B8', ports: { ...p, http: anyOwner }, profile: { name: 'Heron', bio: 'bio' } });
    expect(result.outcome).toBe('error');
    if (result.outcome !== 'error') throw new Error('unreachable');
    expect(result.error).toContain('signs as');
    expect(seen.requests.filter((r) => r.url.endsWith('/api/posts'))).toEqual([]);
  });

  it('publishes under the slug the profile route filed the vault under, not the registry handle', async () => {
    const { ports: p, seen } = ports();
    // The stub's profile route answers { handle: 'heron' }; make it answer a suffixed slug.
    const request = p.http.request;
    const filed: PublishPorts['http'] = { request: async (input) => (input.url.endsWith('/api/creator/profile') ? { status: 200, json: { handle: 'heron-a1b2' } } : request(input)) };
    const parsed = parsePublishPlan(plan());
    if (!parsed.ok) throw new Error(parsed.reason);
    const result = await runPublishPlan({ plan: parsed.plan, address: ADDRESS, origin: ORIGIN, beatId: 'B9', ports: { ...p, http: filed }, profile: { name: 'Heron', bio: 'bio' } });
    expect(result).toMatchObject({ outcome: 'published', handle: 'heron-a1b2' });
    const publishAsked = seen.asked[1] as { action: { handle: string } };
    expect(publishAsked.action.handle).toBe('heron-a1b2');
  });

  it('a purse refusal is the outcome, with its rule, and nothing is sent to the API after it', async () => {
    const { ports: p, seen } = ports({ refuse: 'statement' });
    const parsed = parsePublishPlan(plan());
    if (!parsed.ok) throw new Error(parsed.reason);
    const result = await runPublishPlan({ plan: parsed.plan, address: ADDRESS, origin: ORIGIN, beatId: 'B3', ports: p, profile: { name: 'Heron', bio: 'bio' } });
    expect(result).toMatchObject({ outcome: 'refused', ruleId: 'statement-ceiling' });
    expect(seen.requests.map((r) => r.method)).toEqual(['GET']);
  });

  it('a setup that is not ready is an error before any statement is asked for', async () => {
    const { ports: p, seen } = ports({ stage: 'no-vault' });
    const parsed = parsePublishPlan(plan());
    if (!parsed.ok) throw new Error(parsed.reason);
    const result = await runPublishPlan({ plan: parsed.plan, address: ADDRESS, origin: ORIGIN, beatId: 'B4', ports: p, profile: { name: 'Heron', bio: 'bio' } });
    expect(result.outcome).toBe('error');
    expect(seen.asked).toEqual([]);
  });

  it('an API refusal of the post is an error that quotes the route\'s own sentence', async () => {
    const { ports: p } = ports({ named: true, postStatus: 403 });
    const parsed = parsePublishPlan(plan());
    if (!parsed.ok) throw new Error(parsed.reason);
    const result = await runPublishPlan({ plan: parsed.plan, address: ADDRESS, origin: ORIGIN, beatId: 'B5', ports: p, profile: { name: 'Heron', bio: 'bio' } });
    expect(result.outcome).toBe('error');
    if (result.outcome !== 'error') throw new Error('unreachable');
    expect(result.error).toContain('403');
    expect(result.error).toContain('only the vault owner');
  });
});

describe('phase two with a plan', () => {
  it('runs the plan when the origin and address are given, and writes published with the post id', async () => {
    const dir = await temporaryDirectory('heron-plan-');
    const runs = join(dir, 'runs');
    const state = join(dir, 'state');
    await mkdir(join(runs, 'B6'), { recursive: true });
    await writeFile(join(runs, 'B6', 'intent.json'), JSON.stringify(plan()), 'utf8');
    const { ports: p } = ports({ named: true });
    const { ask, now, ...rest } = p;
    void now;
    const result = await runPhaseTwo({
      runsDir: runs,
      stateDir: state,
      beatId: 'B6',
      ask: { ask },
      publish: { origin: ORIGIN, address: ADDRESS, profile: { name: 'Heron', bio: 'bio' }, ports: rest },
    });
    expect(result.state).toMatchObject({ beatId: 'B6', outcome: 'published', postId: 'post-1', handle: 'heron', named: false });
    const written = JSON.parse(await readFile(join(state, 'latest.json'), 'utf8')) as { outcome: string; postId: string };
    expect(written.outcome).toBe('published');
    expect(written.postId).toBe('post-1');
  });

  it('refuses a plan locally when the beat runs without an origin and address, and writes that', async () => {
    const dir = await temporaryDirectory('heron-plan-');
    const runs = join(dir, 'runs');
    const state = join(dir, 'state');
    await mkdir(join(runs, 'B7'), { recursive: true });
    await writeFile(join(runs, 'B7', 'intent.json'), JSON.stringify(plan()), 'utf8');
    const { ports: p, seen } = ports();
    const result = await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: 'B7', ask: { ask: p.ask } });
    expect(result.state).toMatchObject({ outcome: 'refused', ruleId: 'intent-invalid-locally' });
    expect(seen.asked).toEqual([]);
  });
});

/*
  A paid post is two systems and the first half is permanent.

  The API refuses a paid post whose key is not already priced on chain
  (`packages/web/app/api/posts/route.ts:50`), so the irreversible half must go first and cannot be
  reordered. What makes the gap survivable is that the content key is the sha256 of the body: the
  same plan always produces the same key, so a second attempt at the same post costs no second
  transaction. These tests pin that property, because without it the failure below orphans a price
  on chain for ever.
*/
describe('a paid post survives a failure between pricing and publishing', () => {
  const paid = () => {
    const parsed = parsePublishPlan(plan({ access: 'paid', priceMist: '50000000' }));
    if (!parsed.ok) throw new Error(parsed.reason);
    return parsed.plan;
  };
  const free = () => {
    const parsed = parsePublishPlan(plan());
    if (!parsed.ok) throw new Error(parsed.reason);
    return parsed.plan;
  };
  const PROFILE = { name: 'Wren', bio: 'bio' };

  it('prices the key when it is not priced yet', async () => {
    const { ports: p, seen } = ports();
    const result = await runPublishPlan({ plan: paid(), address: ADDRESS, origin: ORIGIN, beatId: 'PAID', ports: p, profile: PROFILE });

    expect(result.outcome).toBe('published');
    expect(seen.priceReads).toBe(1);
    expect(seen.submitted).toBe(1);
    expect(result.outcome === 'published' && result.resumedPrice).toBe(false);
  });

  it('prices NOTHING when the key already carries this exact price, and publishes anyway', async () => {
    // The resume. This is the state a beat is left in when the submit threw after the price landed.
    const { ports: p, seen } = ports({ alreadyPriced: '50000000' });
    const result = await runPublishPlan({ plan: paid(), address: ADDRESS, origin: ORIGIN, beatId: 'PAID', ports: p, profile: PROFILE });

    expect(result.outcome).toBe('published');
    expect(seen.submitted).toBe(0);
    expect(result.outcome === 'published' && result.resumedPrice).toBe(true);
    // No `post` intent was ever asked for: the chain half was already done.
    expect((seen.asked as { kind?: string }[]).some((a) => a.kind === 'post')).toBe(false);
  });

  it('re-prices when the key is priced at a DIFFERENT price', async () => {
    const { ports: p, seen } = ports({ alreadyPriced: '10000000' });
    const result = await runPublishPlan({ plan: paid(), address: ADDRESS, origin: ORIGIN, beatId: 'PAID', ports: p, profile: PROFILE });

    expect(result.outcome).toBe('published');
    expect(seen.submitted).toBe(1);
    expect(result.outcome === 'published' && result.resumedPrice).toBe(false);
  });

  it('a submit that throws returns an error instead of taking the whole beat down', async () => {
    // The exact defect: on 2026-09-06 the submit threw, publish.ts died with it, step 4 never ran,
    // and the price stayed on chain with no post behind it.
    const { ports: p } = ports({ submitThrows: true });
    const result = await runPublishPlan({ plan: paid(), address: ADDRESS, origin: ORIGIN, beatId: 'PAID', ports: p, profile: PROFILE });

    expect(result.outcome).toBe('error');
    expect(result.outcome === 'error' && result.error).toContain('may have landed');
  });

  it('and the next attempt at that same body finds the price and completes it', async () => {
    const first = ports({ submitThrows: true });
    const failed = await runPublishPlan({ plan: paid(), address: ADDRESS, origin: ORIGIN, beatId: 'PAID', ports: first.ports, profile: PROFILE });
    expect(failed.outcome).toBe('error');

    // The price DID land, as the error says it might have. The retry sees it and publishes.
    const second = ports({ alreadyPriced: '50000000' });
    const result = await runPublishPlan({ plan: paid(), address: ADDRESS, origin: ORIGIN, beatId: 'PAID', ports: second.ports, profile: PROFILE });

    expect(result.outcome).toBe('published');
    expect(second.seen.submitted).toBe(0);
  });

  it('a free post never reads a price and never submits', async () => {
    const { ports: p, seen } = ports();
    await runPublishPlan({ plan: free(), address: ADDRESS, origin: ORIGIN, beatId: 'FREE', ports: p, profile: PROFILE });

    expect(seen.priceReads).toBe(0);
    expect(seen.submitted).toBe(0);
  });
});
