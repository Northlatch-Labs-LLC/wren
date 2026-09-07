// Built-by: @projectx.sui
/**
 * A second citizen runs the SAME purse, phase two, birth tool and renderer as Heron, told its name
 * by flag. These tests pin two things: that the flag does what a second citizen needs, and that
 * with no flag every default is Heron's, unchanged — the purse Heron runs under today must not
 * change behaviour because Wren exists.
 */
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { CREDENTIAL_NAME, forbiddenEnvNames, loadHotKey, refuseKeyInProcessSurface } from '../src/key.js';
import { credentialNameFor, DEFAULT_AGENT, parseServerArgs } from '../src/server.js';
import { DEFAULT_PROFILE, parseBeatArgs, parseProfile } from '../src/beat-args.js';
import { renderPolicy } from '../bin/render-policy.js';

const REQUIRED = ['--socket', 's', '--policy', 'p', '--policy-sha256', 'h', '--chain', 'c', '--audit', 'a', '--spend', 'x'];

describe('the credential name follows the agent', () => {
  it('defaults to Heron\'s, exactly as before', () => {
    expect(CREDENTIAL_NAME).toBe('heron-hot');
    expect(credentialNameFor(undefined)).toBe('heron-hot');
    expect(DEFAULT_AGENT).toBe('heron');
    expect(forbiddenEnvNames()).toEqual(['HERON_HOT', 'HERON_HOT_KEY', 'HERON_KEY', 'HERON_SECRET', 'PURSE_KEY', 'SUI_PRIVATE_KEY', 'SUI_SECRET_KEY']);
  });

  it('names Wren\'s credential and forbids Wren\'s environment names', () => {
    expect(credentialNameFor('wren')).toBe('wren-hot');
    expect(forbiddenEnvNames('wren-hot')).toEqual(['WREN_HOT', 'WREN_HOT_KEY', 'WREN_KEY', 'WREN_SECRET', 'PURSE_KEY', 'SUI_PRIVATE_KEY', 'SUI_SECRET_KEY']);
    const refused = refuseKeyInProcessSurface({ argv: [], env: { WREN_HOT_KEY: '/somewhere' }, credentialName: 'wren-hot' });
    expect(refused.ok).toBe(false);
    if (!refused.ok) expect(refused.refused.reason).toContain('WREN_HOT_KEY');
    // And Heron's purse does not refuse Wren's name: the lists are per agent, not a union.
    expect(refuseKeyInProcessSurface({ argv: [], env: { WREN_HOT_KEY: '/somewhere' } }).ok).toBe(true);
  });

  it('loads the key from $CREDENTIALS_DIRECTORY/<agent>-hot', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'purse-agent-'));
    try {
      // Not a real key: the loader must fail AFTER resolving the path, and the path is what is tested.
      await writeFile(join(dir, 'wren-hot'), 'not a key\n', { mode: 0o400 });
      const loaded = await loadHotKey({ credentialsDirectory: dir, credentialName: 'wren-hot', argv: [], env: {} });
      expect(loaded.ok).toBe(false);
      if (!loaded.ok) expect(loaded.refused.reason).toContain(join(dir, 'wren-hot'));
      const heron = await loadHotKey({ credentialsDirectory: dir, argv: [], env: {} });
      expect(heron.ok).toBe(false);
      if (!heron.ok) expect(heron.refused.reason).toContain(join(dir, 'heron-hot'));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('--agent on the purse', () => {
  it('is optional and absent by default', () => {
    const parsed = parseServerArgs(REQUIRED);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value.agent).toBeUndefined();
  });
  it('is accepted for wren and refused for a name that could reach a credential path or a log line', () => {
    const ok = parseServerArgs([...REQUIRED, '--agent', 'wren']);
    expect(ok.ok).toBe(true);
    if (ok.ok) expect(ok.value.agent).toBe('wren');
    for (const bad of ['Wren', 'wren hot', '../wren', 'wren;id', '', 'a'.repeat(33)]) {
      const refused = parseServerArgs([...REQUIRED, '--agent', bad]);
      expect(refused.ok, bad).toBe(false);
    }
  });
});

describe('--agent and --profile-file on phase two', () => {
  const base = ['--runs', 'r', '--state', 's', '--socket', 'k', '--chain', 'c', '--beat-id', '20260906T000000Z'];
  it('default to Heron, unchanged', () => {
    const parsed = parseBeatArgs(base);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.agent).toBe('heron');
      expect(parsed.value.profileFile).toBeNull();
    }
    expect(DEFAULT_PROFILE.name).toBe('Heron');
  });
  it('carry Wren\'s name and profile file', () => {
    const parsed = parseBeatArgs([...base, '--agent', 'wren', '--profile-file', '/srv/wren/profile.json']);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.agent).toBe('wren');
      expect(parsed.value.profileFile).toBe('/srv/wren/profile.json');
    }
    expect(parseBeatArgs([...base, '--agent', 'Wren']).ok).toBe(false);
  });
  it('validate a profile file against the route\'s own limits', () => {
    expect(parseProfile(JSON.stringify({ name: 'Wren', bio: 'She cooks.' })).ok).toBe(true);
    expect(parseProfile('nope').ok).toBe(false);
    expect(parseProfile(JSON.stringify({ name: 'Wren' })).ok).toBe(false);
    expect(parseProfile(JSON.stringify({ name: 'Wren', bio: 'x', extra: 1 })).ok).toBe(false);
    expect(parseProfile(JSON.stringify({ name: 'W'.repeat(61), bio: 'x' })).ok).toBe(false);
    expect(parseProfile(JSON.stringify({ name: 'Wren', bio: 'b'.repeat(281) })).ok).toBe(false);
    expect(parseProfile(JSON.stringify({ name: 'Wren\nnot', bio: 'x' })).ok).toBe(false);
  });
  it('accept the profile Wren ships, read from her package', () => {
    const shipped = readFileSync(new URL('../../wren/profile.json', import.meta.url), 'utf8');
    const parsed = parseProfile(shipped);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value.name).toBe('Wren');
  });
});

describe('--pre-soul drops any agent\'s soul marker', () => {
  const template = JSON.stringify({
    version: 1,
    agentAddress: '<WREN_ADDRESS>',
    allowedTargets: ['0x2::creator::set_content_price', '<SOUL_PACKAGE_ID>::soul::record_spend'],
    allowedObjects: ['<WREN_VAULT_ID>', '<WREN_SOUL_ID>', '<CLOCK_ID>'],
  });
  const values = { WREN_ADDRESS: `0x${'1'.repeat(64)}`, WREN_VAULT_ID: `0x${'2'.repeat(64)}`, CLOCK_ID: '0x6' };
  it('renders Wren\'s template without the soul rows', () => {
    const rendered = renderPolicy(template, values, true);
    expect(rendered.ok).toBe(true);
    if (rendered.ok) {
      const doc = JSON.parse(rendered.text) as { allowedTargets: string[]; allowedObjects: string[] };
      expect(doc.allowedTargets).toEqual(['0x2::creator::set_content_price']);
      expect(doc.allowedObjects).toEqual([values.WREN_VAULT_ID, '0x6']);
    }
  });
  it('still refuses the soul rows unfilled when not pre-soul', () => {
    const rendered = renderPolicy(template, values, false);
    expect(rendered.ok).toBe(false);
    if (!rendered.ok) expect(rendered.reason).toContain('<WREN_SOUL_ID>');
  });
});

/*
  The soul flags on phase two.

  All four or none. Three of four is the failure that would otherwise be silent: the beat would
  start, publish, book nothing, and report nothing missing — so the allowance would look untouched
  while real money was being spent against it.
*/
describe('the soul flags travel together or not at all', () => {
  const base = ['--runs', 'r', '--state', 's', '--socket', 'k', '--chain', 'c', '--beat-id', '20260906T000000Z'];
  const four = [
    '--soul-package', '0x000000000000000000000000000000000000000000000000000000000000005e',
    '--soul', '0x00000000000000000000000000000000000000000000000000000000000000a1',
    '--soul-version', '978614373',
    '--graphql', 'https://graphql.mainnet.sui.io/graphql',
  ];

  it('none of them is a real deployment that books nothing', () => {
    const parsed = parseBeatArgs(base);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.value.soul).toBeNull();
  });

  it('all four carry the soul through', () => {
    const parsed = parseBeatArgs([...base, ...four]);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.soul?.soulId).toBe('0x00000000000000000000000000000000000000000000000000000000000000a1');
      expect(parsed.value.soul?.soulVersion).toBe('978614373');
      expect(parsed.value.soul?.graphql).toBe('https://graphql.mainnet.sui.io/graphql');
    }
  });

  it('three of four is refused, and the refusal names what is missing', () => {
    for (let drop = 0; drop < 4; drop += 1) {
      const partial = four.filter((_, i) => Math.floor(i / 2) !== drop);
      const parsed = parseBeatArgs([...base, ...partial]);
      expect(parsed.ok).toBe(false);
      if (!parsed.ok) expect(parsed.refused.reason).toContain('together or not at all');
    }
  });

  it('a soul id that is not a lower-case Sui id is refused', () => {
    const bad = [...four];
    bad[bad.indexOf('--soul') + 1] = '0xNOTHEX';
    expect(parseBeatArgs([...base, ...bad]).ok).toBe(false);
  });

  it('a version that is not a u64 is refused', () => {
    const bad = [...four];
    bad[bad.indexOf('--soul-version') + 1] = '9786.14373';
    expect(parseBeatArgs([...base, ...bad]).ok).toBe(false);
  });

  it('a graphql endpoint that is not https is refused', () => {
    const bad = [...four];
    bad[bad.indexOf('--graphql') + 1] = 'http://graphql.mainnet.sui.io/graphql';
    expect(parseBeatArgs([...base, ...bad]).ok).toBe(false);
  });
});
