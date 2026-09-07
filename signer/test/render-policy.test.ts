// Built-by: @projectx.sui
import { describe, expect, it } from 'vitest';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { renderPolicy, parseRenderArgs } from '../bin/render-policy.js';

const POLICY_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'policy');

describe('render-policy', () => {
  it('refuses to render the content template while any substitution is unfilled, and names them', async () => {
    const template = await readFile(join(POLICY_DIR, 'heron-content.json'), 'utf8');
    const values = JSON.parse(await readFile(join(POLICY_DIR, 'heron-values.json'), 'utf8')) as Record<string, string>;
    // As the values stood before the vault existed: the two ids the vault transaction supplies removed.
    delete values['HERON_VAULT_ID'];
    delete values['HERON_CREATOR_CAP_ID'];
    const rendered = renderPolicy(template, values, true);
    expect(rendered.ok).toBe(false);
    if (rendered.ok) throw new Error('unreachable');
    expect(rendered.reason).toContain('<HERON_VAULT_ID>');
    expect(rendered.reason).toContain('<HERON_CREATOR_CAP_ID>');
    expect(rendered.reason).not.toContain('<SOUL_PACKAGE_ID>');
  });

  it('renders the pre-soul content policy once the vault and cap exist, dropping the soul rows and leaving no angle bracket', async () => {
    const template = await readFile(join(POLICY_DIR, 'heron-content.json'), 'utf8');
    const values: Record<string, string> = {
      ...(JSON.parse(await readFile(join(POLICY_DIR, 'heron-values.json'), 'utf8')) as Record<string, string>),
      HERON_VAULT_ID: `0x${'a'.repeat(64)}`,
      HERON_CREATOR_CAP_ID: `0x${'b'.repeat(64)}`,
    };
    const rendered = renderPolicy(template, values, true);
    expect(rendered.ok).toBe(true);
    if (!rendered.ok) throw new Error(rendered.reason);
    expect(rendered.text).not.toContain('<');
    const doc = JSON.parse(rendered.text) as { allowedTargets: string[]; allowedObjects: string[]; allowedRecipients: string[]; agentAddress: string };
    expect(doc.agentAddress).toBe(values['HERON_ADDRESS']);
    expect(doc.allowedTargets).toEqual(['0xdc6dbb96885ba049c5d860d0b775b9e968cf9053a227861ae006f22e352884b5::creator::set_content_price']);
    expect(doc.allowedObjects).toEqual([values['HERON_VAULT_ID'], values['HERON_CREATOR_CAP_ID'], values['CLOCK_ID']]);
    expect(doc.allowedRecipients).toEqual([values['HERON_ADDRESS'], values['OPERATOR_ADDRESS'], values['TREASURY_ADDRESS']]);
  });

  it('without --pre-soul the soul rows stay and must be filled', async () => {
    const template = await readFile(join(POLICY_DIR, 'heron-content.json'), 'utf8');
    const rendered = renderPolicy(template, { HERON_VAULT_ID: `0x${'a'.repeat(64)}` }, false);
    expect(rendered.ok).toBe(false);
    if (rendered.ok) throw new Error('unreachable');
    expect(rendered.reason).toContain('<SOUL_PACKAGE_ID>');
  });

  it('refuses a value that is not a Sui id, and a values key that is not a substitution name', () => {
    expect(renderPolicy('{"a":"<X>"}', { X: 'not-an-id' }, false).ok).toBe(false);
    expect(renderPolicy('{"a":"<X>"}', { 'x y': '0x1' }, false).ok).toBe(false);
    expect(renderPolicy('{"a":"<X>"}', { X: '0x1' }, false)).toEqual({ ok: true, text: '{\n  "a": "0x1"\n}\n' });
  });

  it('parses its flags and refuses an unknown one', () => {
    expect(parseRenderArgs(['--template', 't', '--values', 'v', '--stdout', '--pre-soul'])).toMatchObject({ stdout: true, preSoul: true });
    expect(typeof parseRenderArgs(['--template', 't'])).toBe('string');
    expect(typeof parseRenderArgs(['--nope'])).toBe('string');
  });
});
