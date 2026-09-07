// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/** Changing the policy is a redeploy, not a reload — and the pin is what makes that true. */

import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { canonicalPolicyJson } from '@projectx-social/policy';
import { loadPinnedPolicy } from '../src/policy-file.js';
import { policyFor, temporaryDirectory } from './helpers.js';

const AGENT = `0x${'d'.repeat(64)}`;

async function writePolicy(body: unknown): Promise<{ path: string; sha256: string }> {
  const dir = await temporaryDirectory();
  const path = join(dir, 'heron-policy.json');
  const text = `${JSON.stringify(body, null, 2)}\n`;
  await writeFile(path, text, 'utf8');
  return { path, sha256: createHash('sha256').update(text, 'utf8').digest('hex') };
}

describe('the pin', () => {
  it('loads when the file hashes to what the unit pinned', async () => {
    const written = await writePolicy(policyFor(AGENT));
    const loaded = await loadPinnedPolicy({ path: written.path, expectedSha256: written.sha256 });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    expect(loaded.value.fileSha256).toBe(written.sha256);
    expect(loaded.value.policyHash).toBe(
      createHash('sha256').update(canonicalPolicyJson(loaded.value.doc), 'utf8').digest('hex'),
    );
  });

  it('refuses to start on a hash mismatch, naming both hashes', async () => {
    const written = await writePolicy(policyFor(AGENT));
    const loaded = await loadPinnedPolicy({ path: written.path, expectedSha256: '0'.repeat(64) });

    expect(loaded.ok).toBe(false);
    if (loaded.ok) throw new Error('unreachable');
    expect(loaded.refused.reason).toContain(written.sha256);
    expect(loaded.refused.reason).toContain('redeploy, not a reload');
  });

  it('refuses to start when the document was widened after the pin was taken', async () => {
    // The case the pin exists for: somebody edits the allow-list in place.
    const written = await writePolicy(policyFor(AGENT));
    await writeFile(
      written.path,
      `${JSON.stringify(policyFor(AGENT, { allowedRecipients: [AGENT, `0x${'b'.repeat(64)}`] }), null, 2)}\n`,
      'utf8',
    );

    const loaded = await loadPinnedPolicy({ path: written.path, expectedSha256: written.sha256 });
    expect(loaded.ok).toBe(false);
  });

  it('refuses to start with no pin at all', async () => {
    const written = await writePolicy(policyFor(AGENT));
    const loaded = await loadPinnedPolicy({ path: written.path, expectedSha256: '' });
    expect(loaded.ok).toBe(false);
    if (loaded.ok) throw new Error('unreachable');
    expect(loaded.refused.reason).toContain('64 lowercase hex');
  });
});

describe('the document', () => {
  it('is checked rather than cast — a misspelled field is named at start', async () => {
    const { allowedTargets, ...rest } = policyFor(AGENT);
    void allowedTargets;
    const written = await writePolicy({ ...rest, allowedTagets: [] });
    const loaded = await loadPinnedPolicy({ path: written.path, expectedSha256: written.sha256 });

    expect(loaded.ok).toBe(false);
    if (loaded.ok) throw new Error('unreachable');
    expect(loaded.refused.reason).toContain('allowed');
  });

  it('loads a document that sets an approval bar, and one written before bars existed', async () => {
    /*
      The schema is a `strictObject`, so a key it does not name is a refusal to start. That is the
      right default and it is also why this test exists: without `approvalThresholds` in the
      schema, an operator who wrote a bar would be told at start that their document has an
      unknown field, and the deployed purse could never run the gate at all. Both documents must
      load — the one with a bar, and every document deployed before there were bars.
    */
    const withBar = await writePolicy({
      ...policyFor(AGENT),
      approvalThresholds: [{ coinType: `0x${'0'.repeat(63)}2::sui::SUI`, maxWithoutApproval: '500000' }],
    });
    const loaded = await loadPinnedPolicy({ path: withBar.path, expectedSha256: withBar.sha256 });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    expect(loaded.value.doc.approvalThresholds).toEqual([
      { coinType: `0x${'0'.repeat(63)}2::sui::SUI`, maxWithoutApproval: '500000' },
    ]);

    const withoutBar = await writePolicy(policyFor(AGENT));
    const legacy = await loadPinnedPolicy({
      path: withoutBar.path,
      expectedSha256: withoutBar.sha256,
    });
    expect(legacy.ok).toBe(true);
    if (!legacy.ok) throw new Error(legacy.refused.reason);
    expect(legacy.value.doc.approvalThresholds).toBeUndefined();
    // Different documents, so different policy hashes in the audit chain.
    expect(loaded.value.policyHash).not.toBe(legacy.value.policyHash);
  });

  it('refuses a bar whose amount is not a u64 written as a decimal string', async () => {
    const written = await writePolicy({
      ...policyFor(AGENT),
      approvalThresholds: [{ coinType: `0x${'0'.repeat(63)}2::sui::SUI`, maxWithoutApproval: '' }],
    });
    const loaded = await loadPinnedPolicy({ path: written.path, expectedSha256: written.sha256 });
    expect(loaded.ok).toBe(false);
  });

  it('refuses a policy that is not JSON', async () => {
    const dir = await temporaryDirectory();
    const path = join(dir, 'heron-policy.json');
    await writeFile(path, 'not json', 'utf8');
    const sha256 = createHash('sha256').update('not json', 'utf8').digest('hex');

    const loaded = await loadPinnedPolicy({ path, expectedSha256: sha256 });
    expect(loaded.ok).toBe(false);
  });
});
