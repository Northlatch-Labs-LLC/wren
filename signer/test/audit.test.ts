// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The chain, and what breaking it looks like.
 *
 * The proof that a hash chain is worth having is not that it verifies — an empty function verifies.
 * It is that a single edited field is caught, at the line it was edited, with everything before it
 * still sound.
 */

import { describe, expect, it } from 'vitest';
import { readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { AuditFile, GENESIS_HASH, readAuditFile, verifyAuditLines } from '../src/audit-file.js';
import { temporaryDirectory } from './helpers.js';

const FIELDS = {
  ts: 1_788_000_000_000,
  address: `0x${'d'.repeat(64)}`,
  policyHash: 'f'.repeat(64),
  policyFileSha256: 'e'.repeat(64),
  intentKind: 'price',
  intentHash: 'a'.repeat(64),
  outcome: 'signed' as const,
  ruleId: '',
  reason: '',
  txDigest: '2Wm1kXwYxPjkjVqT1rvHi9oqmvSZY3md6eirK8WheHbR',
};

async function chainOf(count: number): Promise<{ path: string; file: AuditFile }> {
  const dir = await temporaryDirectory();
  const path = join(dir, 'audit.jsonl');
  const opened = await AuditFile.open(path);
  if (!opened.ok) throw new Error(opened.reason);
  for (let i = 0; i < count; i += 1) {
    await opened.file.append({ ...FIELDS, ts: FIELDS.ts + i });
  }
  return { path, file: opened.file };
}

describe('a chain that was written honestly', () => {
  it('verifies, and reports its length and head', async () => {
    const { path, file } = await chainOf(4);
    const read = await readAuditFile(path);
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error(read.reason);

    const verdict = verifyAuditLines(read.lines);
    expect(verdict.intact).toBe(true);
    if (!verdict.intact) throw new Error('unreachable');
    expect(verdict.length).toBe(4);
    expect(verdict.headHash).toBe(file.headHash);
    await file.close();
  });

  it('starts from the genesis hash', async () => {
    const { path, file } = await chainOf(1);
    const read = await readAuditFile(path);
    if (!read.ok) throw new Error(read.reason);
    expect(read.lines[0]!.prevHash).toBe(GENESIS_HASH);
    await file.close();
  });

  it('is 0600, whatever the process umask was', async () => {
    const { path, file } = await chainOf(1);
    const info = await stat(path);
    expect((info.mode & 0o777).toString(8)).toBe('600');
    await file.close();
  });

  it('picks the sequence and head back up when reopened', async () => {
    const { path, file } = await chainOf(3);
    await file.close();

    const reopened = await AuditFile.open(path);
    if (!reopened.ok) throw new Error(reopened.reason);
    expect(reopened.file.length).toBe(3);
    await reopened.file.append(FIELDS);

    const read = await readAuditFile(path);
    if (!read.ok) throw new Error(read.reason);
    expect(verifyAuditLines(read.lines).intact).toBe(true);
    expect(read.lines[3]!.seq).toBe(3);
    await reopened.file.close();
  });
});

describe('a chain somebody edited', () => {
  it('breaks at the edited line, and everything before it still verifies', async () => {
    const { path, file } = await chainOf(5);
    await file.close();

    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    const tampered = JSON.parse(lines[2]!) as Record<string, unknown>;
    tampered['reason'] = 'nothing to see here';
    lines[2] = JSON.stringify(tampered);
    await writeFile(path, `${lines.join('\n')}\n`, 'utf8');

    const read = await readAuditFile(path);
    if (!read.ok) throw new Error(read.reason);
    const verdict = verifyAuditLines(read.lines);

    expect(verdict.intact).toBe(false);
    if (verdict.intact) throw new Error('unreachable');
    expect(verdict.line).toBe(3);
    expect(verifyAuditLines(read.lines.slice(0, 2)).intact).toBe(true);
  });

  it('breaks when a line is deleted', async () => {
    const { path, file } = await chainOf(4);
    await file.close();

    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    lines.splice(1, 1);
    await writeFile(path, `${lines.join('\n')}\n`, 'utf8');

    const read = await readAuditFile(path);
    if (!read.ok) throw new Error(read.reason);
    const verdict = verifyAuditLines(read.lines);
    expect(verdict.intact).toBe(false);
    if (verdict.intact) throw new Error('unreachable');
    expect(verdict.line).toBe(2);
  });

  it('breaks when two lines are swapped', async () => {
    const { path, file } = await chainOf(4);
    await file.close();

    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    [lines[1], lines[2]] = [lines[2]!, lines[1]!];
    await writeFile(path, `${lines.join('\n')}\n`, 'utf8');

    const read = await readAuditFile(path);
    if (!read.ok) throw new Error(read.reason);
    expect(verifyAuditLines(read.lines).intact).toBe(false);
  });

  it('reports a line that is not JSON rather than skipping it', async () => {
    const { path, file } = await chainOf(2);
    await file.close();
    await writeFile(path, `${(await readFile(path, 'utf8')).trim()}\nnot json\n`, 'utf8');

    const read = await readAuditFile(path);
    expect(read.ok).toBe(false);
    if (read.ok) throw new Error('unreachable');
    expect(read.line).toBe(3);
  });

  it('is not appended to — the purse refuses to start on a broken chain', async () => {
    const { path, file } = await chainOf(3);
    await file.close();

    const lines = (await readFile(path, 'utf8')).trim().split('\n');
    const tampered = JSON.parse(lines[1]!) as Record<string, unknown>;
    tampered['txDigest'] = 'something-else';
    lines[1] = JSON.stringify(tampered);
    await writeFile(path, `${lines.join('\n')}\n`, 'utf8');

    const reopened = await AuditFile.open(path);
    expect(reopened.ok).toBe(false);
    if (reopened.ok) throw new Error('unreachable');
    expect(reopened.reason).toContain('line 2');
  });
});

describe('the encoding', () => {
  it('cannot be forged from inside a field', async () => {
    // `reason` carries text a model can influence. Length prefixes are what stop a crafted reason
    // impersonating a field boundary and making two different lines hash alike.
    const dir = await temporaryDirectory();
    const opened = await AuditFile.open(join(dir, 'audit.jsonl'));
    if (!opened.ok) throw new Error(opened.reason);

    const one = await opened.file.append({ ...FIELDS, ruleId: 'ab', reason: 'cd' });
    const otherFile = await AuditFile.open(join(await temporaryDirectory(), 'audit.jsonl'));
    if (!otherFile.ok) throw new Error(otherFile.reason);
    const two = await otherFile.file.append({ ...FIELDS, ruleId: 'a', reason: 'bcd' });

    expect(one.hash).not.toBe(two.hash);
    await opened.file.close();
    await otherFile.file.close();
  });
});
