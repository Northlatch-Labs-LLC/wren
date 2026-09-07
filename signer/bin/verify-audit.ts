#!/usr/bin/env -S npx tsx
// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * `verify-audit <path/to/audit.jsonl>` — walk the chain and report the first break.
 *
 * Exit 0 when it verifies, 1 when it does not, 2 when the file could not be read as a chain at all.
 * The three are kept apart because "the file is missing" and "line 412 was edited" call for
 * completely different next moves, and a single non-zero would send whoever is on call to the wrong
 * one.
 *
 * The first break is reported rather than a count, because everything before it still verifies and
 * that is where a reader has to start.
 */

import { readAuditFile, verifyAuditLines } from '../src/audit-file.js';

const path = process.argv[2];
if (path === undefined) {
  process.stderr.write('verify-audit: usage: verify-audit <path/to/audit.jsonl>\n');
  process.exit(2);
}

const read = await readAuditFile(path);
if (!read.ok) {
  process.stderr.write(`verify-audit: ${path} — ${read.reason}\n`);
  process.exit(2);
}

const verdict = verifyAuditLines(read.lines);
if (!verdict.intact) {
  process.stderr.write(
    `verify-audit: BROKEN at line ${String(verdict.line)} of ${path}\n  ${verdict.reason}\n`,
  );
  process.exit(1);
}

process.stdout.write(
  `verify-audit: intact — ${String(verdict.length)} line(s), head ${verdict.headHash}\n`,
);
process.exit(0);
