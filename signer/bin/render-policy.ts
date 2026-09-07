#!/usr/bin/env -S npx tsx
// Built-by: @projectx.sui
/**
 * Render a policy document from its template and a values file.
 *
 * `policy/heron-content.json` carries `<ANGLE_BRACKET>` substitutions the deploy fills. This is
 * the one place they are filled: every `<NAME>` in the template must be present in the values file
 * as a Sui id or address, and a rendered document that still carries a `<` is refused, never
 * written. `--pre-soul` drops the two entries that name the soul package and the soul object,
 * because the soul is not published yet; a target or object that exists nowhere is not a bound,
 * and a placeholder string in a product path is forbidden (the Master's rule).
 *
 * usage: render-policy.ts --template <path> --values <path> --out <path> [--pre-soul]
 *        render-policy.ts --template <path> --values <path> --stdout [--pre-soul]
 * Prints the rendered document's sha256 on stderr. Never a secret anywhere: ids and addresses only.
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { loadPinnedPolicy } from '../src/policy-file.js';
import { writeFileSync as _unused } from 'node:fs';

const SUI_ID = /^0x[0-9a-fA-F]{1,64}$/;
/** A u64 as a decimal string. JSON has no integer type that survives 2^53; a string does. */
const U64_DECIMAL = /^(0|[1-9][0-9]{0,19})$/;
/** A base58 object digest, bounded rather than decoded: a decoder here would be a second one. */
const BASE58_DIGEST = /^[1-9A-HJ-NP-Za-km-z]{32,64}$/;
/**
 * The substitutions --pre-soul drops: the package, the registry, the ledger cap, and the agent's own
 * soul object under any agent's prefix (`<HERON_SOUL_ID>`, `<WREN_SOUL_ID>`). One pattern, so a
 * second citizen's template needs no change here.
 */
const SOUL_MARKER = /<(SOUL_PACKAGE_ID|SOUL_REGISTRY_ID|LEDGER_CAP_ID|[A-Z][A-Z0-9_]*_SOUL_ID)>/;

export interface RenderArgs {
  readonly template: string;
  readonly values: string;
  readonly out: string | null;
  readonly stdout: boolean;
  readonly preSoul: boolean;
}

export function parseRenderArgs(argv: readonly string[]): RenderArgs | string {
  const map = new Map<string, string>();
  let stdout = false;
  let preSoul = false;
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i]!;
    if (flag === '--stdout') { stdout = true; continue; }
    if (flag === '--pre-soul') { preSoul = true; continue; }
    if (!['--template', '--values', '--out'].includes(flag)) return `${flag} is not a flag this takes.`;
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) return `${flag} needs a value.`;
    map.set(flag, value);
    i += 1;
  }
  if (!map.has('--template') || !map.has('--values')) return '--template and --values are required.';
  if (!stdout && !map.has('--out')) return '--out <path> or --stdout is required.';
  return { template: map.get('--template')!, values: map.get('--values')!, out: map.get('--out') ?? null, stdout, preSoul };
}

/**
 * The rendering itself, as a function so the test can call it on strings.
 * Returns the rendered text or a refusal sentence.
 */
export function renderPolicy(templateText: string, values: Readonly<Record<string, unknown>>, preSoul: boolean): { ok: true; text: string } | { ok: false; reason: string } {
  let doc: unknown;
  try {
    doc = JSON.parse(templateText);
  } catch {
    return { ok: false, reason: 'the template is not JSON.' };
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) return { ok: false, reason: 'the template is not an object.' };

  for (const [name, value] of Object.entries(values)) {
    if (!/^[A-Z][A-Z0-9_]*$/.test(name)) return { ok: false, reason: `values key "${name}" is not a substitution name.` };
    if (typeof value !== 'string') return { ok: false, reason: `values.${name} is not a string.` };
    /*
      Three shapes, chosen by the key's own suffix rather than by trying each in turn.

      A values document used to hold nothing but object ids, so one test served. The settlement
      arm needs an object REFERENCE — id, version and digest — because the purse is handed
      fully-resolved references and never resolves an id against a fullnode itself. A version is a
      u64 and a digest is base58, so a single shape can no longer cover the file.

      Deciding by suffix, not by "whichever pattern matches", is the point. Accepting any of the
      three for any key would let a digest sit where an id belongs and a version where a digest
      does, and the transaction that resulted would name the wrong object with a well-formed
      value. The suffix says what the field IS, and the check holds it to that.
    */
    const shape = name.endsWith('_VERSION') || name.endsWith('_MIST')
      ? { re: U64_DECIMAL, what: 'a u64 written as a decimal string' }
      : name.endsWith('_DIGEST')
        ? { re: BASE58_DIGEST, what: 'a base58 object digest' }
        : { re: SUI_ID, what: 'a Sui id or address' };
    if (!shape.re.test(value)) return { ok: false, reason: `values.${name} is not ${shape.what}.` };
  }

  const record = doc as Record<string, unknown>;
  if (preSoul) {
    const drop = (list: unknown): unknown =>
      Array.isArray(list) ? list.filter((entry) => typeof entry !== 'string' || !SOUL_MARKER.test(entry)) : list;
    record['allowedTargets'] = drop(record['allowedTargets']);
    record['allowedObjects'] = drop(record['allowedObjects']);
  }

  let text = `${JSON.stringify(record, null, 2)}\n`;
  for (const [name, value] of Object.entries(values)) {
    text = text.split(`<${name}>`).join(value as string);
  }
  const left = text.match(/<[A-Z][A-Z0-9_]*>/g);
  if (left !== null) {
    return { ok: false, reason: `unfilled substitution(s): ${[...new Set(left)].join(' ')}. Nothing is written.` };
  }
  return { ok: true, text };
}

async function main(): Promise<number> {
  const parsed = parseRenderArgs(process.argv.slice(2));
  if (typeof parsed === 'string') {
    process.stderr.write(`render-policy: ${parsed}\n`);
    return 1;
  }
  const values = JSON.parse(readFileSync(parsed.values, 'utf8')) as Record<string, unknown>;
  const rendered = renderPolicy(readFileSync(parsed.template, 'utf8'), values, parsed.preSoul);
  if (!rendered.ok) {
    process.stderr.write(`render-policy: refused - ${rendered.reason}\n`);
    return 1;
  }
  const sha = createHash('sha256').update(rendered.text, 'utf8').digest('hex');
  if (parsed.stdout) {
    process.stdout.write(rendered.text);
  } else {
    writeFileSync(parsed.out!, rendered.text, { mode: 0o644 });
    // Loaded back through the real loader, against its own hash: what was written is a policy.
    const loaded = await loadPinnedPolicy({ path: parsed.out!, expectedSha256: sha });
    if (!loaded.ok) {
      process.stderr.write(`render-policy: refused - the rendered document does not load: ${loaded.refused.reason}\n`);
      return 1;
    }
    process.stderr.write(`render-policy: wrote ${parsed.out} for ${loaded.value.doc.agentAddress}\n`);
  }
  process.stderr.write(`render-policy: sha256 ${sha}\n`);
  return 0;
}

void _unused;
if (process.argv[1] !== undefined && /render-policy\.(ts|js)$/.test(process.argv[1])) {
  main().then((code) => process.exit(code), (error) => { process.stderr.write(`render-policy: ${String(error)}\n`); process.exit(1); });
}
