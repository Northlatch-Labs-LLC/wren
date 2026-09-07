// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The policy document, pinned by hash.
 *
 * # Changing the policy is a redeploy, not a reload
 *
 * There is no reload call on the socket and there is no file watcher here. The document is read
 * once, at start, and its sha256 must equal the digest passed on the command line — which comes
 * from the unit file, which is on disk under root and not writable by the purse's own user.
 *
 * The property that buys: a person who can write the policy file cannot widen the policy. They can
 * make the purse **refuse to start**, which is loud, recorded, and refuses everything rather than
 * permitting something. Widening needs the unit changed too, which needs root, and root's edit is
 * in the deploy record.
 *
 * # Two hashes, and they answer different questions
 *
 * `fileSha256` is over the bytes as they sit on disk. It is what the unit pins and what a person
 * can reproduce with `sha256sum`.
 *
 * `policyHash` is over `canonicalPolicyJson(doc)` — key order fixed, so reformatting the file does
 * not change it. It is what `policySigner` writes into every audit entry, and what makes a widening
 * visible at the exact entry where it took effect. Both go in the purse's own audit lines, because
 * a reader with only the canonical hash cannot check the file they were handed, and a reader with
 * only the file hash cannot line the purse's log up against the signer's.
 */

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import { canonicalPolicyJson, type PolicyDoc } from '@projectx-social/policy';
import { allow, refuse, type Outcome } from './outcome.js';

const u64 = z.string().regex(/^(0|[1-9][0-9]{0,19})$/, 'not a u64 written as a decimal string');

/**
 * The document's shape, checked rather than cast.
 *
 * `PolicyDoc` is an interface; `JSON.parse` produces `any`. Casting one to the other is how a
 * policy with `allowedTargets` misspelled becomes a policy with **no** allowed targets — which the
 * evaluator would read as an empty allow-list and refuse everything, so it fails closed, but the
 * operator would be told "move-call-target" for a document they believe permits the call. Checked
 * here, the answer is "your document has no allowedTargets", at start, once.
 */
export const policyDocSchema = z.strictObject({
  version: z.literal(1),
  agentAddress: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/, 'not a Sui address'),
  outflowCeilings: z.array(
    z.strictObject({ coinType: z.string().min(1), maxPerPeriod: u64, periodMs: z.number().int().positive() }),
  ),
  allowedTargets: z.array(z.string().min(1)),
  allowedTypeArguments: z.array(z.string().min(1)),
  allowedRecipients: z.array(z.string().min(1)),
  allowedObjects: z.array(z.string().min(1)),
  /*
    Optional, and the only optional key in this schema, because it is the only one a
    previously-valid deployed document can lack — `policy/heron-content.json` and
    `policy/heron-ledger.json` were both written before approval bars existed and must keep
    loading. `strictObject` is why this line has to exist at all: without it a document carrying a
    bar would be REFUSED at start, and the operator who wrote the bar would be told their document
    has an unknown key rather than that their gate works.

    `.optional()` here means absent-or-a-list. It does not mean the evaluator treats absence as a
    bar of zero; `PolicyDoc.approvalThresholds` says why absence is the permissive reading for this
    one field and the strict reading for every other.
  */
  approvalThresholds: z
    .array(z.strictObject({ coinType: z.string().min(1), maxWithoutApproval: u64 }))
    .optional(),
  maxGasBudgetMist: u64,
  allowedCommandKinds: z.array(z.string().min(1)),
});

/**
 * The calls the `LedgerCap` service is for: the three entry points on the deployed soul package
 * that take a `&LedgerCap`, read off mainnet (`0x8d6567ed…635f::soul`, 2026-09-06).
 *
 * `record_spend` is deliberately NOT here. It is in the same Move module and it is a content-arm
 * call: it takes no capability at all, because the contract asserts `ctx.sender() == soul.agent`,
 * so the key that signs it is the hot key that publishes. Grouping by module rather than by
 * capability would have put it on this side and merged the two paths by accident.
 */
const SETTLEMENT_SUFFIXES = [
  '::soul::settle_epoch',
  '::soul::book_earned',
  '::soul::book_burned',
] as const;

function isSettlement(target: string): boolean {
  return SETTLEMENT_SUFFIXES.some((suffix) => target.endsWith(suffix));
}

/**
 * Refuse a document whose target set spans both money paths.
 *
 * The rule is blunt on purpose: a document that names a settlement call may name **only**
 * settlement calls. It used to be blunter still — `settle_epoch` and nothing else — because the
 * settlement arm had exactly one entry point, and the note here argued against any list on the
 * grounds that an enumeration goes stale when the next entry point is added.
 *
 * That objection is right about the wrong list. Enumerating what counts as a *content* entry goes
 * stale OPEN: a content call this file had not heard of would sit beside `settle_epoch` and be
 * allowed. Enumerating the *settlement* set goes stale CLOSED: a fourth `LedgerCap` call added to
 * the contract tomorrow is not in {@link SETTLEMENT_SUFFIXES}, so a document naming it beside
 * `settle_epoch` is refused until somebody updates this file deliberately. A list whose staleness
 * refuses is a different object from a list whose staleness admits, and only the second one was
 * the danger.
 *
 * The set is by capability, not by module — see {@link SETTLEMENT_SUFFIXES} for why `record_spend`
 * is on the other side despite living in the same Move module.
 *
 * `policy/heron-ledger.json` and `policy/wren-ledger.json` are those documents; each names the
 * three, and nothing else.
 *
 * Returns the sentence to refuse with, or `null` when the document keeps to one path.
 */
export function refuseMixedMoneyPaths(targets: readonly string[]): string | null {
  const settlement = targets.filter(isSettlement);
  if (settlement.length === 0) return null;
  const others = targets.filter((target) => !isSettlement(target));
  if (others.length === 0) return null;

  return (
    `the document allows ${settlement.join(', ')} and also ${others.join(', ')}. One signer per ` +
    `money path: the \`LedgerCap\` that settles an epoch and the key that prices content are ` +
    `different capabilities on different keys under different services (executive decision 6), and ` +
    `a single document naming both would put both money paths behind one signature. A settlement ` +
    `would then consume the content arm's outflow ceiling, and a compromise of either key would ` +
    `reach both. Deploy \`policy/heron-content.json\` to the content purse and ` +
    `\`policy/heron-ledger.json\` to the ledger purse; do not merge them.`
  );
}

export interface PinnedPolicy {
  readonly doc: PolicyDoc;
  /** sha256 of the file's bytes, hex. What the unit pins. */
  readonly fileSha256: string;
  /** sha256 of `canonicalPolicyJson(doc)`, hex. What the signer's audit entries carry. */
  readonly policyHash: string;
}

export async function loadPinnedPolicy(args: {
  readonly path: string;
  readonly expectedSha256: string;
}): Promise<Outcome<PinnedPolicy>> {
  if (!/^[0-9a-f]{64}$/.test(args.expectedSha256)) {
    return refuse(
      'request-malformed',
      `--policy-sha256 must be 64 lowercase hex characters; it is not. The purse will not start ` +
        `without a pin: an unpinned policy is a policy anyone who can write the file can widen.`,
    );
  }

  let bytes: Buffer;
  try {
    bytes = await readFile(args.path);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return refuse('request-malformed', `the policy document at ${args.path} could not be read: ${detail}`);
  }

  const fileSha256 = createHash('sha256').update(bytes).digest('hex');
  if (fileSha256 !== args.expectedSha256) {
    return refuse(
      'request-malformed',
      `the policy document at ${args.path} hashes to ${fileSha256}, and the unit pins ` +
        `${args.expectedSha256}. The purse refuses to start. Either the document was edited without ` +
        `the pin being updated — which is the case this check exists for — or a redeploy was left ` +
        `half done. Changing the policy is a redeploy, not a reload.`,
    );
  }

  let value: unknown;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    return refuse('request-malformed', `the policy document at ${args.path} is not valid JSON.`);
  }

  const parsed = policyDocSchema.safeParse(value);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`);
    return refuse(
      'request-malformed',
      `the policy document at ${args.path} is not a policy: ${problems.join('; ')}.`,
    );
  }

  const doc: PolicyDoc = parsed.data;

  const mixed = refuseMixedMoneyPaths(doc.allowedTargets);
  if (mixed !== null) {
    return refuse('request-malformed', `the policy document at ${args.path} is refused: ${mixed}`);
  }

  return allow({ doc, fileSha256, policyHash: createHash('sha256').update(canonicalPolicyJson(doc), 'utf8').digest('hex') });
}
