// Built-by: @projectx.sui
/**
 * The statement intent: a personal-message signature over ONE of two texts the SDK itself builds.
 *
 * # Why a purse that signs transactions also signs two sentences
 *
 * weir.social takes a creator's writes over HTTP, each proven by a signature over a statement
 * (`@projectx-social/sdk` `statementFor`): naming a vault to a handle, publishing a post. Heron's
 * address is the purse's, so those signatures can only come from here. The purse never signs
 * bytes it is handed. It signs the text it builds itself from a typed, bounded action, with the
 * origin it was configured for, and it records the intent's hash in the same chain as every
 * transaction it signs. A model that wrote this intent chose a title and a digest; it did not
 * choose what was signed.
 *
 * # What bounds it
 *
 * - Off unless the purse was started with `--api-origin` and `--statements-per-day`: no flag, no
 *   statement, as a refusal with the reason.
 * - The intent's `origin` must equal the configured one, so a statement collected here verifies
 *   nowhere else (the SDK's own reason for binding the origin).
 * - `name-vault` may name only a vault the policy's `allowedObjects` lists, and only for the
 *   purse's own coin type.
 * - `publish` binds the handle, the access, the title, the content digest, and the key and price
 *   for a paid post; the price must be at or under the policy's maxPerPeriod for SUI, because a
 *   post priced above what the agent may itself move in a day is not a price anybody meant.
 * - At most `statementsPerDay` signed statements in any rolling 24 hours, counted from the audit
 *   chain on disk, so a restart does not reset the count.
 */

import { createHash } from 'node:crypto';
import { z } from 'zod';
import { statementFor, type Action } from '@projectx-social/sdk';
import { normaliseAddress, normaliseType, type PolicyDoc } from '@projectx-social/policy';
import { readAuditFile, verifyAuditLines } from './audit-file.js';

const HEX_ID = /^0x[0-9a-fA-F]{1,64}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const MOVE_TYPE = /^0x[0-9a-fA-F]{1,64}::[A-Za-z_][A-Za-z0-9_]{0,127}::[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/**
 * The web's own limits, mirrored: the title from packages/web/lib/content.ts:221, the display
 * name and bio from app/api/creator/profile/route.ts:17-18. test/statement.test.ts reads those
 * files and pins the numbers here to them, so a purse cannot sign what the route answers 400 to.
 */
export const MAX_POST_TITLE_LENGTH = 200;
export const MAX_DISPLAY_NAME_LENGTH = 60;
export const MAX_BIO_LENGTH = 280;
export const MAX_HANDLE_LENGTH = 32;

/** One line of printable text, no control characters: a statement is line-oriented. */
const line = (max: number) => z.string().min(1).max(max).regex(/^[^\x00-\x1f\x7f]*$/, 'a statement field is one line without control characters');

export const nameVaultAction = z.strictObject({
  kind: z.literal('name-vault'),
  vaultId: z.string().regex(HEX_ID),
  name: z.string().max(MAX_DISPLAY_NAME_LENGTH).regex(/^[^\x00-\x1f\x7f]*$/),
  bio: z.string().max(MAX_BIO_LENGTH).regex(/^[^\x00-\x1f\x7f]*$/),
  coinType: z.string().regex(MOVE_TYPE),
});

export const publishAction = z.strictObject({
  kind: z.literal('publish'),
  handle: z.string().min(1).max(MAX_HANDLE_LENGTH).regex(/^[a-z0-9_]+$/),
  title: line(MAX_POST_TITLE_LENGTH),
  access: z.enum(['public', 'paid']),
  contentSha256: z.string().regex(SHA256_HEX),
  /** Empty for a public post, as the route signs it; the content key for a paid one, with no edge whitespace (the route refuses it). */
  contentKey: z.string().max(256).regex(/^[^\x00-\x1f\x7f]*$/).refine((v) => v === v.trim(), { message: 'a content key carries no leading or trailing whitespace' }),
  /** Empty for a public post; a positive u64 in MIST for a paid one. */
  price: z.string().regex(/^$|^[1-9][0-9]{0,19}$/),
});

export const statementIntent = z.strictObject({
  kind: z.literal('statement'),
  action: z.discriminatedUnion('kind', [nameVaultAction, publishAction]),
  timestampMs: z.number().int().positive(),
  origin: z.string().url(),
});

export type StatementIntent = z.infer<typeof statementIntent>;

export interface StatementBounds {
  /** The one origin a statement may be issued for. */
  readonly origin: string;
  /** Signed statements allowed in any rolling 24 hours. */
  readonly perDay: number;
  /** The audit file the count is seeded from, once, after its chain verifies. */
  readonly auditPath: string;
  /** The vault a name-vault statement may name: Heron's own, not any allowed object. */
  readonly vaultId: string;
}

/**
 * The rolling-day count of signed statements. Seeded ONCE from the audit chain on disk, after
 * `verifyAuditLines` says the chain is intact, then kept in memory and incremented on each
 * signature: the file is read at start, not on every request, so it is not a trust boundary a
 * writer of that file could move (Security's finding 5, 2026-09-05). A restart re-seeds from the
 * chain, so the count survives one; a chain that does not verify refuses every statement.
 */
export class StatementCounter {
  #times: number[] | null = null;
  readonly #auditPath: string;

  constructor(auditPath: string) {
    this.#auditPath = auditPath;
  }

  async signedSince(sinceMs: number): Promise<{ ok: true; count: number } | { ok: false; reason: string }> {
    if (this.#times === null) {
      const read = await readAuditFile(this.#auditPath);
      if (!read.ok) return { ok: false, reason: `the audit chain could not be read to seed the statement count (${read.reason})` };
      const verdict = verifyAuditLines(read.lines);
      if (!verdict.intact) return { ok: false, reason: `the audit chain is broken at line ${String(verdict.line)} (${verdict.reason}); no statement is signed over a broken chain` };
      this.#times = read.lines.filter((e) => e.intentKind === 'statement' && e.outcome === 'signed').map((e) => e.ts);
    }
    return { ok: true, count: this.#times.filter((t) => t >= sinceMs).length };
  }

  record(ts: number): void {
    (this.#times ??= []).push(ts);
  }
}

export const DAY_MS = 24 * 60 * 60 * 1000;

export interface StatementRefusal {
  readonly ruleId: 'statement-disabled' | 'statement-origin' | 'statement-object' | 'statement-price' | 'statement-ceiling' | 'statement-clock';
  readonly reason: string;
}

/**
 * Everything the purse checks before it signs, as a value. `nowMs` is the purse's clock; the
 * intent's timestamp must sit within the SDK's own freshness window of it, so a model cannot
 * pre-sign a statement for next week.
 */
export async function judgeStatement(args: {
  readonly intent: StatementIntent;
  readonly bounds: StatementBounds | undefined;
  readonly counter: StatementCounter | undefined;
  readonly policy: PolicyDoc;
  readonly nowMs: number;
}): Promise<StatementRefusal | null> {
  const { intent, bounds, counter, policy, nowMs } = args;
  if (bounds === undefined) {
    return {
      ruleId: 'statement-disabled',
      reason: 'this purse was started without --api-origin and --statements-per-day, so it signs no statement. Nothing was signed.',
    };
  }
  if (intent.origin !== bounds.origin) {
    return {
      ruleId: 'statement-origin',
      reason: `the statement names an origin other than the one this purse signs for (${bounds.origin}). Nothing was signed.`,
    };
  }
  if (Math.abs(intent.timestampMs - nowMs) > 60_000) {
    return {
      ruleId: 'statement-clock',
      reason: 'the statement is dated more than a minute from this purse\'s clock. A statement is issued now or not at all.',
    };
  }
  if (intent.action.kind === 'name-vault') {
    // Heron's own vault, exactly, not any object the policy allows (the cap and the clock are
    // allowed objects too and neither is a vault). Normalised on both sides, as every policy rule
    // normalises, so a short spelling from the chain is the same vault.
    const wanted = normaliseAddress(bounds.vaultId);
    const named = normaliseAddress(intent.action.vaultId);
    const objects = new Set(policy.allowedObjects.map((o) => normaliseAddress(o)));
    if (wanted === null || named === null || named !== wanted || !objects.has(named)) {
      return {
        ruleId: 'statement-object',
        reason: 'the vault to be named is not Heron\'s own vault as this purse was started with, or not in the policy\'s allowed objects. Nothing was signed.',
      };
    }
    const coin = normaliseType(intent.action.coinType);
    if (coin === null || !policy.allowedTypeArguments.some((t) => normaliseType(t) === coin)) {
      return {
        ruleId: 'statement-object',
        reason: 'the coin type to be named is not in the policy\'s allowed type arguments. Nothing was signed.',
      };
    }
  } else {
    const paid = intent.action.access === 'paid';
    if (paid !== (intent.action.contentKey !== '') || paid !== (intent.action.price !== '')) {
      return {
        ruleId: 'statement-price',
        reason: 'a paid post carries a content key and a price; a public post carries neither. Nothing was signed.',
      };
    }
    if (paid) {
      const ceiling = policy.outflowCeilings.find((c) => /::sui::SUI$/.test(c.coinType));
      if (ceiling === undefined || BigInt(intent.action.price) > BigInt(ceiling.maxPerPeriod)) {
        return {
          ruleId: 'statement-price',
          reason: 'the price is above the policy\'s daily SUI ceiling, or the policy names no SUI ceiling. Nothing was signed.',
        };
      }
    }
  }
  const since = nowMs - DAY_MS;
  if (counter === undefined) {
    return { ruleId: 'statement-ceiling', reason: 'no statement counter was seeded for this purse. Nothing was signed.' };
  }
  const counted = await counter.signedSince(since);
  if (!counted.ok) {
    return { ruleId: 'statement-ceiling', reason: `${counted.reason}. Nothing was signed.` };
  }
  const signedToday = counted.count;
  if (signedToday >= bounds.perDay) {
    return {
      ruleId: 'statement-ceiling',
      reason: `${String(signedToday)} statements were signed in the last 24 hours, the ceiling is ${String(bounds.perDay)}. Nothing was signed.`,
    };
  }
  return null;
}

/** The exact text that is signed, from the SDK's one builder. */
export function statementText(intent: StatementIntent, address: string): string {
  return statementFor(intent.action as Action, address, intent.timestampMs, intent.origin);
}

export function statementSha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

