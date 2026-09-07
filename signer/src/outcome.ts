// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The one result shape this package uses, and the closed set of names a refusal can carry.
 *
 * # Why a local result type rather than the SDK's `Reading`
 *
 * `Reading`'s failure carries a `kind` from a transport vocabulary — `transport`, `timeout`,
 * `precondition` — which answers "should I retry?". That is the right question for a client
 * calling a node. It is the wrong question here. The purse answers one thing: **which rule said
 * no**, so that a person reading `audit.jsonl` a month later can point at the line in the policy
 * document that produced the refusal, and so that an unattended beat can tell a policy denial
 * (never retry; the policy has to change) from a node that was unreachable (retry next beat).
 *
 * So a refusal carries a `ruleId`. When the policy evaluator refused, it is one of the rule
 * ids from `@projectx-social/policy`. When something before the evaluator refused, it is one of
 * {@link PURSE_REFUSAL_IDS} — a closed union, so a new refusal path cannot be added without being
 * named here and in the README.
 *
 * # A refusal is a value
 *
 * Nothing in this package throws to say no. That is `policySigner`'s existing property and the
 * reason it holds is written in its header: an unattended loop that caught a thrown refusal three
 * frames up would turn a denial into a retry, and a retry against a policy denial is a loop
 * hammering a wall. The purse is exactly that unattended loop's counterparty, so it inherits the
 * property rather than re-deciding it.
 */

import { RULES, type RuleId } from '@projectx-social/policy';

/**
 * Refusals the purse itself produces, before or around the policy evaluator.
 *
 * Each one is a place where the answer is "no" for a reason the policy rules cannot express,
 * because the transaction they judge does not exist yet.
 */
export const PURSE_REFUSAL_IDS = [
  /** The bytes on the socket were not one JSON object, or not the one request this purse answers. */
  'request-malformed',
  /**
   * The connection sent more than `MAX_REQUEST_BYTES` and was answered without being read.
   *
   * Kept apart from `request-malformed` on purpose: a malformed request was read and judged, this
   * one never was, and a reader of `audit.jsonl` needs to be able to tell "somebody sent nonsense"
   * from "somebody streamed at the socket until it stopped listening".
   */
  'request-too-large',
  /** The request was well-formed JSON but its `intent` did not satisfy the schema. */
  'intent-invalid',
  /** The intent was valid and could still not be turned into a transaction. */
  'intent-unbuildable',
  /**
   * The policy signer refused for a reason that was not a policy rule: the build aborted, the
   * simulation could not be read, the simulated transaction would abort, or the inner signer
   * failed. The reason carries the signer's own sentence verbatim.
   */
  'gate-refused',
  /** The intent was rejected before it reached the purse, by the beat's own copy of the schema. */
  'intent-invalid-locally',
  /** The purse could not be reached, or answered something that was not a response. */
  'purse-unreachable',
  /**
   * A chain read the caller needed did not happen: the node refused, timed out, or answered a
   * shape this estate does not recognise.
   *
   * Its own id rather than a shared "error" because the ledger settles a citizen's epoch on these
   * numbers. A read that failed and a read that returned zero must never arrive at the same place:
   * one of them retires a citizen, and only one of them is a fact.
   */
  'chain-unreadable',
  /*
    The statement intent's own refusals (statement.ts). Each is a bound named in that file's
    header: the flags absent, the origin wrong, the clock off, the object or coin outside the
    policy, a price shape or ceiling wrong, the daily count reached.
  */
  'statement-disabled',
  'statement-origin',
  'statement-clock',
  'statement-object',
  'statement-price',
  'statement-ceiling',
] as const;

export type PurseRefusalId = (typeof PURSE_REFUSAL_IDS)[number];

/** Every id a refusal can carry: a policy rule, or one of this package's own. */
export type RefusalId = RuleId | PurseRefusalId;

export interface Refusal {
  readonly ruleId: RefusalId;
  /** The full sentence, written for whoever has to decide whether to widen the policy. */
  readonly reason: string;
}

export type Outcome<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly refused: Refusal };

export function allow<T>(value: T): Outcome<T> {
  return { ok: true, value };
}

export function refuse<T>(ruleId: RefusalId, reason: string): Outcome<T> {
  return { ok: false, refused: { ruleId, reason } };
}

/** Every policy rule id, read from the rule list itself so the two can never drift. */
const POLICY_RULE_IDS: ReadonlySet<string> = new Set(RULES.map((rule) => rule.id));

/**
 * Recover the rule id from a policy refusal's sentence.
 *
 * # Why this reads a string instead of being handed a field
 *
 * `evaluate()` returns `{ allow: false, reason, ruleId }` — the id is right there. `policySigner`
 * then calls `fail('unconfigured', source, decision.reason)`, and `Reading`'s failure has no field
 * for a rule id, so the id is dropped on the floor between the evaluator and this package.
 *
 * The id survives inside the text: `evaluateWith` writes the reason as `` `[${rule.id}] ${reason}` ``
 * (`packages/policy/src/evaluate.ts`), which is a deliberate, tested prefix and not an accident of
 * formatting. So the prefix is parsed back out here, **and checked against `RULES`** — a bracketed
 * word that is not a rule id is not treated as one, so a reason quoting `[something]` in its own
 * prose cannot manufacture an id.
 *
 * Returning `null` is a real answer: it means the signer refused for a reason that was not one of
 * the policy rules, and the caller records `gate-refused`. Guessing a rule id there would put a
 * false attribution in the audit chain, which is the one file that has to be believable.
 *
 * The alternative — widening `Reading` or `PolicySigner` to carry the id — is a change to the
 * custody package on a branch that is not allowed to touch it. It is named in this branch's report
 * as the better fix.
 */
export function ruleIdIn(reason: string): RuleId | null {
  if (!reason.startsWith('[')) return null;
  const end = reason.indexOf(']');
  if (end === -1) return null;
  const candidate = reason.slice(1, end);
  return POLICY_RULE_IDS.has(candidate) ? (candidate as RuleId) : null;
}
