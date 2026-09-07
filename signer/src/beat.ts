// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * Phase two of the beat: outside the container, with the state sink written on every path.
 *
 * # The two phases, and what the split buys
 *
 * Phase one runs the container. It reads and writes exactly one file: `<runs>/<beat-id>/intent.json`.
 * It has no key, no socket that reaches a key, and no way to produce transaction bytes.
 *
 * Phase two is this file. It reads that intent, validates it against the same schema the purse
 * uses, asks the purse, and submits what comes back. A prompt-injected model can therefore write a
 * bad intent and nothing else — the CISO's §2, in his words.
 *
 * The schema is checked **twice**, here and in the purse, and that is not redundancy to delete. The
 * purse's copy is the authority: it is the one that runs next to the key. This copy exists so that
 * a malformed intent is refused before it is put on a socket at all, which keeps the purse's audit
 * chain a record of decisions rather than of the beat's own bugs, and gives the state file a rule
 * id for a failure that never left this host.
 *
 * # `state/latest.json` is written on every path
 *
 * Signed, refused, no intent at all, and an exception. That is the whole point of the file: a sink
 * that only records success cannot detect failure. The `finally` below is the mechanism and
 * `test/beat.test.ts` asserts it on a forced refusal and on a thrown submit.
 */

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseIntent } from './intent.js';
import { looksLikePlan, parsePublishPlan, runPublishPlan, type PublishPorts } from './publish.js';
import type { PurseResponse } from './protocol.js';
import { writeState, type BeatOutcome, type BeatState } from './state.js';
import type { Outcome } from './outcome.js';

/** How the intent reaches the purse. The socket client in production; a direct purse in tests. */
export interface AskPort {
  readonly ask: (intent: unknown) => Promise<Outcome<PurseResponse>>;
}

/** How a signed transaction reaches the chain. Absent under `--dry-run`. */
export interface SubmitPort {
  readonly submit: (args: {
    readonly txBytesB64: string;
    readonly signature: string;
  }) => Promise<string>;
}

export interface PhaseTwoOptions {
  readonly runsDir: string;
  readonly stateDir: string;
  readonly beatId: string;
  readonly ask: AskPort;
  /** Omitted, or `--dry-run`: nothing is submitted and the outcome is still `signed`. */
  readonly submit?: SubmitPort | undefined;
  readonly now?: (() => Date) | undefined;
  /**
   * What a publish plan needs beyond the purse: the API origin, the purse's address, the chain
   * reads and the HTTP calls. Absent, a plan is refused locally rather than half-run.
   */
  readonly publish?:
    | { readonly origin: string; readonly address: string; readonly profile: { name: string; bio: string }; readonly ports: Omit<PublishPorts, 'ask' | 'now'> }
    | undefined;
  /**
   * Book what this beat actually cost against the soul's allowance.
   *
   * Absent, nothing is recorded and the beat behaves exactly as before — a deployment without a
   * soul is a real deployment, not a broken one.
   *
   * `gasOf` reads the cost off the chain AFTER submission. It is not estimated and not configured:
   * an allowance is a bound on real spending, and a figure the operator cannot check against a
   * transaction digest is not a measurement of anything.
   */
  readonly recordSpend?:
    | {
        readonly packageId: string;
        readonly soul: { readonly objectId: string; readonly initialSharedVersion: string };
        readonly gasOf: (digest: string) => Promise<{ ok: true; value: bigint | null } | { ok: false; refused: { reason: string } }>;
      }
    | undefined;
}

export interface PhaseTwoResult {
  readonly state: BeatState;
  readonly statePath: string;
}

export const INTENT_FILE = 'intent.json';

/**
 * Run phase two.
 *
 * Never throws. The one thing this function guarantees is that `state/latest.json` exists and
 * describes what happened when it returns — so the return value is the state, and the caller's only
 * job is to turn it into an exit code.
 */
export async function runPhaseTwo(options: PhaseTwoOptions): Promise<PhaseTwoResult> {
  const now = options.now ?? (() => new Date());
  const startedAt = now().toISOString();
  const intentPath = join(options.runsDir, options.beatId, INTENT_FILE);

  let outcome: BeatOutcome = 'error';
  let ruleId: string | undefined;
  let digest: string | undefined;
  let submittedDigest: string | undefined;
  let error: string | undefined;
  let postId: string | undefined;
  let handle: string | undefined;
  let named: boolean | undefined;
  let spentMist: string | undefined;
  let spendDigest: string | undefined;
  let spendError: string | undefined;

  /*
    The work is an inner function and the write is after it, rather than a `return finish()` inside
    the try. With the write inside, a `finish()` that itself threw would land in the same catch and
    be called a second time — and the second call would throw again, out of a function whose entire
    contract is that it does not. Here there is exactly one call to `writeState`, on exactly one
    path, and the outcome variables above are the only thing the attempt communicates.
  */
  const attempt = async (): Promise<void> => {
    let text: string;
    try {
      text = await readFile(intentPath, 'utf8');
    } catch (readError) {
      const code = (readError as NodeJS.ErrnoException).code;
      if (code === 'ENOENT') {
        // Not an error. The container ran and decided there was nothing to do, or it failed before
        // writing. Either way nothing was asked of the purse, and `no-intent` says exactly that —
        // a different fact from "the purse refused" and from "the beat broke".
        outcome = 'no-intent';
        error = `no intent at ${intentPath}`;
        return;
      }
      outcome = 'error';
      error = `${intentPath} could not be read: ${String(code ?? readError)}`;
      return;
    }

    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      outcome = 'refused';
      ruleId = 'intent-invalid-locally';
      error = `${intentPath} is not valid JSON. Nothing was sent to the purse.`;
      return;
    }

    if (looksLikePlan(value)) {
      const plan = parsePublishPlan(value);
      if (!plan.ok) {
        outcome = 'refused';
        ruleId = 'intent-invalid-locally';
        error = plan.reason;
        return;
      }
      if (options.publish === undefined) {
        outcome = 'refused';
        ruleId = 'intent-invalid-locally';
        error = 'a publish plan was written but this beat runs without an API origin and address; nothing was sent';
        return;
      }
      const result = await runPublishPlan({
        plan: plan.plan,
        address: options.publish.address,
        origin: options.publish.origin,
        beatId: options.beatId,
        profile: options.publish.profile,
        ports: {
          ...options.publish.ports,
          ask: (intent) => options.ask.ask(intent),
          now: () => now().getTime(),
        },
      });
      if (result.priceDigest !== undefined) submittedDigest = result.priceDigest;
      if (result.outcome === 'published') {
        outcome = 'published';
        postId = result.postId;
        handle = result.handle;
        named = result.named;
        return;
      }
      outcome = result.outcome;
      error = result.error;
      if (result.outcome === 'refused') ruleId = result.ruleId;
      return;
    }

    const parsed = parseIntent(value);
    if (parsed.ok && parsed.intent.kind === 'statement') {
      /*
        Security's B1 (2026-09-05): the file is the model's, and a statement intent in it would
        hand the purse a title, a handle, a name and a bio the model chose. Statements have exactly
        one constructor, runPublishPlan, from a validated plan; a raw one here is refused locally
        and never reaches the socket.
      */
      outcome = 'refused';
      ruleId = 'intent-invalid-locally';
      error = 'a statement intent was written to the intent file. Statements are built only by the publish plan from a validated plan; nothing was sent to the purse.';
      return;
    }
    if (!parsed.ok) {
      outcome = 'refused';
      ruleId = 'intent-invalid-locally';
      error = parsed.reason;
      return;
    }

    const answered = await options.ask.ask(parsed.intent);
    if (!answered.ok) {
      // The purse could not be reached, or did not answer with a response. A no-answer, not a
      // refusal — the CISO's alerting list keeps them apart because only one of them means "stop".
      outcome = 'error';
      ruleId = answered.refused.ruleId;
      error = answered.refused.reason;
      return;
    }

    const response = answered.value;
    if (!response.ok) {
      outcome = 'refused';
      ruleId = response.refused.ruleId;
      error = response.refused.reason;
      return;
    }

    if (!('digest' in response)) {
      // Unreachable by construction (a statement intent is refused above), kept as a value.
      outcome = 'error';
      error = 'the purse answered a transaction intent with a statement';
      return;
    }
    digest = response.digest;
    if (options.submit === undefined) {
      outcome = 'signed';
      return;
    }

    submittedDigest = await options.submit.submit({
      txBytesB64: response.txBytesB64,
      signature: response.signature,
    });
    outcome = 'signed';
  };

  try {
    await attempt();
  } catch (thrown) {
    /*
      A throw from anywhere above — the submit port, a node that hung up mid-response, a bug here.

      `outcome` is left at whatever the attempt had reached. In particular a throw from `submit`
      leaves `digest` set, so the state file records that a signature exists for that digest and
      that submitting it threw. "It may well have landed" is the honest reading and the operator
      needs the digest to check; a state file that reported only `error` would send them looking
      for a transaction they cannot name.
    */
    outcome = 'error';
    error = thrown instanceof Error ? thrown.message : String(thrown);
  }

  /*
    Book the spend, after the work and outside its try.

    Deliberately after `attempt` rather than inside it: a failure to record what a beat cost must
    never turn a beat that published into a beat that reports an error. The publish already
    happened and the post is on the network; the soul's books being one beat behind is a smaller,
    recoverable fact, and `spendError` says so in the state file rather than hiding it.

    Recorded only for a transaction that was actually submitted. A dry run and a refusal spend
    nothing, and booking a spend for either would put a number on the chain that no transaction
    backs.
  */
  if (options.recordSpend !== undefined && submittedDigest !== undefined) {
    try {
      const gas = await options.recordSpend.gasOf(submittedDigest);
      if (!gas.ok) {
        spendError = gas.refused.reason;
      } else if (gas.value === null) {
        // The transaction was rebated more than it cost. Nothing to book, and that is not an error.
        spentMist = '0';
      } else {
        const answered = await options.ask.ask({
          kind: 'record_spend',
          packageId: options.recordSpend.packageId,
          soul: { ...options.recordSpend.soul, mutable: true },
          amountMist: gas.value.toString(),
        });
        if (!answered.ok) {
          spendError = answered.refused.reason;
        } else if (!answered.value.ok) {
          spendError = answered.value.refused.reason;
        } else if ('digest' in answered.value) {
          spentMist = gas.value.toString();
          spendDigest = answered.value.digest;
          if (options.submit !== undefined) {
            await options.submit.submit({
              txBytesB64: answered.value.txBytesB64,
              signature: answered.value.signature,
            });
          }
        }
      }
    } catch (thrown) {
      spendError = thrown instanceof Error ? thrown.message : String(thrown);
    }
  }

  const state: BeatState = {
    beatId: options.beatId,
    startedAt,
    finishedAt: now().toISOString(),
    outcome,
    ...(ruleId === undefined ? {} : { ruleId }),
    ...(digest === undefined ? {} : { digest }),
    ...(submittedDigest === undefined ? {} : { submittedDigest }),
    ...(error === undefined ? {} : { error }),
    ...(postId === undefined ? {} : { postId }),
    ...(handle === undefined ? {} : { handle }),
    ...(named === undefined ? {} : { named }),
    ...(spentMist === undefined ? {} : { spentMist }),
    ...(spendDigest === undefined ? {} : { spendDigest }),
    ...(spendError === undefined ? {} : { spendError }),
  };
  const statePath = await writeState(options.stateDir, state);
  return { state, statePath };
}
