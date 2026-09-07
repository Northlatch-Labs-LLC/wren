// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The purse itself: one request in, one decision out, one audit line either way.
 *
 * # The order of the five steps is not this file's to change
 *
 * Build, observe, gate, evaluate, record-then-sign belong to `policySigner`, and its header
 * explains why step 5 must never be swapped. This file adds exactly one thing before them —
 * turning an intent into a transaction, because the model must never supply bytes — and exactly one
 * thing around them: a line in `audit.jsonl` on **every** path, including the paths that never
 * reach the signer at all.
 *
 * Those paths are the reason the purse keeps its own chain. A malformed request and an intent the
 * schema rejected produce no signer entry, because no transaction was ever built. They are also the
 * two lines that show somebody probing the socket, and a log that only records what got as far as
 * the evaluator would not have them.
 *
 * # One request at a time, and the ceiling is why
 *
 * `handle` runs on a single promise chain: a call that arrives while another is in flight waits,
 * and every request is judged against a ledger every earlier request has already written to.
 *
 * Without that, `server.ts` hands each connection to `void serve(...)` and two overlapping beats —
 * a slow node, a timer that fired while the last beat was still running, the same overlap
 * `build.ts` already anticipates for gas coin selection — each read the outflow ceiling before
 * either had recorded its spend, and each was told yes. Two requests that are individually inside
 * the ceiling and together over it would both be signed, which is the ceiling not being a ceiling.
 * Security's A1 of 2026-09-05; `test/purse.test.ts` sums two 6,000,000 MIST requests against a
 * 10,000,000 ceiling and asserts exactly one signature.
 *
 * The cost is that the purse answers serially. It signs one transaction every thirty minutes, so
 * there is no throughput to lose, and a queue behind a 30-second socket timeout is bounded.
 *
 * # Every way out of `handle` is a value
 *
 * There is no `throw` on any path, including the unexpected ones: the whole body is wrapped, and an
 * exception becomes a recorded refusal. The caller is an unattended beat. An exception three frames
 * up becomes a retry, and a retry against a policy denial is a loop hammering a wall — the sentence
 * is `policySigner`'s and the hazard is the same one at this boundary.
 */

import type { SuiGrpcClient } from '@mysten/sui/grpc';
import type { PolicyDoc } from '@projectx-social/policy';
import {
  policySigner,
  type Signer,
  type SimulationPort,
} from '@projectx-social/signer';
import { AuditFile, type PurseAuditLine } from './audit-file.js';
import { buildIntent, nodeGas, type GasPort } from './build.js';
import type { ChainConfig } from './chain.js';
import { intentHash, parseIntent, type Intent } from './intent.js';
import { SpendLedger, outflowsOf } from './ledger-file.js';
import { ruleIdIn, type Refusal } from './outcome.js';
import { requestSchema, type PurseResponse } from './protocol.js';
import { StatementCounter, judgeStatement, statementSha256, statementText, type StatementBounds } from './statement.js';

export interface PurseOptions {
  readonly signer: Signer;
  readonly policy: PolicyDoc;
  /** sha256 of `canonicalPolicyJson(policy)`. Recorded in every line. */
  readonly policyHash: string;
  /** sha256 of the policy file's bytes, as pinned by the unit. Recorded in every line. */
  readonly policyFileSha256: string;
  readonly chain: ChainConfig;
  readonly client: SuiGrpcClient;
  readonly audit: AuditFile;
  readonly ledger: SpendLedger;
  /** Defaults to {@link nodeGas}. A deployment with a pinned gas coin passes `fixedGas`. */
  readonly gas?: GasPort | undefined;
  /** Supplied by tests with a recorded response, exactly as `policySigner` allows. */
  readonly simulation?: SimulationPort | undefined;
  /** One line per decision. Defaults to stderr. Never called with key material. */
  readonly log?: ((line: string) => void) | undefined;
  /** Statement signing: off unless the server was started with both flags (statement.ts). */
  readonly statements?: StatementBounds | undefined;
  /** The purse's clock, for the statement freshness rule. Tests pin it. */
  readonly now?: (() => number) | undefined;
}

export interface Purse {
  /** The address every signature comes from. */
  readonly address: string;
  readonly policyHash: string;
  /** Answer one request. Never throws. Serialised: one request is in flight at a time. */
  readonly handle: (request: unknown) => Promise<PurseResponse>;
  /**
   * Record and answer a refusal decided **before** the request was read.
   *
   * There is exactly one such refusal: a connection that sent more than `MAX_REQUEST_BYTES`, which
   * `server.ts` must answer without ever assembling the bytes. It cannot go through `handle`,
   * because there is no request to hand it — and it must not bypass the chain, because that probe
   * is precisely the one `audit-file.ts` says the purse keeps its own chain for. Security's A2 of
   * 2026-09-05.
   *
   * Runs on the same promise chain as `handle`, so the audit line lands in order.
   */
  readonly refuseUnread: (refusal: Refusal) => Promise<PurseResponse>;
  /** The head of the audit chain, for anchoring outside this host. */
  readonly auditHead: () => string;
}

export function createPurse(options: PurseOptions): Purse {
  const gas = options.gas ?? nodeGas;
  const log = options.log ?? ((line: string) => process.stderr.write(`${line}\n`));
  const address = options.signer.address;
  const statementCounter = options.statements === undefined ? undefined : new StatementCounter(options.statements.auditPath);

  const signer = policySigner({
    inner: options.signer,
    policy: options.policy,
    client: options.client,
    ledger: () => options.ledger.state(),
    ...(options.simulation === undefined ? {} : { simulation: options.simulation }),
  });

  const record = async (fields: {
    readonly intentKind: string;
    readonly intentHash: string;
    readonly refusal: Refusal | null;
    readonly txDigest: string;
  }): Promise<PurseAuditLine> => {
    const line = await options.audit.append({
      ts: Date.now(),
      address,
      policyHash: options.policyHash,
      policyFileSha256: options.policyFileSha256,
      intentKind: fields.intentKind,
      intentHash: fields.intentHash,
      outcome: fields.refusal === null ? 'signed' : 'refused',
      ruleId: fields.refusal?.ruleId ?? '',
      reason: fields.refusal?.reason ?? '',
      txDigest: fields.txDigest,
    });
    log(
      `purse: ${fields.intentKind} ${line.outcome}` +
        (fields.refusal === null ? ` digest=${fields.txDigest}` : ` rule=${fields.refusal.ruleId}`) +
        ` seq=${String(line.seq)}`,
    );
    return line;
  };

  const refused = async (
    refusal: Refusal,
    about: { readonly intentKind: string; readonly intentHash: string; readonly txDigest: string },
  ): Promise<PurseResponse> => {
    await record({ ...about, refusal });
    return { ok: false, refused: refusal };
  };

  const answer = async (request: unknown): Promise<PurseResponse> => {
    const envelope = requestSchema.safeParse(request);
    if (!envelope.success) {
      return refused(
        {
          ruleId: 'request-malformed',
          reason:
            `the request is not \`{ "intent": … }\`. This purse answers one call and has no other ` +
            `request kind: no key export, no sign-arbitrary-bytes, no policy reload, no health ` +
            `call. An unrecognised field is refused rather than ignored.`,
        },
        { intentKind: 'unparsed', intentHash: '', txDigest: '' },
      );
    }

    const parsed = parseIntent(envelope.data.intent);
    if (!parsed.ok) {
      return refused(
        { ruleId: 'intent-invalid', reason: parsed.reason },
        { intentKind: 'unparsed', intentHash: '', txDigest: '' },
      );
    }

    const intent: Intent = parsed.intent;
    const about = { intentKind: intent.kind, intentHash: intentHash(intent), txDigest: '' };

    if (intent.kind === 'statement') {
      /*
        No transaction: the purse builds one of two texts itself and signs it as a personal
        message, under the bounds statement.ts names. Recorded in the same chain as every
        signature, under intentKind "statement", with the intent's hash; the text is not stored,
        because the intent that produced it is reproducible from the hash and the request.
      */
      const nowMs = (options.now ?? (() => Date.now()))();
      const refusal = await judgeStatement({
        intent,
        bounds: options.statements,
        counter: statementCounter,
        policy: options.policy,
        nowMs,
      });
      if (refusal !== null) return refused(refusal, about);
      const text = statementText(intent, address);
      const signed = await signer.signPersonalMessage(new TextEncoder().encode(text));
      if (!signed.ok) {
        return refused({ ruleId: 'gate-refused', reason: `the statement could not be signed: ${signed.failure.detail}` }, about);
      }
      const line = await record({ ...about, refusal: null, txDigest: '' });
      statementCounter?.record(line.ts);
      return {
        ok: true,
        statement: text,
        statementSha256: statementSha256(text),
        signature: signed.value,
        address,
        timestampMs: intent.timestampMs,
      };
    }

    const built = buildIntent({
      intent,
      chain: options.chain,
      policy: options.policy,
      sender: address,
      gas,
    });
    if (!built.ok) return refused(built.refused, about);

    const signed = await signer.signTransaction(built.value);
    if (!signed.ok) {
      const detail = signed.failure.detail;
      const ruleId = ruleIdIn(detail);
      return refused(
        ruleId === null
          ? {
              ruleId: 'gate-refused',
              reason:
                `the gate refused before any rule was reached (${signed.failure.kind}): ${detail}`,
            }
          : { ruleId, reason: detail },
        about,
      );
    }

    /*
      Signed. Record the spend before answering.

      Before, not after: the response leaves this process and the beat may submit immediately, and
      a crash between answering and recording would leave a signature in the world that the next
      beat's ceiling does not know about. Recording first can at worst over-count a signature that
      was never submitted, which delays a post. The asymmetry is the same one `policySigner` gives
      for recording before signing, one layer out.
    */
    await options.ledger.record(outflowsOf(signed.value.effects, address));
    await record({ ...about, refusal: null, txDigest: signed.value.txDigest });

    return {
      ok: true,
      digest: signed.value.txDigest,
      txBytesB64: Buffer.from(signed.value.bytes).toString('base64'),
      signature: signed.value.signature,
    };
  };

  /*
    The chain every call queues on.

    `then(work, work)` rather than `then(work)`: a rejected predecessor must not stop the queue, and
    the predecessor here is a `handle` call whose own catch has already turned a fault into a
    recorded refusal, so there is nothing left to propagate. `chain` is then reset to a promise that
    can never reject, so a single failure cannot poison every later request.
  */
  let chain: Promise<unknown> = Promise.resolve();
  const inTurn = <T>(work: () => Promise<T>): Promise<T> => {
    const next = chain.then(work, work);
    chain = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  };

  return {
    address,
    policyHash: options.policyHash,
    auditHead: () => options.audit.headHash,
    refuseUnread: (refusal) =>
      inTurn(async () => {
        try {
          await record({ intentKind: 'unread', intentHash: '', refusal, txDigest: '' });
        } catch {
          // The append failed. Still a value: the caller is a socket handler that must answer.
        }
        return { ok: false, refused: refusal };
      }),
    handle: (request) =>
      inTurn(async () => {
        try {
          return await answer(request);
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          const refusal: Refusal = {
            ruleId: 'gate-refused',
            reason:
              `the purse raised an unexpected error and nothing was signed — ${detail}. This is a ` +
              `fault in the purse rather than a decision about the intent, and it is recorded as a ` +
              `refusal because the intent was in fact refused.`,
          };
          try {
            await record({ intentKind: 'unparsed', intentHash: '', refusal, txDigest: '' });
          } catch {
            // The append itself failed. Still a value, never a throw: the caller is a loop, and the
            // one thing known for certain is that retrying will not help.
          }
          return { ok: false, refused: refusal };
        }
      }),
  };
}
