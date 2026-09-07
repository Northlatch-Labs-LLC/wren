// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * `state/latest.json` — the sink that is written whatever happened.
 *
 * # A sink that only records success cannot detect failure
 *
 * That is the CTO's 3.10 in his own words, and it is the reason this file has an `outcome` field
 * with four values rather than a `success` boolean. The laptop pulls this file on a timer and the
 * Desk raises staleness; the host's own watchdog refuses if it is older than ninety minutes. Both
 * of those detect "the beat never ran". Neither detects "the beat ran and was refused" unless the
 * refusal is written down here, with the rule that produced it.
 *
 * `refused` and `error` are kept apart on purpose. A refusal is the system working: the policy said
 * no and nothing was signed, and the fix is a policy decision. An error is the system broken: the
 * purse was unreachable, the node timed out, a file could not be written. The CISO's alerting list
 * distinguishes them ("refused distinguished from no-answer, with the runtime stopping on the
 * second") and a single failure flag would collapse the two.
 *
 * # Written atomically
 *
 * A temporary file in the same directory, then `rename`, which is atomic within a filesystem. The
 * puller reads this file on a timer with no lock between them; a partial write would be parsed as a
 * corrupt state and reported as an outage that is not happening.
 */

import { mkdir, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export type BeatOutcome = 'signed' | 'refused' | 'no-intent' | 'error' | 'published';

export interface BeatState {
  readonly beatId: string;
  /** ISO 8601, UTC. */
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly outcome: BeatOutcome;
  readonly ruleId?: string;
  readonly digest?: string;
  readonly error?: string;
  /** Present only when the transaction was submitted. Absent under `--dry-run`. */
  readonly submittedDigest?: string;
  /** A publish plan's result: the post id the API returned, the handle it was published under. */
  readonly postId?: string;
  readonly handle?: string;
  /** True when this beat also named the vault to the handle (a first publish). */
  readonly named?: boolean;
  /*
    What this beat cost, booked against the soul's allowance.

    `spentMist` is what the submitted transaction actually cost, read off the chain after the fact
    — never estimated. "0" means the transaction was rebated more than it cost, which is ordinary
    on Sui and is not an error. All three are absent on a deployment with no soul configured.
  */
  readonly spentMist?: string;
  readonly spendDigest?: string;
  /** Set when the spend could not be booked. The beat still succeeded; the books are one behind. */
  readonly spendError?: string;
}

export const STATE_FILE = 'latest.json';

export async function writeState(stateDir: string, state: BeatState): Promise<string> {
  await mkdir(stateDir, { recursive: true });
  const target = join(stateDir, STATE_FILE);
  const temporary = `${target}.writing`;
  await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o640 });
  await rename(temporary, target);
  return target;
}
