// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * What this agent has already spent, on disk.
 *
 * # Why this file exists rather than an empty ledger
 *
 * `policySigner` takes `ledger: () => LedgerState` and the `outflow-ceiling` rule reads it. Hand it
 * a function that always returns no prior spend and the ceiling stops being a rolling window: it
 * becomes a per-transaction size check, and an unattended loop defeats it by asking twice. The
 * rule's own text says so — "a window that is zero ... would apply to this transaction alone and a
 * loop would defeat it".
 *
 * The purse is the only process that can sign for this address, so it is the only place that can
 * know the spend. It records one line per **signed** transaction: the coin type, the outflow
 * magnitude, and when. A refusal spends nothing and writes nothing here.
 *
 * # Recorded from the simulation, not from the chain
 *
 * The amount comes from the effects the policy judged. That is deliberately conservative in the
 * one direction that matters: a transaction that was signed and then never landed still counts
 * against the window. The alternative — confirm on chain first — leaves a gap between signing and
 * confirmation in which a second beat sees no prior spend, and that gap is exactly when a loop
 * being steered would ask again. Over-counting costs a delayed post; under-counting costs the
 * ceiling.
 *
 * # Pruning
 *
 * Entries older than the longest period in the policy are dropped on load, not deleted eagerly:
 * the file is rewritten at open, once, so an unbounded log does not accumulate on a 10 GB disk.
 * The dropped entries are outside every window the policy can ask about, so nothing that could
 * change a decision is lost. The audit chain, which is the record of what happened, is never
 * pruned.
 */

import { open, readFile, rename, writeFile } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import type { LedgerEntry, LedgerState, PolicyDoc, SimulatedEffects } from '@projectx-social/policy';

/** The outflows this transaction puts out, by coin type, as positive magnitudes. */
export function outflowsOf(effects: SimulatedEffects, agentAddress: string): LedgerEntry[] {
  const wanted = normalise(agentAddress);
  const totals = new Map<string, bigint>();

  for (const change of effects.balanceChanges) {
    if (normalise(change.address) !== wanted) continue;
    let amount: bigint;
    try {
      amount = BigInt(change.amount);
    } catch {
      // An unreadable amount is not zero. It is skipped here only because the `amount-wellformed`
      // rule has already refused any transaction that carries one — this function never runs on a
      // transaction the evaluator did not allow.
      continue;
    }
    if (amount >= 0n) continue;
    totals.set(change.coinType, (totals.get(change.coinType) ?? 0n) + -amount);
  }

  return [...totals].map(([coinType, amountOut]) => ({
    coinType,
    amountOut: amountOut.toString(),
    atMs: effects.observedAtMs,
  }));
}

function normalise(address: string): string {
  const trimmed = address.trim();
  if (!/^0x[0-9a-fA-F]{1,64}$/.test(trimmed)) return trimmed.toLowerCase();
  return `0x${trimmed.slice(2).toLowerCase().padStart(64, '0')}`;
}

function longestPeriodMs(policy: PolicyDoc): number {
  let longest = 0;
  for (const ceiling of policy.outflowCeilings) {
    if (Number.isInteger(ceiling.periodMs) && ceiling.periodMs > longest) longest = ceiling.periodMs;
  }
  return longest;
}

/** The spend ledger, held open for appends. */
export class SpendLedger {
  readonly #handle: FileHandle;
  readonly #entries: LedgerEntry[];
  readonly #now: () => number;

  private constructor(handle: FileHandle, entries: LedgerEntry[], now: () => number) {
    this.#handle = handle;
    this.#entries = entries;
    this.#now = now;
  }

  /**
   * Open, keeping only what any ceiling in this policy could still ask about.
   *
   * A line that does not parse is **kept** rather than dropped, and it is kept in the form the
   * evaluator will refuse: `outflow-ceiling` returns a denial for a ledger entry it cannot read,
   * with the words "an unreadable record of past spending must not be counted as zero". Dropping
   * it here would turn that refusal into a silent zero, which is the whole hazard.
   */
  static async open(args: {
    readonly path: string;
    readonly policy: PolicyDoc;
    readonly now?: () => number;
  }): Promise<{ ok: true; ledger: SpendLedger } | { ok: false; reason: string }> {
    const now = args.now ?? (() => Date.now());
    const window = longestPeriodMs(args.policy);
    const cutoff = now() - window;
    const kept: LedgerEntry[] = [];

    let text = '';
    try {
      text = await readFile(args.path, 'utf8');
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT') {
        return { ok: false, reason: `${args.path} could not be read: ${String(code ?? error)}` };
      }
    }

    for (const line of text.split('\n')) {
      if (line.trim() === '') continue;
      let value: unknown;
      try {
        value = JSON.parse(line);
      } catch {
        return {
          ok: false,
          reason:
            `${args.path} holds a line that is not JSON. The purse will not start on an unreadable ` +
            `spend record: prior spend that cannot be read must never be counted as zero.`,
        };
      }
      const entry = value as Partial<LedgerEntry>;
      if (typeof entry.coinType !== 'string' || typeof entry.amountOut !== 'string' || typeof entry.atMs !== 'number') {
        return {
          ok: false,
          reason: `${args.path} holds a line that is not a spend entry. The purse will not start.`,
        };
      }
      if (entry.atMs < cutoff) continue;
      kept.push({ coinType: entry.coinType, amountOut: entry.amountOut, atMs: entry.atMs });
    }

    // Rewritten once, atomically, so the file stays bounded without ever being truncated in place.
    const temporary = `${args.path}.rewriting`;
    try {
      await writeFile(temporary, kept.map((e) => JSON.stringify(e)).join('\n') + (kept.length > 0 ? '\n' : ''), {
        mode: 0o600,
      });
      await rename(temporary, args.path);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return { ok: false, reason: `${args.path} could not be rewritten: ${detail}` };
    }

    let handle: FileHandle;
    try {
      handle = await open(args.path, 'a', 0o600);
      await handle.chmod(0o600);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return { ok: false, reason: `${args.path} could not be opened for appending: ${detail}` };
    }

    return { ok: true, ledger: new SpendLedger(handle, kept, now) };
  }

  /** What `policySigner` calls before every evaluation. */
  state(): LedgerState {
    return { nowMs: this.#now(), spend: [...this.#entries] };
  }

  async record(entries: readonly LedgerEntry[]): Promise<void> {
    if (entries.length === 0) return;
    for (const entry of entries) this.#entries.push(entry);
    await this.#handle.write(entries.map((e) => JSON.stringify(e)).join('\n') + '\n');
    await this.#handle.sync();
  }

  async close(): Promise<void> {
    await this.#handle.close();
  }
}
