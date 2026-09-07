// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * Phase two, and the one property the whole state sink exists for: it is written on every path.
 *
 * A sink that only records success cannot detect failure. So there are four outcomes and a test for
 * each, and two of the four are the ones that would be missing from a naive implementation — a
 * refusal, and an exception thrown from the submit.
 */

import { describe, expect, it } from 'vitest';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { runPhaseTwo, type AskPort, type SubmitPort } from '../src/beat.js';
import { STATE_FILE, type BeatState } from '../src/state.js';
import { priceIntentFor, temporaryDirectory } from './helpers.js';

const BEAT_ID = '20260905T120000Z';

async function stage(intent: unknown | undefined): Promise<{ runs: string; state: string }> {
  const dir = await temporaryDirectory();
  const runs = join(dir, 'runs');
  const state = join(dir, 'state');
  if (intent !== undefined) {
    await mkdir(join(runs, BEAT_ID), { recursive: true });
    await writeFile(join(runs, BEAT_ID, 'intent.json'), JSON.stringify(intent), 'utf8');
  }
  return { runs, state };
}

async function readState(stateDir: string): Promise<BeatState> {
  return JSON.parse(await readFile(join(stateDir, STATE_FILE), 'utf8')) as BeatState;
}

const signingPurse: AskPort = {
  ask: async () => ({
    ok: true,
    value: { ok: true, digest: 'DiGeSt', txBytesB64: 'AAAA', signature: 'AQID' },
  }),
};

const refusingPurse: AskPort = {
  ask: async () => ({
    ok: true,
    value: {
      ok: false,
      refused: { ruleId: 'object-input', reason: '[object-input] the vault is not in the allow-list.' },
    },
  }),
};

describe('the state file is written on every path', () => {
  it('signed — with the digest', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const result = await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: signingPurse });

    expect(result.state.outcome).toBe('signed');
    const written = await readState(state);
    expect(written.outcome).toBe('signed');
    expect(written.digest).toBe('DiGeSt');
    expect(written.beatId).toBe(BEAT_ID);
    // Nothing submitted: no submit port was given, which is what --dry-run does.
    expect(written.submittedDigest).toBeUndefined();
  });

  it('signed and submitted — with both digests', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const submit: SubmitPort = { submit: async () => 'OnChainDigest' };
    await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: signingPurse, submit });

    const written = await readState(state);
    expect(written.outcome).toBe('signed');
    expect(written.submittedDigest).toBe('OnChainDigest');
  });

  it('refused — with the rule id, on a forced refusal', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const result = await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: refusingPurse });

    expect(result.state.outcome).toBe('refused');
    const written = await readState(state);
    expect(written.outcome).toBe('refused');
    expect(written.ruleId).toBe('object-input');
    expect(written.error).toContain('allow-list');
  });

  it('error — on a thrown submit, keeping the digest so the operator can check the chain', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const submit: SubmitPort = {
      submit: async () => {
        throw new Error('the node hung up mid-response');
      },
    };
    const result = await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: signingPurse, submit });

    expect(result.state.outcome).toBe('error');
    const written = await readState(state);
    expect(written.outcome).toBe('error');
    expect(written.error).toContain('hung up');
    // A signature exists for this digest. Reporting only `error` would send whoever is on call
    // looking for a transaction they cannot name.
    expect(written.digest).toBe('DiGeSt');
  });

  it('error — when the ask port itself throws', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const exploding: AskPort = {
      ask: async () => {
        throw new Error('socket exploded');
      },
    };
    await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: exploding });

    const written = await readState(state);
    expect(written.outcome).toBe('error');
    expect(written.error).toContain('socket exploded');
  });

  it('no-intent — when the container wrote nothing', async () => {
    const { runs, state } = await stage(undefined);
    await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: signingPurse });

    const written = await readState(state);
    expect(written.outcome).toBe('no-intent');
    expect(written.error).toContain('intent.json');
  });

  it('error — when the purse could not be reached, which is a no-answer and not a refusal', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const unreachable: AskPort = {
      ask: async () => ({
        ok: false,
        refused: { ruleId: 'purse-unreachable', reason: 'the purse did not answer within 120000ms.' },
      }),
    };
    await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: unreachable });

    const written = await readState(state);
    expect(written.outcome).toBe('error');
    expect(written.ruleId).toBe('purse-unreachable');
  });
});

describe('the beat checks the schema before it opens the socket', () => {
  it('refuses a malformed intent locally, and never asks the purse', async () => {
    const { runs, state } = await stage({ kind: 'buy', to: `0x${'b'.repeat(64)}` });
    let asked = false;
    const watching: AskPort = {
      ask: async () => {
        asked = true;
        return { ok: true, value: { ok: true, digest: '', txBytesB64: '', signature: '' } };
      },
    };
    await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: watching });

    expect(asked).toBe(false);
    const written = await readState(state);
    expect(written.outcome).toBe('refused');
    expect(written.ruleId).toBe('intent-invalid-locally');
  });

  it('refuses an intent file that is not JSON', async () => {
    const dir = await temporaryDirectory();
    const runs = join(dir, 'runs');
    await mkdir(join(runs, BEAT_ID), { recursive: true });
    await writeFile(join(runs, BEAT_ID, 'intent.json'), '{ not json', 'utf8');

    await runPhaseTwo({ runsDir: runs, stateDir: join(dir, 'state'), beatId: BEAT_ID, ask: signingPurse });
    const written = await readState(join(dir, 'state'));
    expect(written.outcome).toBe('refused');
    expect(written.ruleId).toBe('intent-invalid-locally');
  });
});

/*
  Booking what a beat cost.

  The property that matters most here is negative: a failure to book a spend must never turn a
  beat that published into a beat that reports an error. The post is already on the network; the
  soul's books being one beat behind is smaller, recoverable, and belongs in `spendError` rather
  than in `outcome`.
*/
describe('the beat books what it actually spent', () => {
  const SOUL = {
    packageId: '0x000000000000000000000000000000000000000000000000000000000000005e',
    soul: { objectId: '0x00000000000000000000000000000000000000000000000000000000000000a1', initialSharedVersion: '7' },
  };
  const gasOf = (mist: bigint | null) => async () => ({ ok: true as const, value: mist });

  it('records the gas the submitted transaction actually cost', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const asked: unknown[] = [];
    const ask: AskPort = {
      ask: async (intent) => {
        asked.push(intent);
        return { ok: true, value: { ok: true, digest: 'DiGeSt', txBytesB64: 'AAAA', signature: 'AQID' } };
      },
    };
    const submit: SubmitPort = { submit: async () => 'OnChainDigest' };

    await runPhaseTwo({
      runsDir: runs, stateDir: state, beatId: BEAT_ID, ask, submit,
      recordSpend: { ...SOUL, gasOf: gasOf(1_348_000n) },
    });

    const written = await readState(state);
    expect(written.outcome).toBe('signed');
    expect(written.spentMist).toBe('1348000');
    expect(written.spendError).toBeUndefined();
    // The second ask is the record_spend, against this soul, for exactly that number.
    const spend = asked[1] as { kind: string; amountMist: string; soul: { objectId: string; mutable: boolean } };
    expect(spend.kind).toBe('record_spend');
    expect(spend.amountMist).toBe('1348000');
    expect(spend.soul.objectId).toBe(SOUL.soul.objectId);
    expect(spend.soul.mutable).toBe(true);
  });

  it('books nothing when nothing was submitted — a dry run spends no coin', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const asked: unknown[] = [];
    const ask: AskPort = {
      ask: async (intent) => {
        asked.push(intent);
        return { ok: true, value: { ok: true, digest: 'DiGeSt', txBytesB64: 'AAAA', signature: 'AQID' } };
      },
    };

    await runPhaseTwo({
      runsDir: runs, stateDir: state, beatId: BEAT_ID, ask,
      recordSpend: { ...SOUL, gasOf: gasOf(1_348_000n) },
    });

    expect(asked).toHaveLength(1);
    expect((await readState(state)).spentMist).toBeUndefined();
  });

  it('books nothing on a refusal, which submitted nothing either', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const submit: SubmitPort = { submit: async () => 'OnChainDigest' };

    await runPhaseTwo({
      runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: refusingPurse, submit,
      recordSpend: { ...SOUL, gasOf: gasOf(1_348_000n) },
    });

    const written = await readState(state);
    expect(written.outcome).toBe('refused');
    expect(written.spentMist).toBeUndefined();
  });

  it('books zero when the transaction was rebated more than it cost, and calls it no error', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const submit: SubmitPort = { submit: async () => 'OnChainDigest' };

    await runPhaseTwo({
      runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: signingPurse, submit,
      recordSpend: { ...SOUL, gasOf: gasOf(null) },
    });

    const written = await readState(state);
    expect(written.spentMist).toBe('0');
    expect(written.spendError).toBeUndefined();
    expect(written.outcome).toBe('signed');
  });

  it('a chain read that fails leaves the beat signed and says so in spendError', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const submit: SubmitPort = { submit: async () => 'OnChainDigest' };

    await runPhaseTwo({
      runsDir: runs, stateDir: state, beatId: BEAT_ID, ask: signingPurse, submit,
      recordSpend: {
        ...SOUL,
        gasOf: async () => ({ ok: false as const, refused: { reason: 'the node did not answer.' } }),
      },
    });

    const written = await readState(state);
    expect(written.outcome).toBe('signed');
    expect(written.submittedDigest).toBe('OnChainDigest');
    expect(written.spentMist).toBeUndefined();
    expect(written.spendError).toContain('did not answer');
  });

  it('a purse that refuses the spend leaves the beat signed and says so', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const submit: SubmitPort = { submit: async () => 'OnChainDigest' };
    let call = 0;
    const ask: AskPort = {
      ask: async () => {
        call += 1;
        return call === 1
          ? { ok: true, value: { ok: true, digest: 'DiGeSt', txBytesB64: 'AAAA', signature: 'AQID' } }
          : { ok: true, value: { ok: false, refused: { ruleId: 'move-call-target', reason: 'record_spend is not allowed.' } } };
      },
    };

    await runPhaseTwo({
      runsDir: runs, stateDir: state, beatId: BEAT_ID, ask, submit,
      recordSpend: { ...SOUL, gasOf: gasOf(1_348_000n) },
    });

    const written = await readState(state);
    expect(written.outcome).toBe('signed');
    expect(written.spendError).toContain('not allowed');
  });

  it('a deployment with no soul configured behaves exactly as before', async () => {
    const { runs, state } = await stage(priceIntentFor());
    const asked: unknown[] = [];
    const ask: AskPort = {
      ask: async (intent) => {
        asked.push(intent);
        return { ok: true, value: { ok: true, digest: 'DiGeSt', txBytesB64: 'AAAA', signature: 'AQID' } };
      },
    };
    const submit: SubmitPort = { submit: async () => 'OnChainDigest' };

    await runPhaseTwo({ runsDir: runs, stateDir: state, beatId: BEAT_ID, ask, submit });

    expect(asked).toHaveLength(1);
    const written = await readState(state);
    expect(written.outcome).toBe('signed');
    expect(written.spentMist).toBeUndefined();
    expect(written.spendError).toBeUndefined();
  });
});
