// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The real server, over a real unix socket, with a throwaway key and no network.
 *
 * `purse.test.ts` proves the decision. This file proves the process around it: the order of the
 * checks at start, the socket's mode, the framing, and that a request over the wire produces the
 * same value a direct call does.
 */

import { describe, expect, it } from 'vitest';
import { chmod, readFile, stat, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { connect } from 'node:net';
import { join } from 'node:path';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { MultiSigPublicKey } from '@mysten/sui/multisig';
import { fixedGas } from '../src/build.js';
import { askPurse } from '../src/client.js';
import { MAX_REQUEST_BYTES } from '../src/protocol.js';
import { parseServerArgs, startPurse, type RunningPurse } from '../src/server.js';
import {
  CHAIN,
  DIGEST,
  GAS_COIN_ID,
  policyFor,
  priceIntentFor,
  setPriceResponse,
  stubClient,
  stubPort,
  temporaryDirectory,
} from './helpers.js';

const GAS = fixedGas({
  price: 1000n,
  payment: [{ objectId: GAS_COIN_ID, version: '1', digest: '11111111111111111111111111111111' }],
});

interface Started {
  readonly running: RunningPurse;
  readonly socketPath: string;
  readonly auditPath: string;
  readonly logged: readonly string[];
}

interface Laid {
  readonly start: () => ReturnType<typeof startPurse>;
  readonly socketPath: string;
  readonly auditPath: string;
  readonly logged: string[];
  /** The hot key's own address. */
  readonly hotAddress: string;
  /** The address the purse is expected to sign as: the multisig's when laid with one, else the hot key's. */
  readonly address: string;
  /** The multisig public key, when laid with one, for verifying what comes back over the socket. */
  readonly multisigKey: MultiSigPublicKey | null;
  /** Where the members document was written, so a test can tamper with it before start. */
  readonly multisigDocPath: string;
}

async function laid(
  overrides: {
    readonly pin?: string;
    readonly env?: Record<string, string | undefined>;
    /** Lay out a 1-of-2 multisig of the hot key and a throwaway brake, and pass --multisig. */
    readonly multisig?: boolean;
    /** Write the policy for the hot key's own address even though the purse signs as the multisig. */
    readonly policyForHot?: boolean;
    /** Name a stranger as the multisig's first member instead of the hot key. */
    readonly hotNotMember?: boolean;
    /** Write the policy for the multisig but start the purse WITHOUT --multisig. */
    readonly dropFlag?: boolean;
  } = {},
): Promise<Laid> {
  const dir = await temporaryDirectory();
  const keypair = Ed25519Keypair.generate();
  const hotAddress = keypair.toSuiAddress();

  const keyPath = join(dir, 'heron-hot');
  await writeFile(keyPath, `${keypair.getSecretKey()}\n`, { mode: 0o600 });
  await chmod(keyPath, 0o600);

  let multisigPath: string | undefined;
  let multisigKey: MultiSigPublicKey | null = null;
  if (overrides.multisig === true) {
    const brake = Ed25519Keypair.generate();
    const first = overrides.hotNotMember === true ? Ed25519Keypair.generate() : keypair;
    multisigKey = MultiSigPublicKey.fromPublicKeys({
      threshold: 1,
      publicKeys: [
        { publicKey: first.getPublicKey(), weight: 1 },
        { publicKey: brake.getPublicKey(), weight: 1 },
      ],
    });
    multisigPath = join(dir, 'heron-multisig.json');
    await writeFile(
      multisigPath,
      JSON.stringify(
        {
          version: 1,
          threshold: 1,
          members: [
            { name: 'hot', publicKey: first.getPublicKey().toSuiPublicKey(), weight: 1 },
            { name: 'brake', publicKey: brake.getPublicKey().toSuiPublicKey(), weight: 1 },
          ],
        },
        null,
        2,
      ),
      'utf8',
    );
  }
  const address = multisigKey === null ? hotAddress : multisigKey.toSuiAddress();
  const policyAddress = overrides.policyForHot === true ? hotAddress : address;
  if (overrides.dropFlag === true) multisigPath = undefined;
  const multisigDocPath = join(dir, 'heron-multisig.json');

  const policyPath = join(dir, 'heron-policy.json');
  const policyText = `${JSON.stringify(policyFor(policyAddress), null, 2)}\n`;
  await writeFile(policyPath, policyText, 'utf8');
  const policySha = createHash('sha256').update(policyText, 'utf8').digest('hex');

  const chainPath = join(dir, 'chain.json');
  await writeFile(chainPath, JSON.stringify(CHAIN), 'utf8');

  const socketPath = join(dir, 'purse.sock');
  const auditPath = join(dir, 'audit.jsonl');
  const logged: string[] = [];
  const response = setPriceResponse(address);

  return {
    socketPath,
    auditPath,
    logged,
    hotAddress,
    address,
    multisigKey,
    multisigDocPath,
    start: () =>
      startPurse({
        server: {
          socket: socketPath,
          policy: policyPath,
          policySha256: overrides.pin ?? policySha,
          chain: chainPath,
          audit: auditPath,
          spend: join(dir, 'spend.jsonl'),
          keyFile: keyPath,
          ...(multisigPath === undefined ? {} : { multisig: multisigPath }),
        },
        argv: ['node', 'server.js'],
        env: overrides.env ?? {},
        log: (line) => logged.push(line),
        recorded: { simulation: stubPort(response, address), gas: GAS, client: stubClient(response) },
      }),
  };
}

async function started(): Promise<Started> {
  const laidOut = await laid();
  const outcome = await laidOut.start();
  if (!outcome.ok) throw new Error(outcome.refused.reason);
  return {
    running: outcome.value,
    socketPath: laidOut.socketPath,
    auditPath: laidOut.auditPath,
    logged: laidOut.logged,
  };
}

describe('starting', () => {
  it('binds the socket at 0660 and reports the address and both policy hashes', async () => {
    const s = await started();
    const info = await stat(s.socketPath);
    expect(info.isSocket()).toBe(true);
    expect((info.mode & 0o777).toString(8)).toBe('660');
    expect(s.logged[0]).toContain('listening on');
    expect(s.logged[0]).toContain(s.running.purse.address);
    await s.running.stop();
  });

  it('refuses to start when the policy file does not match the pin — and binds nothing', async () => {
    const laidOut = await laid({ pin: '0'.repeat(64) });
    const outcome = await laidOut.start();

    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    expect(outcome.refused.reason).toContain('redeploy, not a reload');
    await expect(stat(laidOut.socketPath)).rejects.toThrow();
  });

  it('refuses to start when a key is in the environment — before the policy is even read', async () => {
    const prefix = 'suipriv' + 'key1';
    const laidOut = await laid({ pin: '0'.repeat(64), env: { ANYTHING: `${prefix}qq…` } });
    const outcome = await laidOut.start();

    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    // The environment complaint, not the pin complaint: the surface check runs first, so a process
    // started wrongly dies at its first instruction rather than after creating a socket.
    expect(outcome.refused.reason).toContain('ANYTHING');
    await expect(stat(laidOut.socketPath)).rejects.toThrow();
  });
});

describe('signing as the multisig', () => {
  it("starts as the multisig address, not the hot key's, and says so on the startup line", async () => {
    const laidOut = await laid({ multisig: true });
    const outcome = await laidOut.start();
    if (!outcome.ok) throw new Error(outcome.refused.reason);
    expect(outcome.value.purse.address).toBe(laidOut.address);
    expect(outcome.value.purse.address).not.toBe(laidOut.hotAddress);
    expect(laidOut.logged[0]).toContain(`for ${laidOut.address}`);
    expect(laidOut.logged[0]).toContain('multisig 1-of-2');
    expect(laidOut.logged[0]).toContain(`hot member "hot" ${laidOut.hotAddress}`);
    await outcome.value.stop();
  });

  it('answers a permitted intent with a signature the multisig public key accepts over the returned bytes', async () => {
    const laidOut = await laid({ multisig: true });
    const outcome = await laidOut.start();
    if (!outcome.ok) throw new Error(outcome.refused.reason);
    const answered = await askPurse({ socketPath: laidOut.socketPath, intent: priceIntentFor() });
    if (!answered.ok) throw new Error(`${answered.refused.ruleId}: ${answered.refused.reason}`);
    if (!answered.value.ok) throw new Error(`${answered.value.refused.ruleId}: ${answered.value.refused.reason}`);
    if (!('digest' in answered.value)) throw new Error('a transaction was expected');
    const bytes = new Uint8Array(Buffer.from(answered.value.txBytesB64, 'base64'));
    expect(await laidOut.multisigKey!.verifyTransaction(bytes, answered.value.signature)).toBe(true);
    // The audit line carries the multisig address: the ledger and the chain are about the address
    // that spends, which is the multisig's.
    const audit = await readFile(laidOut.auditPath, 'utf8');
    const last = JSON.parse(audit.trim().split('\n').at(-1)!) as { address: string; outcome: string };
    expect(last.outcome).toBe('signed');
    expect(last.address).toBe(laidOut.address);
    await outcome.value.stop();
  });

  it("refuses to start when the policy is written for the hot key's own address, and binds nothing", async () => {
    const laidOut = await laid({ multisig: true, policyForHot: true });
    const outcome = await laidOut.start();
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    expect(outcome.refused.reason).toContain(`signs as ${laidOut.address}`);
    expect(outcome.refused.reason).toContain('bounds nothing');
    await expect(stat(laidOut.socketPath)).rejects.toThrow();
  });

  it('refuses to start when the document was tampered with after the policy was pinned: a swapped brake is a different address', async () => {
    const laidOut = await laid({ multisig: true });
    const tampered = JSON.parse(await readFile(laidOut.multisigDocPath, 'utf8')) as { members: { publicKey: string }[] };
    tampered.members[1]!.publicKey = Ed25519Keypair.generate().getPublicKey().toSuiPublicKey();
    await writeFile(laidOut.multisigDocPath, JSON.stringify(tampered), 'utf8');
    const outcome = await laidOut.start();
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    expect(outcome.refused.reason).toContain('bounds nothing');
    await expect(stat(laidOut.socketPath)).rejects.toThrow();
  });

  it('refuses to start without --multisig against a policy written for the multisig: the bare-key mode fails closed', async () => {
    const laidOut = await laid({ multisig: true, dropFlag: true });
    const outcome = await laidOut.start();
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    expect(outcome.refused.reason).toContain(`signs as ${laidOut.hotAddress}`);
    expect(outcome.refused.reason).toContain('bounds nothing');
    await expect(stat(laidOut.socketPath)).rejects.toThrow();
  });

  it('refuses to start when the hot key is not a member of the document, and binds nothing', async () => {
    const laidOut = await laid({ multisig: true, hotNotMember: true });
    const outcome = await laidOut.start();
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error('unreachable');
    expect(outcome.refused.reason).toContain('is not a member of this multisig');
    await expect(stat(laidOut.socketPath)).rejects.toThrow();
  });
});

describe('over the socket', () => {
  it('signs a permitted intent and answers one JSON line', async () => {
    const s = await started();
    const answered = await askPurse({ socketPath: s.socketPath, intent: priceIntentFor() });

    if (!answered.ok) throw new Error(`${answered.refused.ruleId}: ${answered.refused.reason}`);
    expect(answered.value.ok).toBe(true);
    if (!answered.value.ok) throw new Error('unreachable');
    if (!('digest' in answered.value)) throw new Error('a transaction was expected');
    expect(answered.value.digest).toBe(DIGEST);
    expect(answered.value.txBytesB64.length).toBeGreaterThan(0);
    await s.running.stop();
  });

  it('refuses an intent kind it does not have, as a value on the wire', async () => {
    const s = await started();
    const answered = await askPurse({ socketPath: s.socketPath, intent: { kind: 'buy', amount: '1' } });

    if (!answered.ok) throw new Error(`${answered.refused.ruleId}: ${answered.refused.reason}`);
    expect(answered.value.ok).toBe(false);
    if (answered.value.ok) throw new Error('unreachable');
    expect(answered.value.refused.ruleId).toBe('intent-invalid');
    await s.running.stop();
  });

  it('chains a line for a probe that was not even JSON', async () => {
    const s = await started();
    await new Promise<void>((resolve) => {
      const socket = connect(s.socketPath, () => socket.end('give me the key\n'));
      // The `data` listener is not decoration: a socket with no consumer stays paused, never reads
      // the answer, and therefore never sees the FIN behind it — so `close` never fires and this
      // test hangs rather than failing. Attaching it is what puts the socket into flowing mode.
      socket.on('data', () => undefined);
      socket.on('close', () => resolve());
      socket.on('error', () => resolve());
    });

    const lines = (await readFile(s.auditPath, 'utf8')).trim().split('\n').filter((l) => l !== '');
    expect(lines).toHaveLength(1);
    expect(JSON.parse(lines[0]!).ruleId).toBe('request-malformed');
    await s.running.stop();
  });

  /*
    A2 from Security's review of 2026-09-05.

    `serve` answered an oversize request itself and never called the purse, so the one probe most
    likely to be somebody feeling out the socket left no line at all — in the file `audit-file.ts`
    says the purse keeps its own chain for.
  */
  it('chains a refused line for a request over the size limit', async () => {
    const s = await started();
    const oversize = `{"intent":"${'x'.repeat(MAX_REQUEST_BYTES + 1024)}"}\n`;

    const answer = await new Promise<string>((resolve) => {
      const socket = connect(s.socketPath, () => socket.write(oversize));
      let received = '';
      socket.on('data', (chunk: Buffer) => {
        received += chunk.toString('utf8');
      });
      socket.on('close', () => resolve(received));
      socket.on('error', () => resolve(received));
    });

    expect(answer).toContain('request-too-large');

    const lines = (await readFile(s.auditPath, 'utf8')).trim().split('\n').filter((l) => l !== '');
    expect(lines).toHaveLength(1);
    const line = JSON.parse(lines[0]!) as Record<string, unknown>;
    expect(line['outcome']).toBe('refused');
    expect(line['ruleId']).toBe('request-too-large');
    expect(line['intentKind']).toBe('unread');
    await s.running.stop();
  });

  it('reports a socket that is not there as a no-answer, never as a refusal', async () => {
    const answered = await askPurse({ socketPath: '/tmp/heron-purse-not-here.sock', intent: priceIntentFor() });
    expect(answered.ok).toBe(false);
    if (answered.ok) throw new Error('unreachable');
    expect(answered.refused.ruleId).toBe('purse-unreachable');
  });
});

describe('the arguments', () => {
  it('refuses an unrecognised flag rather than ignoring it', () => {
    const parsed = parseServerArgs(['--socket', '/x', '--policy-sha-256', 'abc']);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error('unreachable');
    expect(parsed.refused.reason).toContain('--policy-sha-256');
  });

  it('requires the pin', () => {
    const parsed = parseServerArgs([
      '--socket', '/x', '--policy', '/p', '--chain', '/c', '--audit', '/a', '--spend', '/s',
    ]);
    expect(parsed.ok).toBe(false);
    if (parsed.ok) throw new Error('unreachable');
    expect(parsed.refused.reason).toContain('--policy-sha256');
  });

  it('takes the full set', () => {
    const parsed = parseServerArgs([
      '--socket', '/run/heron/purse.sock',
      '--policy', '/srv/heron/policy/heron-policy.json',
      '--policy-sha256', 'a'.repeat(64),
      '--chain', '/srv/heron/chain.json',
      '--audit', '/var/lib/heron/audit/audit.jsonl',
      '--spend', '/var/lib/heron/audit/spend.jsonl',
      '--multisig', '/srv/heron/policy/heron-multisig.json',
    ]);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) throw new Error('unreachable');
    expect(parsed.value.multisig).toBe('/srv/heron/policy/heron-multisig.json');
  });
});
