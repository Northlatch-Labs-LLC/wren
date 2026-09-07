#!/usr/bin/env -S npx tsx
// Built-by: @projectx.sui
/**
 * The brake sweep, and its drill: move SUI out of Heron's address with the brake key alone.
 *
 * Two commands, run minutes apart, by two different hands:
 *
 *   prepare --multisig <doc> --chain <doc> --to <address> --amount-mist <n> --out <file>
 *     The desk's half. Derives Heron's address from the multisig document, builds one transfer of
 *     the amount from Heron's address balance to the recipient, simulates it against the node,
 *     and writes the transaction bytes (base64) to the file. No key is read. It prints the
 *     sender, the recipient, the amount, the simulated gas, the epochs the bytes stay valid for,
 *     and the file's sha256.
 *
 *   send --multisig <doc> --chain <doc> --to <address> --amount-mist <n> --bytes <file> [--dry-run]
 *     The operator's half, in a terminal. Reads the bytes back and refuses them unless they are
 *     exactly that sweep (`inspectSweep`); asks for the brake key at a hidden prompt on the
 *     terminal, and nowhere else: not argv, not the environment, not a file; refuses a key that
 *     is not the brake member; re-simulates; signs; wraps the signature in the multisig envelope;
 *     verifies it; sends it; waits; prints the digest and the effects' status. With --dry-run it
 *     stops after the verified envelope and sends nothing.
 *
 * The key exists in this process's memory from the prompt to the exit and is written nowhere.
 * That is the bound this tool offers and the one it claims; a hardware signer would be stronger.
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { createClient, type ProjectXSocialConfig } from '@projectx-social/sdk';
import { fromBase64, toBase64 } from '@mysten/sui/utils';
import { loadChainConfig } from '../src/chain.js';
import { refuseKeyInProcessSurface } from '../src/key.js';
import { loadMultisigDoc } from '../src/multisig-file.js';
import { brakeKeypairFrom, buildSweep, inspectSweep, multisigPublicKeyOf, signAsMultisig, type ValidDuring } from '../src/sweep.js';

const GAS_BUDGET = 5_000_000n;

interface Args {
  readonly mode: 'prepare' | 'send';
  readonly multisig: string;
  readonly chain: string;
  readonly to: string;
  readonly amountMist: bigint;
  readonly out: string | null;
  readonly bytes: string | null;
  readonly dryRun: boolean;
}

function parseArgs(argv: readonly string[]): Args | string {
  const mode = argv[0];
  if (mode !== 'prepare' && mode !== 'send') return 'the first word is prepare or send.';
  const map = new Map<string, string>();
  let dryRun = false;
  for (let i = 1; i < argv.length; i += 1) {
    const flag = argv[i]!;
    if (flag === '--dry-run') { dryRun = true; continue; }
    if (!['--multisig', '--chain', '--to', '--amount-mist', '--out', '--bytes'].includes(flag)) return `${flag} is not a flag this takes.`;
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) return `${flag} needs a value.`;
    map.set(flag, value);
    i += 1;
  }
  for (const required of ['--multisig', '--chain', '--to', '--amount-mist']) {
    if (!map.has(required)) return `${required} is required.`;
  }
  if (mode === 'prepare' && !map.has('--out')) return 'prepare needs --out <file>.';
  if (mode === 'send' && !map.has('--bytes')) return 'send needs --bytes <file>.';
  const to = map.get('--to')!;
  if (!/^0x[0-9a-f]{64}$/.test(to)) return '--to is not a lower-case full Sui address.';
  const amountText = map.get('--amount-mist')!;
  if (!/^[1-9][0-9]{0,18}$/.test(amountText)) return '--amount-mist is a positive integer in MIST.';
  return {
    mode,
    multisig: map.get('--multisig')!,
    chain: map.get('--chain')!,
    to,
    amountMist: BigInt(amountText),
    out: map.get('--out') ?? null,
    bytes: map.get('--bytes') ?? null,
    dryRun,
  };
}

function say(line: string): void {
  process.stderr.write(`brake-sweep: ${line}\n`);
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

/*
  The three control characters the prompt reacts to, by code so the source stays printable:
  end-of-text (Ctrl-C), end-of-transmission (Ctrl-D), and delete, which a Mac's backspace sends.
*/
const CTRL_C = String.fromCharCode(3);
const CTRL_D = String.fromCharCode(4);
const DEL = String.fromCharCode(127);

/**
 * One line from the terminal with echo off. Refuses when stdin is not a terminal: a pipe or a
 * file would be a second place the key had been, and the point of the prompt is that there is
 * none. Raw mode so a paste arrives whole and nothing is echoed; Ctrl-C and Ctrl-D end the
 * prompt without a key.
 */
async function hiddenLine(prompt: string): Promise<string | null> {
  if (!process.stdin.isTTY) return null;
  process.stderr.write(prompt);
  const stdin = process.stdin;
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding('utf8');
  return new Promise((resolve) => {
    let line = '';
    const finish = (value: string | null): void => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      process.stderr.write('\n');
      resolve(value);
    };
    const onData = (chunk: string): void => {
      for (const ch of chunk) {
        if (ch === CTRL_C || ch === CTRL_D) { finish(null); return; }
        if (ch === '\r' || ch === '\n') { finish(line); return; }
        if (ch === DEL || ch === '\b') { line = line.slice(0, -1); continue; }
        line += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function main(): Promise<number> {
  const parsed = parseArgs(process.argv.slice(2));
  if (typeof parsed === 'string') {
    say(parsed);
    say('usage: brake-sweep prepare --multisig <doc> --chain <doc> --to <address> --amount-mist <n> --out <file>');
    say('       brake-sweep send    --multisig <doc> --chain <doc> --to <address> --amount-mist <n> --bytes <file> [--dry-run]');
    return 1;
  }
  const args = parsed;

  const surface = refuseKeyInProcessSurface({ argv: process.argv, env: process.env });
  if (!surface.ok) { say(surface.refused.reason); return 1; }

  const chain = await loadChainConfig(args.chain);
  if (!chain.ok) { say(chain.refused.reason); return 1; }
  const config = chain.value as ProjectXSocialConfig;
  const doc = await loadMultisigDoc(args.multisig);
  if (!doc.ok) { say(doc.refused.reason); return 1; }
  const sender = multisigPublicKeyOf(doc.value.doc).toSuiAddress();
  const shape = { sender, recipient: args.to, amountMist: args.amountMist };
  say(`Heron's address ${sender} (${String(doc.value.doc.threshold)}-of-${String(doc.value.doc.members.length)}) on ${config.network}`);
  say(`sweep ${String(args.amountMist)} MIST to ${args.to}`);

  const client = createClient(config);
  const simulate = async (bytes: Uint8Array): Promise<boolean> => {
    const simulated = await client.core.simulateTransaction({ transaction: bytes, include: { effects: true } });
    if (simulated.$kind !== 'Transaction') {
      say(`the simulation did not produce a transaction: ${JSON.stringify(simulated).slice(0, 400)}`);
      return false;
    }
    const status = simulated.Transaction.effects.status;
    if (!status.success) {
      say(`the simulation failed: ${JSON.stringify(status.error)}`);
      return false;
    }
    const gas = simulated.Transaction.effects.gasUsed;
    say(`simulated clean; gas computation ${gas.computationCost} storage ${gas.storageCost} rebate ${gas.storageRebate}`);
    return true;
  };

  if (args.mode === 'prepare') {
    const [{ systemState }, { chainIdentifier }, { referenceGasPrice }] = await Promise.all([
      client.core.getCurrentSystemState(),
      client.core.getChainIdentifier(),
      client.core.getReferenceGasPrice(),
    ]);
    const epoch = BigInt(systemState.epoch);
    const expiration: ValidDuring = {
      ValidDuring: { minEpoch: String(epoch), maxEpoch: String(epoch + 1n), minTimestamp: null, maxTimestamp: null, chain: chainIdentifier, nonce: (Math.random() * 4294967296) >>> 0 },
    };
    const built = await buildSweep({ ...shape, gasBudget: GAS_BUDGET, gasPrice: BigInt(referenceGasPrice), expiration });
    if (!built.ok) { say(built.refused.reason); return 1; }
    const read = inspectSweep(built.value, shape);
    if (!read.ok) { say(`the bytes just built do not read back as the sweep: ${read.refused.reason}`); return 1; }
    if (!(await simulate(built.value))) return 1;
    writeFileSync(args.out!, `${toBase64(built.value)}\n`, { mode: 0o600 });
    say(`valid during epochs ${String(epoch)} to ${String(epoch + 1n)}; bytes ${String(built.value.length)}, sha256 ${sha256(built.value)}`);
    say(`written to ${args.out!}; no key was read`);
    process.stdout.write(`${JSON.stringify({ sender, recipient: args.to, amountMist: String(args.amountMist), bytesFile: args.out, sha256: sha256(built.value), minEpoch: String(epoch), maxEpoch: String(epoch + 1n) }, null, 2)}\n`);
    return 0;
  }

  // --- send -----------------------------------------------------------------------------------
  let bytes: Uint8Array;
  try {
    bytes = fromBase64(readFileSync(args.bytes!, 'utf8').trim());
  } catch (error) {
    say(`the bytes file could not be read: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
  const read = inspectSweep(bytes, shape);
  if (!read.ok) { say(read.refused.reason); return 1; }
  say(`bytes ${String(bytes.length)}, sha256 ${sha256(bytes)}, valid during epochs ${read.value.expiration.ValidDuring.minEpoch} to ${read.value.expiration.ValidDuring.maxEpoch}, gas budget ${String(read.value.gasBudget)}`);
  const { systemState } = await client.core.getCurrentSystemState();
  if (BigInt(systemState.epoch) > BigInt(read.value.expiration.ValidDuring.maxEpoch)) {
    say(`the bytes expired: the chain is at epoch ${systemState.epoch}. Run prepare again.`);
    return 1;
  }
  if (!(await simulate(bytes))) return 1;

  const secret = await hiddenLine('brake-sweep: paste the brake key and press return (nothing is shown): ');
  if (secret === null) { say('no key was entered on a terminal; nothing was signed.'); return 1; }
  const brake = brakeKeypairFrom(secret, doc.value.doc);
  if (!brake.ok) { say(brake.refused.reason); return 1; }
  say(`the key entered is the brake (${brake.value.getPublicKey().toSuiAddress()})`);
  const envelope = await signAsMultisig(bytes, brake.value, doc.value.doc);
  if (!envelope.ok) { say(envelope.refused.reason); return 1; }
  say('multisig envelope built and verified against the multisig public key');
  if (args.dryRun) {
    say('--dry-run: not sent');
    return 0;
  }
  const executed = await client.core.executeTransaction({ transaction: bytes, signatures: [envelope.value], include: { effects: true } });
  if (executed.$kind !== 'Transaction') {
    say(`the node did not accept the transaction: ${JSON.stringify(executed).slice(0, 400)}`);
    return 1;
  }
  const digest = executed.Transaction.digest;
  await client.core.waitForTransaction({ digest });
  const effects = executed.Transaction.effects;
  if (!effects.status.success) {
    say(`executed ${digest} but the effects report failure: ${JSON.stringify(effects.status.error)}`);
    return 1;
  }
  say(`executed ${digest}; status success; gas computation ${effects.gasUsed.computationCost} storage ${effects.gasUsed.storageCost} rebate ${effects.gasUsed.storageRebate}`);
  process.stdout.write(`${JSON.stringify({ digest, sender, recipient: args.to, amountMist: String(args.amountMist) }, null, 2)}\n`);
  return 0;
}

main().then((code) => process.exit(code), (error) => { say(String(error instanceof Error ? error.message : error)); process.exit(1); });
