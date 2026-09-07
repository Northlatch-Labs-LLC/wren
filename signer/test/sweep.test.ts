// Built-by: @projectx.sui
/**
 * The brake sweep: bytes built without a key, read back and checked before a key touches them,
 * signed by the brake alone into an envelope the multisig public key accepts.
 */

import { describe, expect, it } from 'vitest';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { MultiSigPublicKey } from '@mysten/sui/multisig';
import { Transaction } from '@mysten/sui/transactions';
import { publicKeyFromSuiBytes } from '@mysten/sui/verify';
import type { MultisigDoc } from '../src/multisig-file.js';
import { brakeKeypairFrom, buildSweep, inspectSweep, multisigPublicKeyOf, signAsMultisig, type ValidDuring } from '../src/sweep.js';
import { DIGEST, STRANGER, throwawayKeypair } from './helpers.js';

const TREASURY = `0x${'e7'.repeat(32)}`;
const AMOUNT = 10_000_000n;
const EXPIRATION: ValidDuring = { ValidDuring: { minEpoch: '900', maxEpoch: '901', minTimestamp: null, maxTimestamp: null, chain: DIGEST, nonce: 7 } };

function docFor(hot: Ed25519Keypair, brake: Ed25519Keypair, threshold = 1): MultisigDoc {
  return {
    version: 1,
    threshold,
    members: [
      { name: 'hot', publicKey: hot.getPublicKey().toSuiPublicKey(), weight: 1 },
      { name: 'brake', publicKey: brake.getPublicKey().toSuiPublicKey(), weight: 1 },
    ],
  };
}

async function sweepFor(doc: MultisigDoc, overrides: Partial<Parameters<typeof buildSweep>[0]> = {}) {
  const sender = multisigPublicKeyOf(doc).toSuiAddress();
  const built = await buildSweep({ sender, recipient: TREASURY, amountMist: AMOUNT, gasBudget: 5_000_000n, gasPrice: 1000n, expiration: EXPIRATION, ...overrides });
  return { sender, built };
}

describe('the bytes', () => {
  it('are sent by the multisig address, pay gas from the balance, and carry the expiration', async () => {
    const doc = docFor(throwawayKeypair(), throwawayKeypair());
    const { sender, built } = await sweepFor(doc);
    expect(built.ok).toBe(true);
    if (!built.ok) throw new Error('unreachable');
    const data = Transaction.from(built.value).getData();
    expect(data.sender).toBe(sender);
    expect(data.gasData.payment).toEqual([]);
    expect(data.expiration?.$kind).toBe('ValidDuring');
    expect(data.commands.map((c) => c.$kind)).toEqual(['MoveCall', 'TransferObjects']);
    expect(data.inputs[0]?.$kind).toBe('FundsWithdrawal');
    const read = inspectSweep(built.value, { sender, recipient: TREASURY, amountMist: AMOUNT });
    expect(read.ok).toBe(true);
    if (!read.ok) throw new Error('unreachable');
    expect(read.value.gasBudget).toBe(5_000_000n);
    expect(read.value.expiration.ValidDuring.maxEpoch).toBe('901');
  });

  it('refuse a sweep to the sender itself, a zero amount, and a short address', async () => {
    const doc = docFor(throwawayKeypair(), throwawayKeypair());
    const sender = multisigPublicKeyOf(doc).toSuiAddress();
    expect((await sweepFor(doc, { recipient: sender })).built.ok).toBe(false);
    expect((await sweepFor(doc, { amountMist: 0n })).built.ok).toBe(false);
    expect((await sweepFor(doc, { recipient: '0xe7' })).built.ok).toBe(false);
  });
});

describe('the inspection between the two halves', () => {
  it('refuses bytes whose sender, recipient or amount is not the one named', async () => {
    const doc = docFor(throwawayKeypair(), throwawayKeypair());
    const { sender, built } = await sweepFor(doc);
    if (!built.ok) throw new Error('unreachable');
    const wrongSender = inspectSweep(built.value, { sender: STRANGER, recipient: TREASURY, amountMist: AMOUNT });
    expect(wrongSender.ok).toBe(false);
    if (wrongSender.ok) throw new Error('unreachable');
    expect(wrongSender.refused.reason).toContain('not by Heron');
    const wrongRecipient = inspectSweep(built.value, { sender, recipient: STRANGER, amountMist: AMOUNT });
    expect(wrongRecipient.ok).toBe(false);
    if (wrongRecipient.ok) throw new Error('unreachable');
    expect(wrongRecipient.refused.reason).toContain(`send to ${TREASURY}`);
    const wrongAmount = inspectSweep(built.value, { sender, recipient: TREASURY, amountMist: AMOUNT + 1n });
    expect(wrongAmount.ok).toBe(false);
    if (wrongAmount.ok) throw new Error('unreachable');
    expect(wrongAmount.refused.reason).toContain(`move ${String(AMOUNT)} MIST`);
  });

  it('refuses the old shape, a split from the gas coin, which the node refuses in balance-paid mode', async () => {
    const doc = docFor(throwawayKeypair(), throwawayKeypair());
    const sender = multisigPublicKeyOf(doc).toSuiAddress();
    const tx = new Transaction();
    tx.setSender(sender);
    tx.setGasPayment([]);
    tx.setGasBudget(5_000_000n);
    tx.setGasPrice(1000n);
    tx.setExpiration(EXPIRATION);
    const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(AMOUNT)]);
    tx.transferObjects([coin!], tx.pure.address(TREASURY));
    const read = inspectSweep(await tx.build(), { sender, recipient: TREASURY, amountMist: AMOUNT });
    expect(read.ok).toBe(false);
    if (read.ok) throw new Error('unreachable');
    expect(read.refused.reason).toContain('redeem_funds');
  });

  it('refuses bytes that are not a two-command sweep, and bytes that are not a transaction', async () => {
    const doc = docFor(throwawayKeypair(), throwawayKeypair());
    const sender = multisigPublicKeyOf(doc).toSuiAddress();
    const tx = new Transaction();
    tx.setSender(sender);
    tx.setGasPayment([]);
    tx.setGasBudget(5_000_000n);
    tx.setGasPrice(1000n);
    tx.setExpiration(EXPIRATION);
    const [a, b] = tx.splitCoins(tx.gas, [tx.pure.u64(AMOUNT), tx.pure.u64(1n)]);
    tx.transferObjects([a!, b!], tx.pure.address(TREASURY));
    const bytes = await tx.build();
    const read = inspectSweep(bytes, { sender, recipient: TREASURY, amountMist: AMOUNT });
    expect(read.ok).toBe(false);
    const garbage = inspectSweep(new Uint8Array([1, 2, 3]), { sender, recipient: TREASURY, amountMist: AMOUNT });
    expect(garbage.ok).toBe(false);
  });
});

describe('the brake key', () => {
  it('is accepted when it is the brake member, and the refusals never repeat the secret', () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    const doc = docFor(hot, brake);
    const accepted = brakeKeypairFrom(`  ${brake.getSecretKey()}\n`, doc);
    expect(accepted.ok).toBe(true);
    if (!accepted.ok) throw new Error('unreachable');
    expect(accepted.value.getPublicKey().toSuiAddress()).toBe(brake.getPublicKey().toSuiAddress());

    const notBrake = brakeKeypairFrom(hot.getSecretKey(), doc);
    expect(notBrake.ok).toBe(false);
    if (notBrake.ok) throw new Error('unreachable');
    expect(notBrake.refused.reason).toContain('not the brake');
    expect(notBrake.refused.reason).not.toContain(hot.getSecretKey());

    const stranger = brakeKeypairFrom(throwawayKeypair().getSecretKey(), doc);
    expect(stranger.ok).toBe(false);

    const garbage = brakeKeypairFrom('suiprivkey1notakey', doc);
    expect(garbage.ok).toBe(false);
    if (garbage.ok) throw new Error('unreachable');
    expect(garbage.refused.reason).not.toContain('notakey');

    expect(brakeKeypairFrom('', doc).ok).toBe(false);
  });
});

describe('the envelope', () => {
  it('signed by the brake alone is one the multisig public key accepts, at threshold 1', async () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    const doc = docFor(hot, brake);
    const { built } = await sweepFor(doc);
    if (!built.ok) throw new Error('unreachable');
    const signed = await signAsMultisig(built.value, brake, doc);
    expect(signed.ok).toBe(true);
    if (!signed.ok) throw new Error('unreachable');
    const multisig = MultiSigPublicKey.fromPublicKeys({
      threshold: 1,
      publicKeys: doc.members.map((m) => ({ publicKey: publicKeyFromSuiBytes(m.publicKey), weight: m.weight })),
    });
    expect(await multisig.verifyTransaction(built.value, signed.value)).toBe(true);
    // The hot key alone can no longer be the one that signed it.
    expect(await hot.getPublicKey().verifyTransaction(built.value, signed.value).catch(() => false)).toBe(false);
  });

  it('is refused at threshold 2, where one member is not enough, with the threshold named', async () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    const doc = docFor(hot, brake, 2);
    const { built } = await sweepFor(doc);
    if (!built.ok) throw new Error('unreachable');
    const signed = await signAsMultisig(built.value, brake, doc);
    expect(signed.ok).toBe(false);
    if (signed.ok) throw new Error('unreachable');
    expect(signed.refused.reason).toContain('threshold is 2');
  });

  it('is refused for a signer who is not a member', async () => {
    const doc = docFor(throwawayKeypair(), throwawayKeypair());
    const { built } = await sweepFor(doc);
    if (!built.ok) throw new Error('unreachable');
    const signed = await signAsMultisig(built.value, throwawayKeypair(), doc);
    expect(signed.ok).toBe(false);
  });
});
