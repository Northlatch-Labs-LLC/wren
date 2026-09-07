// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The multisig document and the wrap: the purse signs AS the multisig address, and the signature it
 * returns is one the multisig public key itself accepts.
 */

import { describe, expect, it } from 'vitest';
import { symlink, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { MultiSigPublicKey } from '@mysten/sui/multisig';
import { MAX_DOCUMENT_BYTES, loadMultisigDoc, wrapAsMultisig, type MultisigDoc } from '../src/multisig-file.js';
import { signerFor, temporaryDirectory, throwawayKeypair } from './helpers.js';

function docFor(hot: Ed25519Keypair, brake: Ed25519Keypair, overrides: Partial<MultisigDoc> = {}): MultisigDoc {
  return {
    version: 1,
    threshold: 1,
    members: [
      { name: 'hot', publicKey: hot.getPublicKey().toSuiPublicKey(), weight: 1 },
      { name: 'brake', publicKey: brake.getPublicKey().toSuiPublicKey(), weight: 1 },
    ],
    ...overrides,
  };
}

async function written(doc: unknown, name = 'heron-multisig.json'): Promise<string> {
  const dir = await temporaryDirectory('heron-multisig-');
  const path = join(dir, name);
  await writeFile(path, typeof doc === 'string' ? doc : JSON.stringify(doc, null, 2), 'utf8');
  return path;
}

describe('the document', () => {
  it('loads the two-member shape', async () => {
    const path = await written(docFor(throwawayKeypair(), throwawayKeypair()));
    const loaded = await loadMultisigDoc(path);
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error('unreachable');
    expect(loaded.value.doc.members.map((m) => m.name)).toEqual(['hot', 'brake']);
  });

  it('refuses an unrecognised field rather than ignoring it', async () => {
    const path = await written({ ...docFor(throwawayKeypair(), throwawayKeypair()), reload: true });
    const loaded = await loadMultisigDoc(path);
    expect(loaded.ok).toBe(false);
    if (loaded.ok) throw new Error('unreachable');
    expect(loaded.refused.reason).toContain('unrecognised field is refused');
  });

  it('refuses a threshold of zero, a weight of zero, and a key that is not a key', async () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    for (const bad of [
      docFor(hot, brake, { threshold: 0 }),
      { ...docFor(hot, brake), members: [{ name: 'hot', publicKey: hot.getPublicKey().toSuiPublicKey(), weight: 0 }] },
      { ...docFor(hot, brake), members: [{ name: 'hot', publicKey: 'not-a-key', weight: 1 }] },
    ]) {
      const loaded = await loadMultisigDoc(await written(bad));
      expect(loaded.ok).toBe(false);
    }
  });

  it('refuses a member listed twice and a name used twice', async () => {
    const hot = throwawayKeypair();
    const pub = hot.getPublicKey().toSuiPublicKey();
    const twice = await loadMultisigDoc(
      await written({ version: 1, threshold: 1, members: [{ name: 'a', publicKey: pub, weight: 1 }, { name: 'b', publicKey: pub, weight: 1 }] }),
    );
    expect(twice.ok).toBe(false);
    if (twice.ok) throw new Error('unreachable');
    expect(twice.refused.reason).toContain('one public key twice');
    const sameName = await loadMultisigDoc(
      await written({
        version: 1,
        threshold: 1,
        members: [
          { name: 'a', publicKey: pub, weight: 1 },
          { name: 'a', publicKey: throwawayKeypair().getPublicKey().toSuiPublicKey(), weight: 1 },
        ],
      }),
    );
    expect(sameName.ok).toBe(false);
  });

  it('refuses a file that is not JSON without quoting its bytes, and a path that is not there, naming the path', async () => {
    const prefix = 'suipriv' + 'key1';
    const notJson = await loadMultisigDoc(await written(`${prefix}notreallyakey`));
    expect(notJson.ok).toBe(false);
    if (notJson.ok) throw new Error('unreachable');
    expect(notJson.refused.reason).not.toContain(prefix);
    expect(notJson.refused.reason).toContain('deliberately not shown');
    const missing = await loadMultisigDoc('/nonexistent/heron-multisig.json');
    expect(missing.ok).toBe(false);
    if (missing.ok) throw new Error('unreachable');
    expect(missing.refused.reason).toContain('/nonexistent/heron-multisig.json');
  });
});

describe('the document, hardened', () => {
  it('refuses a symlink rather than following it, and a document over the size cap unread', async () => {
    const hot = throwawayKeypair();
    const real = await written(docFor(hot, throwawayKeypair()));
    const link = join(dirname(real), 'linked.json');
    await symlink(real, link);
    const viaLink = await loadMultisigDoc(link);
    expect(viaLink.ok).toBe(false);
    if (viaLink.ok) throw new Error('unreachable');
    expect(viaLink.refused.reason).toContain('symbolic link');
    const big = await written(`${JSON.stringify(docFor(hot, throwawayKeypair()))}${' '.repeat(MAX_DOCUMENT_BYTES)}`);
    const oversized = await loadMultisigDoc(big);
    expect(oversized.ok).toBe(false);
    if (oversized.ok) throw new Error('unreachable');
    expect(oversized.refused.reason).toContain('Refused unread');
  });

  it('refuses a member name that could carry a separator into the journal, and bounds weight and threshold to what Sui encodes', async () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    const badName = docFor(hot, brake);
    const renamed = { ...badName, members: [{ ...badName.members[0]!, name: 'hot\nforged line' }, badName.members[1]!] };
    expect((await loadMultisigDoc(await written(renamed))).ok).toBe(false);
    const heavy = { ...docFor(hot, brake), members: [{ ...docFor(hot, brake).members[0]!, weight: 256 }, docFor(hot, brake).members[1]!] };
    expect((await loadMultisigDoc(await written(heavy))).ok).toBe(false);
    expect((await loadMultisigDoc(await written(docFor(hot, brake, { threshold: 65536 })))).ok).toBe(false);
    // The bounds' inside edge still loads.
    expect((await loadMultisigDoc(await written(docFor(hot, brake, { threshold: 2 })))).ok).toBe(true);
  });
});

describe('the wrap', () => {
  it('signs as the multisig address, and the signature verifies against the multisig public key', async () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    const doc = docFor(hot, brake);
    const wrapped = wrapAsMultisig(doc, signerFor(hot));
    expect(wrapped.ok).toBe(true);
    if (!wrapped.ok) throw new Error('unreachable');

    // The source of truth for the address: the SDK's own derivation over the same members.
    const expected = MultiSigPublicKey.fromPublicKeys({
      threshold: 1,
      publicKeys: [
        { publicKey: hot.getPublicKey(), weight: 1 },
        { publicKey: brake.getPublicKey(), weight: 1 },
      ],
    });
    expect(wrapped.value.signer.address).toBe(expected.toSuiAddress());
    expect(wrapped.value.signer.address).not.toBe(hot.toSuiAddress());
    expect(wrapped.value.signer.scheme).toBe('multisig');
    expect(wrapped.value.memberName).toBe('hot');
    expect(wrapped.value.threshold).toBe(1);
    expect(wrapped.value.memberCount).toBe(2);

    const bytes = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const signature = await wrapped.value.signer.signTransaction(bytes);
    expect(signature.ok).toBe(true);
    if (!signature.ok) throw new Error('unreachable');
    expect(await expected.verifyTransaction(bytes, signature.value)).toBe(true);
    // And it is a multisig signature, not the hot key's bare one.
    expect(await hot.getPublicKey().verifyTransaction(bytes, signature.value).catch(() => false)).toBe(false);
  });

  it('refuses a hot key that is not a member, at start rather than at signing time', () => {
    const doc = docFor(throwawayKeypair(), throwawayKeypair());
    const wrapped = wrapAsMultisig(doc, signerFor(throwawayKeypair()));
    expect(wrapped.ok).toBe(false);
    if (wrapped.ok) throw new Error('unreachable');
    expect(wrapped.refused.reason).toContain('is not a member of this multisig');
  });

  it('refuses a threshold the hot key alone cannot reach, before any node sees a signature', async () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    const wrapped = wrapAsMultisig(docFor(hot, brake, { threshold: 2 }), signerFor(hot));
    // Construction passes (the members' total weight reaches 2); signing is where the hot key alone
    // falls short, and the signer package refuses there with the missing weight named.
    expect(wrapped.ok).toBe(true);
    if (!wrapped.ok) throw new Error('unreachable');
    const signature = await wrapped.value.signer.signTransaction(new Uint8Array([9]));
    expect(signature.ok).toBe(false);
    if (signature.ok) throw new Error('unreachable');
    expect(signature.failure.detail).toContain('1 of the 2 weight required');
  });

  it('a member swapped or a member added is a different address, as much as a different threshold', () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    const base = wrapAsMultisig(docFor(hot, brake), signerFor(hot));
    const swapped = wrapAsMultisig(docFor(hot, throwawayKeypair()), signerFor(hot));
    const added = wrapAsMultisig(
      { ...docFor(hot, brake), members: [...docFor(hot, brake).members, { name: 'third', publicKey: throwawayKeypair().getPublicKey().toSuiPublicKey(), weight: 1 }] },
      signerFor(hot),
    );
    if (!base.ok || !swapped.ok || !added.ok) throw new Error('unreachable');
    expect(swapped.value.signer.address).not.toBe(base.value.signer.address);
    expect(added.value.signer.address).not.toBe(base.value.signer.address);
  });

  it('a different threshold is a different address', () => {
    const hot = throwawayKeypair();
    const brake = throwawayKeypair();
    const one = wrapAsMultisig(docFor(hot, brake, { threshold: 1 }), signerFor(hot));
    const two = wrapAsMultisig(docFor(hot, brake, { threshold: 2 }), signerFor(hot));
    if (!one.ok || !two.ok) throw new Error('unreachable');
    expect(one.value.signer.address).not.toBe(two.value.signer.address);
  });
});
