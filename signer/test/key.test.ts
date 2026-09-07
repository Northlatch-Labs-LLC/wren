// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The key comes from a file, and from nothing else.
 *
 * Every key in this file is generated in this process and written into a directory `mkdtemp` made.
 * Nothing reads `~/.sui`, nothing reads the pile, and no file outside the temp directory is opened.
 */

import { describe, expect, it } from 'vitest';
import { chmod, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { CREDENTIAL_NAME, loadHotKey, refuseKeyInProcessSurface } from '../src/key.js';
import { temporaryDirectory } from './helpers.js';

/** Written rather than pasted, so this file holds no key and matches no grep for the prefix. */
async function writeThrowawayKey(dir: string, name = 'heron-hot', mode = 0o600): Promise<{ path: string; address: string }> {
  const keypair = Ed25519Keypair.generate();
  const path = join(dir, name);
  await writeFile(path, `${keypair.getSecretKey()}\n`, { mode });
  await chmod(path, mode);
  return { path, address: keypair.toSuiAddress() };
}

describe('the file door', () => {
  it('loads from an explicit --key-file', async () => {
    const dir = await temporaryDirectory();
    const written = await writeThrowawayKey(dir);
    const loaded = await loadHotKey({ keyFile: written.path, argv: [], env: {} });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    expect(loaded.value.signer.address).toBe(written.address);
  });

  it('loads from $CREDENTIALS_DIRECTORY when no flag is given', async () => {
    const dir = await temporaryDirectory();
    const written = await writeThrowawayKey(dir, CREDENTIAL_NAME, 0o400);
    const loaded = await loadHotKey({ credentialsDirectory: dir, argv: [], env: {} });

    expect(loaded.ok).toBe(true);
    if (!loaded.ok) throw new Error(loaded.refused.reason);
    expect(loaded.value.signer.address).toBe(written.address);
  });

  it('refuses when there is neither', async () => {
    const loaded = await loadHotKey({ argv: [], env: {} });
    expect(loaded.ok).toBe(false);
    if (loaded.ok) throw new Error('unreachable');
    expect(loaded.refused.reason).toContain('--key-file');
  });
});

describe('the doors that are shut', () => {
  it('refuses to start when a key is in argv', () => {
    const prefix = 'suipriv' + 'key1';
    const verdict = refuseKeyInProcessSurface({ argv: ['node', 'server.js', `${prefix}qq…`], env: {} });
    expect(verdict.ok).toBe(false);
    if (verdict.ok) throw new Error('unreachable');
    expect(verdict.refused.reason).toContain('ps');
  });

  it('refuses to start when a key is in any environment value', () => {
    const prefix = 'suipriv' + 'key1';
    const verdict = refuseKeyInProcessSurface({ argv: [], env: { SOMETHING_ELSE: `${prefix}qq…` } });
    expect(verdict.ok).toBe(false);
    if (verdict.ok) throw new Error('unreachable');
    expect(verdict.refused.reason).toContain('SOMETHING_ELSE');
    // The value is named as leaked and is not repeated.
    expect(verdict.refused.reason).not.toContain(prefix);
  });

  it('refuses a key-shaped environment name even when it holds a path', () => {
    const verdict = refuseKeyInProcessSurface({ argv: [], env: { HERON_HOT_KEY: '/srv/heron/keys/hot' } });
    expect(verdict.ok).toBe(false);
    if (verdict.ok) throw new Error('unreachable');
    expect(verdict.refused.reason).toContain('HERON_HOT_KEY');
  });

  it('refuses a key file the group or others can read', async () => {
    const dir = await temporaryDirectory();
    const written = await writeThrowawayKey(dir, 'heron-hot', 0o640);
    const loaded = await loadHotKey({ keyFile: written.path, argv: [], env: {} });

    expect(loaded.ok).toBe(false);
    if (loaded.ok) throw new Error('unreachable');
    expect(loaded.refused.reason).toContain('0640');
  });

  it('accepts 0440 under $CREDENTIALS_DIRECTORY, the mode systemd 257 places a credential at, and refuses the same file as a --key-file', async () => {
    const dir = await temporaryDirectory();
    const written = await writeThrowawayKey(dir, CREDENTIAL_NAME, 0o440);
    const viaCredentials = await loadHotKey({ credentialsDirectory: dir, argv: [], env: {} });
    expect(viaCredentials.ok).toBe(true);
    if (!viaCredentials.ok) throw new Error(viaCredentials.refused.reason);
    expect(viaCredentials.value.signer.address).toBe(written.address);
    const asKeyFile = await loadHotKey({ keyFile: written.path, argv: [], env: {} });
    expect(asKeyFile.ok).toBe(false);
    if (asKeyFile.ok) throw new Error('unreachable');
    expect(asKeyFile.refused.reason).toContain('0440');
  });

  it('refuses a credential the group can write or others can read, even under $CREDENTIALS_DIRECTORY', async () => {
    for (const mode of [0o460, 0o444, 0o404]) {
      const dir = await temporaryDirectory();
      await writeThrowawayKey(dir, CREDENTIAL_NAME, mode);
      const loaded = await loadHotKey({ credentialsDirectory: dir, argv: [], env: {} });
      expect(loaded.ok).toBe(false);
    }
  });

  it('refuses a symlink rather than following it', async () => {
    const dir = await temporaryDirectory();
    const written = await writeThrowawayKey(dir);
    const link = join(dir, 'linked-hot');
    await symlink(written.path, link);

    const loaded = await loadHotKey({ keyFile: link, argv: [], env: {} });
    expect(loaded.ok).toBe(false);
    if (loaded.ok) throw new Error('unreachable');
    expect(loaded.refused.reason).toContain('symbolic link');
  });

  it('refuses a file that is not a key, without quoting what it read', async () => {
    const dir = await temporaryDirectory();
    const path = join(dir, 'heron-hot');
    await writeFile(path, 'this-is-not-a-key\n', { mode: 0o600 });
    await chmod(path, 0o600);

    const loaded = await loadHotKey({ keyFile: path, argv: [], env: {} });
    expect(loaded.ok).toBe(false);
    if (loaded.ok) throw new Error('unreachable');
    expect(loaded.refused.reason).not.toContain('this-is-not-a-key');
  });

  it('refuses an empty file', async () => {
    const dir = await temporaryDirectory();
    const path = join(dir, 'heron-hot');
    await writeFile(path, '', { mode: 0o600 });
    await chmod(path, 0o600);

    const loaded = await loadHotKey({ keyFile: path, argv: [], env: {} });
    expect(loaded.ok).toBe(false);
  });
});
