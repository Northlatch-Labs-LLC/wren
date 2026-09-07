// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * Which deployment this purse signs against.
 *
 * Read from a file named on the command line, not from the environment. The values are public —
 * a package id and a fullnode URL are on chain and on the website — so this is not about secrecy.
 * It is about the environment being the wrong place for anything the purse depends on: the key
 * loader refuses to start if a private key is found in the environment, and a process that reads
 * *some* of its configuration from there invites the next person to put the key there too.
 *
 * The file is validated rather than trusted. A `latestPackageId` that is one character short would
 * otherwise produce a move call against an address that does not exist and a refusal from the
 * node, three steps later and pointing at the wrong thing.
 */

import { readFile } from 'node:fs/promises';
import { z } from 'zod';
import { allow, refuse, type Outcome } from './outcome.js';

const suiId = z.string().regex(/^0x[0-9a-fA-F]{1,64}$/, 'not a Sui object id');

export const chainConfigSchema = z.strictObject({
  network: z.enum(['mainnet', 'testnet', 'devnet', 'localnet']),
  grpcUrl: z.string().url(),
  packageId: suiId,
  latestPackageId: suiId,
  platformId: suiId,
  registryId: suiId,
});

/**
 * Structurally the SDK's `ProjectXSocialConfig`. Declared here rather than imported so that the
 * validation and the type come from one place; assignability to the SDK's interface is asserted by
 * the builder that consumes it, which takes the SDK type.
 */
export type ChainConfig = z.infer<typeof chainConfigSchema>;

export async function loadChainConfig(path: string): Promise<Outcome<ChainConfig>> {
  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return refuse('request-malformed', `the chain configuration at ${path} could not be read: ${detail}`);
  }

  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return refuse('request-malformed', `the chain configuration at ${path} is not valid JSON.`);
  }

  const parsed = chainConfigSchema.safeParse(value);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`);
    return refuse(
      'request-malformed',
      `the chain configuration at ${path} is not a deployment: ${problems.join('; ')}.`,
    );
  }
  return allow(parsed.data);
}
