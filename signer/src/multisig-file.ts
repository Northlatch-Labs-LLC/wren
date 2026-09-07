// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The multisig document: who Heron's address is made of, so the purse signs AS that address.
 *
 * # Why a document, and why it needs no pin of its own
 *
 * Heron's address is a 1-of-2 multisig of the hot key and the brake (the Master's ruling,
 * 2026-09-05). A Sui multisig address commits its members, their weights and the threshold at
 * derivation, so the address the purse signs for is a pure function of this document and the hot
 * key. `server.ts` already refuses to start unless the signer's address equals the policy's
 * `agentAddress`, and the policy is pinned by sha256 in the unit under root. That one check now
 * proves three things at once: the members here, the threshold here, and the hot key in the
 * credential directory together derive exactly the address the pinned policy was written for.
 * Change any member, weight or threshold and the derived address moves, the check fails, and the
 * purse refuses to start — loud, before a key is held open. So this file carries no second pin.
 *
 * # What the purse does with it
 *
 * The hot key is the only member this process holds. `multiSigSigner` from the signer package
 * takes the members, the threshold and the one available signer, and returns a `Signer` whose
 * `address` is the multisig's and whose `signTransaction` produces the hot key's partial
 * signature wrapped in the multisig envelope — then verifies the result against the multisig
 * public key before returning it, so a combination that would not satisfy the threshold is refused
 * here with the missing weight named rather than rejected by a node.
 *
 * Nothing in this file is secret: two public keys and two small integers. That is why a parse
 * failure here may quote the document, where `key.ts` never may.
 */

import { lstat, readFile } from 'node:fs/promises';
import { z } from 'zod';
import { publicKeyFromSuiBytes } from '@mysten/sui/verify';
import { multiSigSigner, type Signer } from '@projectx-social/signer';
import { allow, refuse, type Outcome } from './outcome.js';

/**
 * A member's public key as Sui's flag-prefixed bytes in base64: one flag byte then the key, so an
 * Ed25519 member is 33 bytes -> 44 base64 characters starting with `A` (flag 0x00). The regex only
 * bounds the shape; `publicKeyFromSuiBytes` inside `multiSigSigner` is what actually reads it.
 */
const flaggedPublicKeyB64 = z
  .string()
  .regex(/^[A-Za-z0-9+/]{44,88}={0,2}$/, 'not a flag-prefixed public key in base64');

/*
  Sui encodes a member's weight as u8 and the threshold as u16 (MultiSigPublicKey.toSuiAddress:
  flag ‖ u16 threshold ‖ (flagged key ‖ u8 weight)*). Bounded here so an out-of-range value is a
  policy sentence at start rather than the SDK's serialisation error (Security, 2026-09-05).
*/
const weight = z.number().int().min(1).max(255);
const threshold = z.number().int().min(1).max(65535);

/*
  The one field the derived address does not commit is the label, so it is the one field that
  must be bounded by shape: lower-case, digits and hyphens, so it can never carry a newline into
  the startup line or the journal (Security, 2026-09-05).
*/
const memberName = z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'a member name is [a-z0-9-], at most 32');

/** A document is two public keys and two small integers; anything larger is not one. */
export const MAX_DOCUMENT_BYTES = 8 * 1024;

export const multisigDocSchema = z.strictObject({
  version: z.literal(1),
  threshold,
  members: z
    .array(
      z.strictObject({
        /** A label for the log line and the ledger. Never used for anything cryptographic. */
        name: memberName,
        publicKey: flaggedPublicKeyB64,
        weight,
      }),
    )
    .min(1)
    .max(10),
});

export type MultisigDoc = z.infer<typeof multisigDocSchema>;

export interface LoadedMultisig {
  readonly doc: MultisigDoc;
  readonly path: string;
}

export async function loadMultisigDoc(path: string): Promise<Outcome<LoadedMultisig>> {
  /*
    The path is the operator's, not the content's. A symlink at it could point the purse at the
    decrypted credential, and a parse failure that quoted the bytes would then print the start of
    a key. So: no symlink, a size cap, and a refusal that names the path and never the bytes
    (Security's second finding, 2026-09-05). The same two refusals key.ts makes at its own door.
  */
  let info: Awaited<ReturnType<typeof lstat>>;
  try {
    info = await lstat(path);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return refuse('request-malformed', `the multisig document ${path} could not be read: ${detail}`);
  }
  if (info.isSymbolicLink()) {
    return refuse(
      'request-malformed',
      `${path} is a symbolic link. The purse never follows one to a document it will parse: a ` +
        `link is a way to make it read, and quote, a file that is not this document.`,
    );
  }
  if (!info.isFile()) {
    return refuse('request-malformed', `${path} is not a regular file.`);
  }
  if (info.size > MAX_DOCUMENT_BYTES) {
    return refuse(
      'request-malformed',
      `the multisig document ${path} is ${String(info.size)} bytes; a members document is under ` +
        `${String(MAX_DOCUMENT_BYTES)}. Refused unread.`,
    );
  }

  let text: string;
  try {
    text = await readFile(path, 'utf8');
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return refuse('request-malformed', `the multisig document ${path} could not be read: ${detail}`);
  }

  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    // The parser's message quotes the offending bytes. Not repeated: see the header of this function.
    return refuse('request-malformed', `the multisig document ${path} is not JSON. Its bytes are deliberately not shown.`);
  }

  const parsed = multisigDocSchema.safeParse(json);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `${issue.path.map(String).join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    return refuse(
      'request-malformed',
      `the multisig document ${path} does not have the shape this purse takes: ${issues}. It is ` +
        `{ version: 1, threshold, members: [{ name, publicKey, weight }] } and nothing else; an ` +
        `unrecognised field is refused rather than ignored.`,
    );
  }

  /*
    Duplicates are judged on the decoded key's address, not on the base64 text: two spellings of
    one key are one member (Security's third finding, 2026-09-05). A key that does not decode is
    refused here with the member named, before multiSigSigner sees it.
  */
  const names = new Set<string>();
  const addresses = new Set<string>();
  for (const member of parsed.data.members) {
    if (names.has(member.name)) {
      return refuse('request-malformed', `the multisig document ${path} names the member "${member.name}" twice.`);
    }
    let address: string;
    try {
      address = publicKeyFromSuiBytes(member.publicKey).toSuiAddress();
    } catch {
      return refuse(
        'request-malformed',
        `the multisig document ${path}: member "${member.name}" does not carry a public key this ` +
          `purse can read (flag-prefixed Sui bytes in base64).`,
      );
    }
    if (addresses.has(address)) {
      return refuse(
        'request-malformed',
        `the multisig document ${path} lists one public key twice (member "${member.name}"). A ` +
          `member counted twice is a weight nobody meant to grant.`,
      );
    }
    names.add(member.name);
    addresses.add(address);
  }

  return allow({ doc: parsed.data, path });
}

export interface MultisigWrapped {
  /** Signs as the multisig address; the hot key is the one member it holds. */
  readonly signer: Signer;
  /** The member the hot key is, by the document's own label. */
  readonly memberName: string;
  readonly memberCount: number;
  readonly threshold: number;
}

/**
 * Wrap the hot key as the multisig's one available member.
 *
 * Every failure is a configuration fact and comes back as a refusal with the sentence the signer
 * package wrote for it: a hot key that is not a member, a threshold the members cannot reach, a
 * member key that does not parse.
 */
export function wrapAsMultisig(doc: MultisigDoc, hot: Signer): Outcome<MultisigWrapped> {
  const wrapped = multiSigSigner({
    threshold: doc.threshold,
    members: doc.members.map((member) => ({ publicKey: member.publicKey, weight: member.weight })),
    available: [hot],
  });
  if (!wrapped.ok) {
    return refuse(
      'request-malformed',
      `the hot key cannot sign as this multisig: ${wrapped.failure.detail} The purse will not ` +
        `start; nothing was bound.`,
    );
  }

  /*
    Which member is the hot key. `multiSigSigner` has already refused a non-member, so exactly one
    entry matches; the name is for the startup line and the ledger, nothing more.
  */
  let memberName = '';
  for (const member of doc.members) {
    const one = multiSigSigner({ threshold: 1, members: [{ publicKey: member.publicKey, weight: 1 }], available: [hot] });
    if (one.ok) {
      memberName = member.name;
      break;
    }
  }

  return allow({
    signer: wrapped.value,
    memberName,
    memberCount: doc.members.length,
    threshold: doc.threshold,
  });
}
