// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * The one request this purse answers, and the two shapes it answers with.
 *
 * # One call, and no others
 *
 * `{ "intent": <typed intent> }` in, one JSON object out. There is no second request kind. There is
 * no key export, no "sign these bytes", no policy reload, no health call that reports whether a key
 * is loaded — the CISO's §2 names each of those as something the purse must never expose, and the
 * way to not expose them is for the parser to have nowhere to put them.
 *
 * An unknown key at the top level is a refusal, not a field that is ignored. That is the same
 * `.strict()` reasoning as the intent schema: a permissive envelope is how a `bytes` field reaches
 * a handler that grew support for one in a later commit.
 *
 * # The response never carries the key, and cannot
 *
 * A signature is a signature; the bytes are the bytes that were simulated and judged, base64 so
 * they survive JSON; the digest is what the node reported. There is no field on this type that
 * could hold key material, and `test/purse.test.ts` greps every response, every log line and every
 * audit line for the bech32 prefix.
 */

import { z } from 'zod';
import type { Refusal } from './outcome.js';

export const requestSchema = z.strictObject({
  intent: z.unknown(),
});

export type SignedResponse = {
  readonly ok: true;
  /** The transaction digest the simulation reported. Empty only if the node reported none. */
  readonly digest: string;
  /** The exact bytes that were simulated, evaluated and signed. Not rebuilt at any point. */
  readonly txBytesB64: string;
  readonly signature: string;
};

/** The answer to a statement intent: the text that was signed and the signature over it. */
export type StatementResponse = {
  readonly ok: true;
  readonly statement: string;
  readonly statementSha256: string;
  readonly signature: string;
  readonly address: string;
  readonly timestampMs: number;
};
export type RefusedResponse = {
  readonly ok: false;
  readonly refused: Refusal;
};

export type PurseResponse = SignedResponse | StatementResponse | RefusedResponse;

/**
 * The largest request the purse will read off a connection.
 *
 * An intent is a few hundred bytes. The cap is generous by three orders of magnitude and still
 * bounded, because the socket's peer is the beat and the beat's input came from a model: a peer
 * that streams without ever sending a newline is a memory exhaustion on a 512 MB droplet that also
 * has to hold the Docker daemon.
 */
export const MAX_REQUEST_BYTES = 256 * 1024;
