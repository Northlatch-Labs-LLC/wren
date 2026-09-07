// Built-by: @projectx.sui · Co-authored-by: Kaela <kaela@projectxprotocol.dev>
/**
 * Asking the purse, over the unix socket.
 *
 * One connection, one request, one response, then the connection closes. No pipelining and no
 * keep-alive: the purse serves one agent whose beat fires every thirty minutes, so a connection
 * pool would buy nothing and would make "one request is being handled at a time" a property of the
 * server's bookkeeping rather than of the protocol.
 *
 * Every failure here is a value. The caller is the beat, and the beat's job on a failure is to
 * write `state/latest.json` and stop — not to retry against a socket that may be refusing on
 * purpose.
 */

import { connect } from 'node:net';
import { MAX_REQUEST_BYTES, type PurseResponse } from './protocol.js';
import { refuse, type Outcome } from './outcome.js';

export interface AskOptions {
  readonly socketPath: string;
  readonly intent: unknown;
  /** Milliseconds. The purse simulates against a fullnode, so this is a network timeout, not a local one. */
  readonly timeoutMs?: number;
}

export async function askPurse(options: AskOptions): Promise<Outcome<PurseResponse>> {
  const timeoutMs = options.timeoutMs ?? 120_000;

  return new Promise<Outcome<PurseResponse>>((resolve) => {
    let settled = false;
    const finish = (result: Outcome<PurseResponse>): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    const chunks: Buffer[] = [];
    let received = 0;

    const socket = connect(options.socketPath);
    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      socket.end(`${JSON.stringify({ intent: options.intent })}\n`);
    });

    socket.on('data', (chunk: Buffer) => {
      received += chunk.byteLength;
      if (received > MAX_REQUEST_BYTES) {
        finish(
          refuse(
            'purse-unreachable',
            `the purse sent more than ${String(MAX_REQUEST_BYTES)} bytes in answer to one intent. ` +
              `Nothing was submitted.`,
          ),
        );
        return;
      }
      chunks.push(chunk);
    });

    socket.on('timeout', () => {
      finish(
        refuse(
          'purse-unreachable',
          `the purse at ${options.socketPath} did not answer within ${String(timeoutMs)}ms. ` +
            `Nothing was submitted. This is a no-answer, not a refusal: the policy said nothing.`,
        ),
      );
    });

    socket.on('error', (error: Error) => {
      finish(
        refuse(
          'purse-unreachable',
          `the purse at ${options.socketPath} could not be reached: ${error.message}. Nothing was submitted.`,
        ),
      );
    });

    socket.on('close', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim();
      if (text === '') {
        finish(
          refuse('purse-unreachable', `the purse at ${options.socketPath} closed without answering.`),
        );
        return;
      }
      let value: unknown;
      try {
        value = JSON.parse(text);
      } catch {
        finish(refuse('purse-unreachable', `the purse's answer was not JSON.`));
        return;
      }
      const response = value as Partial<PurseResponse>;
      if (typeof response.ok !== 'boolean') {
        finish(refuse('purse-unreachable', `the purse's answer had no \`ok\` field.`));
        return;
      }
      finish({ ok: true, value: value as PurseResponse });
    });
  });
}
