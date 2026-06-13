import {
  buildTimeStampRequest,
  parseTimeStampResponse,
  PKI_STATUS_GRANTED,
  PKI_STATUS_GRANTED_WITH_MODS,
} from './rfc3161.js';

/** A configured RFC 3161 Trusted Timestamp Authority. */
export interface TsaConfig {
  /** HTTP(S) endpoint that accepts a TimeStampReq (application/timestamp-query). */
  readonly url: string;
  /** Human-friendly name recorded on receipts. */
  readonly name: string;
}

/**
 * freetsa.org — a free, public RFC 3161 TSA that (importantly) publishes its CA
 * and TSA certificates, so anchored tokens can be verified OFFLINE by a third
 * party. That property is what makes the exported bundle independently checkable.
 */
export const FREETSA: TsaConfig = {
  url: 'https://freetsa.org/tsr',
  name: 'freetsa.org',
};

/** Pluggable transport so tests never touch the network. */
export type TsaTransport = (
  url: string,
  body: Buffer,
) => Promise<{ status: number; body: Buffer }>;

/** Default transport: HTTP POST of the DER request via global fetch, with timeout. */
export function httpTransport(timeoutMs = 10_000): TsaTransport {
  return async (url, body) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/timestamp-query',
          accept: 'application/timestamp-reply',
        },
        body: new Uint8Array(body),
        signal: controller.signal,
      });
      const buf = Buffer.from(await response.arrayBuffer());
      return { status: response.status, body: buf };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** Submits checkpoint roots to a TSA and returns the timeStampToken (DER). */
export class TsaClient {
  constructor(
    public readonly config: TsaConfig,
    private readonly transport: TsaTransport = httpTransport(),
  ) {}

  /** Timestamp a digest (e.g. a checkpoint Merkle root). Throws on any failure. */
  async stamp(digest: Buffer): Promise<Buffer> {
    const request = buildTimeStampRequest(digest, { certReq: true });
    const response = await this.transport(this.config.url, request);
    if (response.status !== 200) {
      throw new Error(`TSA returned HTTP ${response.status}`);
    }
    const parsed = parseTimeStampResponse(response.body);
    if (
      parsed.status !== PKI_STATUS_GRANTED &&
      parsed.status !== PKI_STATUS_GRANTED_WITH_MODS
    ) {
      throw new Error(`TSA rejected the request (PKIStatus ${parsed.status})`);
    }
    if (!parsed.token) {
      throw new Error('TSA response contained no timeStampToken');
    }
    return parsed.token;
  }
}
