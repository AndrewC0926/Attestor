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
  /**
   * Optional HTTP headers sent with each request — the seam for commercial TSA
   * auth (API key, `Authorization: Bearer …`, or Basic). Kept generic on
   * purpose; a typed per-provider auth union is not warranted yet.
   */
  readonly headers?: Record<string, string>;
  /**
   * Optional PEM trust anchors (the TSA's CA / signing cert chain) used to
   * validate this TSA's tokens OFFLINE. They are carried into exported bundles
   * so a third party can verify without contacting the TSA. The verification
   * logic itself is unchanged — these are just the trust roots fed to it.
   */
  readonly certsPem?: readonly string[];
}

/**
 * freetsa.org — a free, public RFC 3161 TSA that (importantly) publishes its CA
 * and TSA certificates, so anchored tokens can be verified OFFLINE by a third
 * party. That property is what makes the exported bundle independently checkable.
 * This is the DEV/DEFAULT TSA (no SLA, no legal standing) — use a qualified /
 * commercial TSP in production.
 */
export const FREETSA: TsaConfig = {
  url: 'https://freetsa.org/tsr',
  name: 'freetsa.org',
};

/**
 * Documented STARTING POINTS for commercial TSAs — NOT verified-working
 * endpoints. The exact URL, required auth, and CA/cert chain differ per account
 * and change over time. VERIFY THE CURRENT ENDPOINT + CREDENTIALS WITH YOUR
 * PROVIDER (and supply `certsPem`) before relying on these in production.
 */
export const DIGICERT_TSA: TsaConfig = {
  // Public DigiCert timestamp endpoint (commonly used for code-signing); confirm
  // suitability/terms for your use case with DigiCert before relying on it.
  url: 'http://timestamp.digicert.com',
  name: 'digicert',
};

export const SECTIGO_TSA: TsaConfig = {
  // Sectigo's public timestamp endpoint; confirm endpoint + terms with Sectigo.
  url: 'http://timestamp.sectigo.com',
  name: 'sectigo',
};

/**
 * Pluggable transport so tests never touch the network. `headers` carries the
 * TSA's configured auth headers (optional; fakes may ignore it).
 */
export type TsaTransport = (
  url: string,
  body: Buffer,
  headers?: Record<string, string>,
) => Promise<{ status: number; body: Buffer }>;

/** Default transport: HTTP POST of the DER request via global fetch, with timeout. */
export function httpTransport(timeoutMs = 10_000): TsaTransport {
  return async (url, body, headers) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/timestamp-query',
          accept: 'application/timestamp-reply',
          ...(headers ?? {}),
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
    const response = await this.transport(this.config.url, request, this.config.headers);
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
