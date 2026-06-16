/**
 * @attestor/anchor — independent external anchoring for the Attestor spine.
 *
 * Anchors each signed Merkle checkpoint root to an RFC 3161 Trusted Timestamp
 * Authority, so the evidence log becomes verifiable by a third party who does
 * not trust the operator. Strictly additive: it consumes the spine's existing
 * checkpoint output and reuses the spine's exported verify/Merkle functions; it
 * never modifies the spine or gateway core.
 */
export {
  buildTimeStampRequest,
  parseTimeStampResponse,
  verifyTimeStampToken,
  pemToDer,
  PKI_STATUS_GRANTED,
  PKI_STATUS_GRANTED_WITH_MODS,
  type TimeStampResponse,
  type TokenVerification,
} from './rfc3161.js';
export { ensureCryptoEngine } from './crypto-engine.js';
export {
  TsaClient,
  httpTransport,
  FREETSA,
  DIGICERT_TSA,
  SECTIGO_TSA,
  type TsaConfig,
  type TsaTransport,
} from './tsa-client.js';
export {
  AnchorStore,
  type AnchorReceipt,
  type AnchorStatus,
} from './anchor-store.js';
export { AnchorService, type AnchorLag } from './anchor-service.js';
export {
  exportBundle,
  writeBundle,
  readBundle,
  type AnchoredBundle,
  type BundleAnchor,
} from './bundle.js';
export {
  verifyAnchoredBundle,
  type AnchoredVerification,
  type AnchorCheck,
  type InclusionCheck,
} from './verify-bundle.js';
