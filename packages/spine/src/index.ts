/**
 * @attestor/spine — the tamper-evident evidence system of record.
 *
 * Public surface for the gateway and CLI. The only write path is `Spine.append`;
 * there is intentionally no exported mutation or delete capability.
 */
export { Spine, type SpineOptions } from './spine.js';
export { verifyLog } from './verify.js';
export {
  buildCheckpoint,
  signCheckpoint,
  verifyCheckpointSignature,
  merkleRootOfRecords,
  checkpointSigningBytes,
} from './checkpoint.js';
export {
  type Signer,
  LocalKeySigner,
  Pkcs11Signer,
  type Pkcs11SigningHandle,
  toSigner,
  ED25519_SPKI_PREFIX,
} from './signer.js';
export { computeRecordHash, chainRecord } from './chain.js';
export {
  buildInclusionProof,
  verifyInclusionProof,
  merkleRootHex,
} from './merkle.js';
export {
  generateSpineKeyPair,
  signMessage,
  verifySignature,
  publicKeyFromPrivate,
  type SpineKeyPair,
} from './signing.js';
export { loadOrCreateKeyPair, resolveKeyPair } from './keys.js';
export { canonicalize, type CanonicalValue } from './canonical.js';
export { sha256Hex, sha256Bytes } from './hash.js';
export {
  createStore,
  storeConfigFromEnv,
  SqliteEvidenceStore,
  PostgresEvidenceStore,
  type EvidenceStore,
  type StoreConfig,
} from './store/index.js';
