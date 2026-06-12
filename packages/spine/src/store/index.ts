import type { EvidenceStore } from './types.js';
import { PostgresEvidenceStore } from './postgres.js';
import { SqliteEvidenceStore } from './sqlite.js';

export type { EvidenceStore } from './types.js';
export { PostgresEvidenceStore } from './postgres.js';
export { SqliteEvidenceStore } from './sqlite.js';

/**
 * Store configuration. `sqlite` is the zero-dependency laptop/CI backend;
 * `postgres` is the production-shaped backend. Both honour the same append-only
 * guarantees, so the rest of the platform is backend-agnostic.
 */
export type StoreConfig =
  | { readonly kind: 'sqlite'; readonly path: string }
  | { readonly kind: 'postgres'; readonly connectionString: string };

/** Construct (but do not initialize) a store from configuration. */
export function createStore(config: StoreConfig): EvidenceStore {
  switch (config.kind) {
    case 'sqlite':
      return new SqliteEvidenceStore(config.path);
    case 'postgres':
      return new PostgresEvidenceStore(config.connectionString);
  }
}

/**
 * Resolve a store from environment, defaulting to SQLite for local use.
 *   ATTESTOR_DATABASE_URL — Postgres connection string (takes precedence)
 *   ATTESTOR_SQLITE_PATH   — SQLite file path (default ./.attestor/evidence.sqlite)
 */
export function storeConfigFromEnv(env: NodeJS.ProcessEnv = process.env): StoreConfig {
  const url = env.ATTESTOR_DATABASE_URL;
  if (url && url.length > 0) {
    return { kind: 'postgres', connectionString: url };
  }
  return {
    kind: 'sqlite',
    path: env.ATTESTOR_SQLITE_PATH ?? '.attestor/evidence.sqlite',
  };
}
