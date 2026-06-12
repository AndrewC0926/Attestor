import { canonicalize, type CanonicalValue } from '@attestor/spine';

/**
 * Canonicalize an arbitrary JSON value (MCP arguments / results) for hashing.
 * `undefined` is normalized to `null` so a missing payload hashes consistently.
 */
export function canonicalJson(value: unknown): string {
  return canonicalize((value ?? null) as CanonicalValue);
}
