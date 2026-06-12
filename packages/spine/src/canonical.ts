/**
 * Deterministic ("canonical") serialization.
 *
 * Record and checkpoint hashes must be reproducible byte-for-byte on any machine
 * at any time, so we cannot rely on `JSON.stringify` key ordering. This module
 * emits JSON with object keys sorted lexicographically at every depth. The output
 * is what we hash and sign; it is never persisted as the record itself.
 */

export type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue };

/**
 * Serialize a value to canonical JSON: object keys sorted at every level, no
 * insignificant whitespace, arrays preserved in order.
 */
export function canonicalize(value: CanonicalValue): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }
  const obj = value as { readonly [key: string]: CanonicalValue };
  const keys = Object.keys(obj).sort();
  const members = keys.map(
    (key) => `${JSON.stringify(key)}:${canonicalize(obj[key] as CanonicalValue)}`,
  );
  return `{${members.join(',')}}`;
}
