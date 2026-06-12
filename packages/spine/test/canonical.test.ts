import { describe, expect, it } from 'vitest';
import { canonicalize } from '../src/canonical.js';

describe('canonicalize', () => {
  it('sorts object keys at every depth', () => {
    const a = canonicalize({ b: 1, a: { d: 2, c: 3 } });
    const b = canonicalize({ a: { c: 3, d: 2 }, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":{"c":3,"d":2},"b":1}');
  });

  it('preserves array order', () => {
    expect(canonicalize([3, 1, 2])).toBe('[3,1,2]');
  });

  it('handles primitives and null', () => {
    expect(canonicalize('x')).toBe('"x"');
    expect(canonicalize(7)).toBe('7');
    expect(canonicalize(true)).toBe('true');
    expect(canonicalize(null)).toBe('null');
  });

  it('produces identical output regardless of insertion order', () => {
    const x = canonicalize({ z: [{ q: 1, a: 2 }], m: 'v' });
    const y = canonicalize({ m: 'v', z: [{ a: 2, q: 1 }] });
    expect(x).toBe(y);
  });
});
