import { describe, expect, it } from 'vitest';
import { controlTitle, loadControlCatalog } from '../src/controls.js';

describe('control catalog', () => {
  it('loads the bundled ISO 42001 mapping', () => {
    const catalog = loadControlCatalog('data/iso42001-controls.json');
    expect(catalog.framework).toContain('42001');
    expect(catalog.controls['A.6.2.8']?.title).toBeTruthy();
  });

  it('returns an empty catalog when the file is missing', () => {
    const catalog = loadControlCatalog('data/does-not-exist.json');
    expect(catalog.controls).toEqual({});
  });

  it('formats a known control with its title and falls back to the id', () => {
    const catalog = loadControlCatalog('data/iso42001-controls.json');
    expect(controlTitle(catalog, 'A.6.2.4')).toContain('A.6.2.4 —');
    expect(controlTitle(catalog, 'A.99.9')).toBe('A.99.9');
  });
});
