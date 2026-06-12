import { describe, expect, it } from 'vitest';
import { resolveConfig } from '../src/config.js';

describe('resolveConfig', () => {
  it('defaults to SQLite with local paths', () => {
    const config = resolveConfig({} as NodeJS.ProcessEnv);
    expect(config.store).toEqual({ kind: 'sqlite', path: '.attestor/evidence.sqlite' });
    expect(config.keyFilePath).toBe('.attestor/signing-key.json');
    expect(config.policyPath).toBe('policies/v0.yaml');
  });

  it('honours environment overrides', () => {
    const config = resolveConfig({
      ATTESTOR_DATABASE_URL: 'postgres://localhost/attestor',
      ATTESTOR_KEY_FILE: '/secrets/key.json',
      ATTESTOR_POLICY_FILE: '/etc/policy.yaml',
    } as NodeJS.ProcessEnv);
    expect(config.store).toEqual({
      kind: 'postgres',
      connectionString: 'postgres://localhost/attestor',
    });
    expect(config.keyFilePath).toBe('/secrets/key.json');
    expect(config.policyPath).toBe('/etc/policy.yaml');
  });
});
