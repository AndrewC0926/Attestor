import { describe, expect, it } from 'vitest';
import {
  PostgresEvidenceStore,
  SqliteEvidenceStore,
  createStore,
  storeConfigFromEnv,
} from '../src/store/index.js';

describe('store factory', () => {
  it('creates a sqlite store', () => {
    const store = createStore({ kind: 'sqlite', path: ':memory:' });
    expect(store).toBeInstanceOf(SqliteEvidenceStore);
  });

  it('creates a postgres store without connecting', () => {
    const store = createStore({
      kind: 'postgres',
      connectionString: 'postgres://localhost:5432/none',
    });
    expect(store).toBeInstanceOf(PostgresEvidenceStore);
  });

  it('resolves postgres config when a database url is present', () => {
    const config = storeConfigFromEnv({
      ATTESTOR_DATABASE_URL: 'postgres://localhost/attestor',
    } as NodeJS.ProcessEnv);
    expect(config).toEqual({
      kind: 'postgres',
      connectionString: 'postgres://localhost/attestor',
    });
  });

  it('defaults to sqlite with an overridable path', () => {
    expect(storeConfigFromEnv({} as NodeJS.ProcessEnv)).toEqual({
      kind: 'sqlite',
      path: '.attestor/evidence.sqlite',
    });
    expect(
      storeConfigFromEnv({ ATTESTOR_SQLITE_PATH: '/tmp/x.sqlite' } as NodeJS.ProcessEnv),
    ).toEqual({ kind: 'sqlite', path: '/tmp/x.sqlite' });
  });
});
