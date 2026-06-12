import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    environment: 'node',
    include: ['packages/**/test/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'html'],
      // The evidence spine is the sacred core; enforce its coverage floor here.
      include: ['packages/spine/src/**/*.ts'],
      exclude: [
        'packages/spine/src/index.ts',
        // Postgres glue requires a live database; it is exercised by the Docker
        // integration path and the demo, not by the unit suite. The integrity
        // logic it relies on is backend-agnostic and covered via SQLite.
        'packages/spine/src/store/postgres.ts',
        '**/*.d.ts',
      ],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 85,
        statements: 90,
      },
    },
  },
});
