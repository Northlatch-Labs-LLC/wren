// Built-by: @projectx.sui
/*
  `test/*.test.mjs` are node:test files, run by their own documented command (`node --test
  test/wren.test.mjs`, and likewise for the two host checkers). They assert against the deployed
  droplet's layout — /srv/wren, agent-runtime, digitalocean — which this checkout does not carry,
  and vitest cannot collect node:test suites anyway ("No test suite found in file"). Excluding
  them here routes each file to the harness that can run it; it deletes nothing. The vitest suite
  is the .ts files.
*/
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    exclude: ['**/test/*.test.mjs', '**/node_modules/**', '**/dist/**'],
  },
});
