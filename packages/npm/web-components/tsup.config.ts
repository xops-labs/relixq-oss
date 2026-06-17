// Copyright (c) 2026 Yasvanth Udayakumar
// SPDX-License-Identifier: Apache-2.0
// See LICENSE in the repository root for full terms.
import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  // react / react-dom are peerDependencies — never bundle them, and keep the
  // automatic JSX runtime import external so the consumer's React is used.
  external: ['react', 'react-dom', 'react/jsx-runtime'],
  // Force .mjs / .cjs so the emitted files match the package.json `exports`
  // map. The matching .d.mts / .d.cts declarations are emitted alongside.
  outExtension({ format }) {
    return { js: format === 'esm' ? '.mjs' : '.cjs' };
  },
});
