import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

// The webview loads only bundled files: relative base for the Tauri asset protocol, no remote
// assets, and nothing inlined as data: URIs (the CSP allows fonts from 'self' only).
export default defineConfig({
  base: './',
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    sourcemap: false,
    // one local bundle (React + xterm) loaded from disk by the webview; no network cost to split for
    chunkSizeWarningLimit: 1024,
  },
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
  },
});
