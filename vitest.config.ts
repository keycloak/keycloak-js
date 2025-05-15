import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom', // or 'node' if preferred for non-DOM related tests, jsdom is good for browser-like environment
    globals: true, // To use Vitest globals like describe, it, expect without importing
    // Optional: specify where test files are located if not using default pattern
    include: ['test/vitest/**/*.test.ts'], 
    // setupFiles: ['./test/setup.ts'], // if any global setup is needed
  },
});
