import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  retries: 0,
  use: {
    proxy: {
      server: 'socks5://127.0.0.1:11081',
    },
    ignoreHTTPSErrors: true,
  },
});
