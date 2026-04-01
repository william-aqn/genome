import { test, expect } from '@playwright/test';

test('speedtest.net: loads fully with Go button', async ({ browser }) => {
  const ctx = await browser.newContext({
    proxy: { server: 'socks5://127.0.0.1:11082' },
    ignoreHTTPSErrors: true,
    viewport: { width: 1280, height: 800 },
  });
  const page = await ctx.newPage();

  let total = 0, done = 0;
  page.on('request', () => total++);
  page.on('requestfinished', () => done++);
  page.on('requestfailed', () => done++);

  // Load and wait for full network settle.
  console.log('Loading speedtest.net...');
  await page.goto('https://www.speedtest.net/', { waitUntil: 'domcontentloaded', timeout: 30_000 });

  // Wait up to 30s for app to initialize (6.8 MB JS bundle).
  console.log('Waiting for app JS...');
  for (let i = 0; i < 30; i++) {
    await page.waitForTimeout(1_000);
    const goVisible = await page.locator('.start-button a').isVisible().catch(() => false);
    if (goVisible) {
      console.log(`Go button appeared after ${i + 1}s (${done}/${total} requests)`);
      break;
    }
    if (i % 5 === 4) {
      console.log(`  ${i + 1}s: ${done}/${total} requests done`);
    }
  }

  await page.screenshot({ path: 'tests/speedtest-01.png' });

  // Accept cookies.
  try {
    await page.locator('#onetrust-accept-btn-handler').click({ timeout: 3_000 });
    await page.waitForTimeout(1_000);
  } catch {}

  await page.screenshot({ path: 'tests/speedtest-02.png' });

  const goVisible = await page.locator('.start-button a').isVisible().catch(() => false);
  console.log(`Final: Go button visible=${goVisible}, ${done}/${total} requests`);

  await page.screenshot({ path: 'tests/speedtest-03-result.png' });
  expect(goVisible).toBe(true);

  await ctx.close();
});
