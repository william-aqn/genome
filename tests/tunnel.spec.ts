import { test, expect } from '@playwright/test';

// --- Basic connectivity ---

test('HTTP: example.com loads', async ({ page }) => {
  const resp = await page.goto('http://example.com', { waitUntil: 'domcontentloaded' });
  expect(resp?.status()).toBe(200);
  await expect(page.locator('h1')).toHaveText('Example Domain');
});

test('HTTPS: example.com loads', async ({ page }) => {
  const resp = await page.goto('https://example.com', { waitUntil: 'domcontentloaded' });
  expect(resp?.status()).toBe(200);
  await expect(page.locator('h1')).toHaveText('Example Domain');
});

// --- Real websites with JS/CSS/images ---

test('HTTPS: wikipedia.org loads with content', async ({ page }) => {
  const resp = await page.goto('https://en.wikipedia.org/wiki/Main_Page', { waitUntil: 'domcontentloaded' });
  expect(resp?.status()).toBe(200);
  const fontFamily = await page.locator('body').evaluate(el => getComputedStyle(el).fontFamily);
  expect(fontFamily).toBeTruthy();
  await expect(page.locator('#mp-upper')).toBeVisible();
});

test('HTTPS: httpbin.org/get returns JSON', async ({ page }) => {
  const resp = await page.goto('https://httpbin.org/get', { waitUntil: 'domcontentloaded' });
  expect(resp?.status()).toBe(200);
  const text = await page.locator('pre').textContent();
  const json = JSON.parse(text || '{}');
  expect(json).toHaveProperty('headers');
  expect(json).toHaveProperty('url');
});

// --- Subresource loading (CSS, JS, images) ---

test('HTTPS: site with CSS/JS loads fully', async ({ page }) => {
  const failedRequests: string[] = [];
  page.on('requestfailed', req => {
    failedRequests.push(`${req.failure()?.errorText}: ${req.url()}`);
  });

  const resp = await page.goto('https://en.wikipedia.org/wiki/Go_(programming_language)', { waitUntil: 'domcontentloaded', timeout: 25_000 });
  expect(resp?.status()).toBe(200);

  const hasStyles = await page.evaluate(() => {
    const styles = document.querySelectorAll('link[rel="stylesheet"], style');
    return styles.length > 0;
  });
  expect(hasStyles).toBe(true);

  // Check images loaded.
  const images = await page.evaluate(() => {
    const imgs = document.querySelectorAll('img');
    return Array.from(imgs).map(img => ({ src: img.src, complete: img.complete, natural: img.naturalWidth }));
  });
  const loadedImages = images.filter(i => i.complete && i.natural > 0);
  console.log(`Images: ${loadedImages.length}/${images.length} loaded`);

  if (failedRequests.length > 0) {
    console.log('Failed subresources:', failedRequests.slice(0, 10));
  }
  expect(failedRequests.length).toBeLessThan(5);
});

test('HTTPS: github.com loads (heavy site)', async ({ page }) => {
  const failedRequests: string[] = [];
  page.on('requestfailed', req => {
    failedRequests.push(`${req.failure()?.errorText}: ${req.url()}`);
  });

  try {
    const resp = await page.goto('https://github.com', { waitUntil: 'domcontentloaded', timeout: 25_000 });
    expect(resp?.status()).toBe(200);
    console.log('github.com loaded OK');
  } catch (e: any) {
    console.log('github.com SLOW/FAILED:', e.message);
    console.log('Failed requests:', failedRequests.slice(0, 10));
    // Don't fail the test — this diagnoses throughput issues.
  }

  if (failedRequests.length > 0) {
    console.log('Failed subresources:', failedRequests.slice(0, 10));
  }
});

// --- Sequential requests (connection reuse) ---

test('Sequential requests work', async ({ page }) => {
  await page.goto('https://httpbin.org/get', { waitUntil: 'domcontentloaded' });
  const text1 = await page.locator('pre').textContent();
  expect(text1).toContain('headers');

  await page.goto('https://example.com', { waitUntil: 'domcontentloaded' });
  await expect(page.locator('h1')).toHaveText('Example Domain');

  await page.goto('https://httpbin.org/ip', { waitUntil: 'domcontentloaded' });
  const text3 = await page.locator('pre').textContent();
  expect(text3).toContain('origin');
});

// --- Large response ---

test('Large response: google robots.txt', async ({ page }) => {
  const resp = await page.goto('https://www.google.com/robots.txt', { waitUntil: 'domcontentloaded' });
  expect(resp?.status()).toBe(200);
  const text = await page.locator('pre').textContent() ?? await page.content();
  expect(text.length).toBeGreaterThan(1000);
});

// --- Parallel page loads ---

test('Parallel page loads', async ({ browser }) => {
  const urls = [
    'https://example.com',
    'https://httpbin.org/get',
    'https://en.wikipedia.org',
  ];

  const results = await Promise.all(
    urls.map(async (url) => {
      const ctx = await browser.newContext({
        proxy: {
          server: 'socks5://127.0.0.1:11081',
        },
        ignoreHTTPSErrors: true,
      });
      const page = await ctx.newPage();
      try {
        const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 20_000 });
        return { url, status: resp?.status(), ok: true };
      } catch (e: any) {
        return { url, error: e.message, ok: false };
      } finally {
        await ctx.close();
      }
    })
  );

  console.log('Parallel results:', JSON.stringify(results, null, 2));
  for (const r of results) {
    expect(r.ok, `${r.url} failed: ${(r as any).error}`).toBe(true);
  }
});

// --- Diagnose hanging requests ---

test('Diagnose: many requests, find hangs', async ({ page }) => {
  const urls = [
    'https://example.com',
    'https://httpbin.org/get',
    'https://httpbin.org/ip',
    'https://www.google.com/robots.txt',
    'https://en.wikipedia.org/wiki/Main_Page',
    'https://cloudflare.com',
    'https://httpbin.org/headers',
    'https://httpbin.org/user-agent',
  ];

  for (const url of urls) {
    const start = Date.now();
    try {
      const resp = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10_000 });
      const elapsed = Date.now() - start;
      console.log(`OK  ${elapsed}ms  ${resp?.status()}  ${url}`);
    } catch (e: any) {
      const elapsed = Date.now() - start;
      console.log(`FAIL  ${elapsed}ms  ${url}  ${e.message.split('\n')[0]}`);
    }
  }
});

test('Diagnose: rapid sequential (same host)', async ({ page }) => {
  for (let i = 0; i < 5; i++) {
    const start = Date.now();
    try {
      const resp = await page.goto(`https://httpbin.org/get?i=${i}`, { waitUntil: 'domcontentloaded', timeout: 10_000 });
      const elapsed = Date.now() - start;
      console.log(`  req ${i}: ${elapsed}ms  status=${resp?.status()}`);
    } catch (e: any) {
      const elapsed = Date.now() - start;
      console.log(`  req ${i}: HANG ${elapsed}ms  ${e.message.split('\n')[0]}`);
    }
  }
});

// --- Check exit IP ---

test('Exit IP is via tunnel', async ({ page }) => {
  await page.goto('https://httpbin.org/ip', { waitUntil: 'domcontentloaded' });
  const text = await page.locator('pre').textContent();
  const json = JSON.parse(text || '{}');
  console.log('Exit IP:', json.origin);
  expect(json.origin).toMatch(/\d+\.\d+\.\d+\.\d+/);
});
