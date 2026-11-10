#!/usr/bin/env node
// Render dev/tools/shots/*.html at desktop (1280) and phone (480) widths,
// assert no horizontal overflow, and save full-page PNGs next to the HTML.
// Usage: node dev/tools/shot.mjs <page-name>   (e.g. protection)
import { chromium } from '/home/grey/.nvm/versions/node/v22.22.2/lib/node_modules/wp-studio/node_modules/playwright/index.mjs';

const exe = '/home/grey/.cache/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell';

const name = process.argv[2];
if (!name) {
  console.error('usage: node dev/tools/shot.mjs <page-name>');
  process.exit(1);
}
const file = new URL(`./shots/${name}.html`, import.meta.url).pathname;
const out = (w) => `dev/tools/shots/${name}-${w === 1280 ? 'desktop' : 'mobile'}.png`;

const browser = await chromium.launch({ executablePath: exe });
for (const width of [1280, 480]) {
  const page = await browser.newPage({
    viewport: { width, height: 900 },
    deviceScaleFactor: 2,
  });
  await page.goto(`file://${file}`);
  await page.waitForTimeout(300);
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth
  );
  if (overflow > 0) {
    console.error(`x-overflow ${overflow}px at ${width}px`);
    process.exitCode = 1;
  }
  await page.screenshot({ path: out(width), fullPage: true });
  await page.close();
  console.log(`${out(width)} (overflow ${overflow}px)`);
}
await browser.close();
