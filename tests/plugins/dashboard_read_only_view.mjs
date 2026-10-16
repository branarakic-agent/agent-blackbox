/**
 * Real-browser check of the dashboard in a read-only view (2026-10-15: the demo's read-only view
 * refuses /api/session, and Save said "Network error. Settings not saved.") — the browser half.
 * Refuses /api/session the way such a view does, then presses Save in Settings and Engage on a
 * shield banner, and records what each says. tests/plugins/test_blackbox_dashboard_browser.py
 * serves the fixture app, runs this script and asserts on the summary.
 *
 *   PW_EXEC=<chromium binary> node tests/plugins/dashboard_read_only_view.mjs <base url> <out dir>
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";

const base = process.argv[2];
const outDir = process.argv[3] || ".";
const browser = await chromium.launch(process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {});
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const pageErrors = [];
page.on("pageerror", (err) => pageErrors.push(String(err)));
await page.route("**/api/session", (route) => route.fulfill({ status: 403, contentType: "application/json",
  body: JSON.stringify({ error: "read-only demo" }) }));

await page.goto(base + "/", { waitUntil: "domcontentloaded" });
const engage = page.locator('[data-shield-engage="trader"]');
await engage.waitFor({ state: "visible", timeout: 60000 });

await page.click("#settings-open");
await page.waitForFunction(() => !document.getElementById("set-save")?.disabled, null, { timeout: 30000 });
await page.click("#set-save");
await page.waitForFunction(() => /switched off in this view|Network error/.test(document.getElementById("set-status")?.textContent || ""),
  null, { timeout: 30000 });
const saveStatus = await page.locator("#set-status").innerText();
await page.click("#set-close");

await engage.click();
await page.waitForFunction(() => /Engage /.test(document.querySelector('[data-shield-engage="trader"]')?.textContent || ""),
  null, { timeout: 30000 });
const engageButton = await engage.innerText();

writeFileSync(`${outDir}/read-only-view-summary.json`, JSON.stringify({ saveStatus, engageButton, pageErrors }, null, 1));
await browser.close();
