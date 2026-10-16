/**
 * Real-browser check that the Settings form is never stale (2026-10-15 dashboard audit) — the browser half.
 *
 * The sequence that used to disengage a shield: load Settings once (the page keeps that copy),
 * close it, press "Engage" on the Trader Shield banner (which writes the setting on its own),
 * reopen Settings and press Save. The old page reopened its first copy, showed the shield OFF,
 * and Save wrote OFF back. Writes one JSON summary; tests/plugins/test_blackbox_dashboard_browser.py
 * serves the fixture app, runs this script and asserts on the summary.
 *
 *   PW_EXEC=<chromium binary> node tests/plugins/dashboard_settings_freshness.mjs <base url> <out dir>
 */
import { chromium } from "playwright";
import { writeFileSync } from "node:fs";

const base = process.argv[2];
const outDir = process.argv[3] || ".";
const launch = process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {};
const browser = await chromium.launch(launch);
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
const consoleErrors = [];
const pageErrors = [];
page.on("console", (msg) => { if (msg.type() === "error") consoleErrors.push(msg.text()); });
page.on("pageerror", (err) => pageErrors.push(String(err)));

const toggle = 'input[data-shield-id="trader"][data-field="enabled"]';
const saveEnabled = () => page.waitForFunction(() => {
  const button = document.getElementById("set-save");
  return button && !button.disabled;
}, null, { timeout: 30000 });

await page.goto(base + "/", { waitUntil: "domcontentloaded" });
await page.evaluate(() => document.fonts.ready);
const engage = page.locator('[data-shield-engage="trader"]');
await engage.waitFor({ state: "visible", timeout: 60000 });

// 1. Load Settings once, so the page holds a copy with the shield OFF, then close it.
await page.click("#settings-open");
await saveEnabled();
const offBefore = await page.isChecked(toggle);
await page.click("#set-close");

// 2. Engage from the banner: the setting is written by this button alone.
await engage.click();
await page.waitForFunction(() => /Engaged/.test(document.querySelector('[data-shield-engage="trader"]')?.textContent || "")
  || !document.querySelector('[data-shield-engage="trader"]'), null, { timeout: 30000 });

// 3. Reopen Settings: it must show the shield ON (a fresh read), then Save.
await page.click("#settings-open");
await saveEnabled();
const onInForm = await page.isChecked(toggle);
await page.click("#set-save");
await page.waitForFunction(() => document.getElementById("settings-modal")?.getAttribute("aria-hidden") === "true",
  null, { timeout: 30000 });

// 4. What the server holds after that Save.
const enabledAfterSave = await page.evaluate(async () => {
  const response = await fetch("/api/settings");
  const view = await response.json();
  return Boolean(view?.shields?.trader?.mode?.enabled);
});

writeFileSync(`${outDir}/settings-freshness-summary.json`, JSON.stringify({
  offBefore, onInForm, enabledAfterSave, consoleErrors, pageErrors,
}, null, 1));
await browser.close();
