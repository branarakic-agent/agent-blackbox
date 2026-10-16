/**
 * Real-browser replay of captured shield payloads on the dashboard (LES-002, LES-018) — the browser half.
 *
 * Serves nothing itself: `tests/plugins/test_blackbox_shields_panel.py` runs the real app, and this
 * script answers `GET /api/shields` and `GET /api/shields/<id>/events` from the JSON files it is
 * given (everything else is the real app). At desktop (1440) and phone (390) widths it replays:
 *
 *   (each load's first /api/shields answers [], as the server's cache does before it fills)
 *   engaged  — the captured payload: the card is drawn, its banner exists but stays hidden; a
 *              recent event opens the events window; Settings shows the shield's group, and a
 *              save sends only the "lines" entries the field's pattern accepts;
 *   off      — the same payload with the shield off: the banner shows, the card hides;
 *   sparse   — payloads missing every optional field (and a non-list): nothing throws.
 *
 * It writes one JSON summary per viewport: console errors, page errors, failed requests,
 * horizontal overflow per step, and what each step found on the page.
 *
 *   PW_EXEC=<chromium binary> node tests/plugins/shields_replay.mjs <base url> <cards.json> <events.json> <out dir>
 */
import { chromium } from "playwright";
import { readFileSync, writeFileSync } from "node:fs";

const [base, cardsFile, eventsFile, outDir] = process.argv.slice(2);
const cards = JSON.parse(readFileSync(cardsFile, "utf-8"));
const events = JSON.parse(readFileSync(eventsFile, "utf-8"));
const off = cards.map((card) => ({ ...card, mode: { ...card.mode, enabled: false } }));
const SPARSE = [[{}], [{ shield_id: "trader" }], [{ shield_id: "trader", mode: { enabled: true }, sections: [{}, { rows: [{}] }] }], { not: "a list" }];
const viewports = [
  { name: "desktop", width: 1440, height: 900 },
  { name: "phone", width: 390, height: 844 },
];

const launch = process.env.PW_EXEC ? { executablePath: process.env.PW_EXEC } : {};
const browser = await chromium.launch(launch);
const summary = [];
for (const vp of viewports) {
  const context = await browser.newContext({ viewport: { width: vp.width, height: vp.height }, deviceScaleFactor: 1 });
  const page = await context.newPage();
  const consoleErrors = [];
  const pageErrors = [];
  const failedRequests = [];
  page.on("console", (msg) => { if (msg.type() === "error") consoleErrors.push(msg.text().slice(0, 300)); });
  page.on("pageerror", (err) => pageErrors.push(String(err.stack || err).slice(0, 600)));
  page.on("requestfailed", (req) => failedRequests.push(`${req.method()} ${req.url()} — ${req.failure()?.errorText}`));
  page.on("response", (res) => { if (res.status() >= 400) failedRequests.push(`${res.status()} ${res.url()}`); });

  // Like the server's cache, the first /api/shields of each page load answers the empty default:
  // the page must ask again and draw the cards within seconds, not at its 30 s refresh.
  let served = cards, firstOfLoad = true;
  await page.route(/\/api\/shields$/, (route) => {
    const body = firstOfLoad ? [] : served;
    firstOfLoad = false;
    return route.fulfill({ contentType: "application/json", body: JSON.stringify(body) });
  });
  await page.route(/\/api\/shields\/[^/]+\/events$/, (route) => route.fulfill({ contentType: "application/json", body: JSON.stringify(events) }));

  const overflow = (label) => page.evaluate((label) => {
    const doc = document.documentElement;
    return { label, scrollWidth: doc.scrollWidth, clientWidth: doc.clientWidth, horizontalOverflow: doc.scrollWidth > doc.clientWidth };
  }, label);
  const load = async () => {
    firstOfLoad = true;
    await page.goto(base, { waitUntil: "domcontentloaded", timeout: 30000 });
    try { await page.waitForLoadState("networkidle", { timeout: 15000 }); } catch { /* the page polls */ }
    await page.waitForTimeout(1500);
  };
  const shown = (selector) => page.evaluate((selector) => {
    const el = document.querySelector(selector);
    return el ? { present: true, hidden: el.hidden || el.closest("[hidden]") !== null, text: (el.innerText || "").replace(/\s+/g, " ").trim().slice(0, 4000) }
              : { present: false, hidden: true, text: "" };
  }, selector);

  // engaged: the captured payload
  await load();
  const checks = [await overflow("engaged")];
  const found = {
    card: await shown('[data-shield-card="trader"]'),
    banner: await shown('[data-shield-banner="trader"]'),
    cardLogos: await page.locator('[data-shield-card="trader"] img.wl').count(),
  };
  await page.locator('[data-shield-card="trader"] .wp-ev').first().click();
  await page.waitForTimeout(800);
  found.window = await shown(".wev-overlay");
  found.windowStory = await shown(".wev-overlay .wev-story");
  found.windowFacts = await page.locator(".wev-overlay .wev-facts .k").count();
  found.windowSteps = await page.locator(".wev-overlay .wev-step").count();
  found.injected = await page.evaluate(() => window.__shieldsReplayInjected === true || document.querySelector(".wev-story img, .wev-story script") !== null);
  checks.push(await overflow("events-window"));
  await page.keyboard.press("Escape");
  await page.waitForTimeout(300);
  found.windowAfterEscape = await shown(".wev-overlay");
  // The gear sits in the header (folded away on a phone); Settings itself is what is checked here.
  await page.evaluate(() => document.getElementById("settings-open").click());
  await page.waitForTimeout(1200);
  found.settings = await shown('[data-shield-settings="trader"]');
  found.settingsInputs = await page.locator('[data-shield-settings="trader"] input[data-field], [data-shield-settings="trader"] textarea[data-field]').count();
  checks.push(await overflow("settings"));
  // A "lines" field never sends a line its pattern refuses: type one accepted and one refused line,
  // save, and read what the real POST /api/settings carried.
  const posted = page.waitForRequest((req) => req.method() === "POST" && /\/api\/settings$/.test(req.url()), { timeout: 15000 });
  const linesKey = await page.evaluate(() => {
    const box = document.querySelector('[data-shield-settings="trader"] textarea[data-field]');
    box.value = "0x" + "a".repeat(40) + "\nnot-an-address";
    box.dispatchEvent(new Event("input", { bubbles: true }));
    return box.getAttribute("data-field");
  });
  found.linesNote = await shown(`[data-shield-settings="trader"] [data-lines-note="${linesKey}"]`);
  await page.evaluate(() => document.getElementById("set-save").click());
  found.linesSent = ((await posted).postDataJSON().shields?.trader ?? {})[linesKey] ?? null;
  await page.waitForTimeout(800);
  await page.evaluate(() => document.getElementById("set-cancel").click());

  // off: the banner shows and the card hides
  served = off;
  await load();
  found.offBanner = await shown('[data-shield-banner="trader"]');
  found.offCard = await shown('[data-shield-card="trader"]');
  checks.push(await overflow("off"));

  // sparse: every optional field missing, and a payload that is not a list
  found.sparse = [];
  for (const payload of SPARSE) {
    served = payload;
    await load();
    found.sparse.push(await page.locator("[data-shield-card]").count());
    checks.push(await overflow("sparse"));
  }
  summary.push({ viewport: vp, consoleErrors, pageErrors, failedRequests, checks, found });
  await context.close();
}
await browser.close();
writeFileSync(`${outDir}/shields-replay-summary.json`, JSON.stringify(summary, null, 2));
