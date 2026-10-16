/**
 * Cross-runtime SHARING-GATE parity — the TypeScript half.
 *
 * Reads a JSON array of record-file contents (path in argv[2]; null = no record
 * file), writes each into a fresh Blackbox home, asks `sharingConsentInForce`,
 * and prints the answers as a JSON array.
 * `tests/plugins/test_blackbox_sharing_gate_parity.py` compares them with
 * `community/consent.in_force` (sharing opt-in: on only with an acceptance and no opt-out).
 *
 * Run with: npx tsx integrations/openclaw/test/sharing-gate-parity.mjs <cases.json>
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { sharingConsentInForce } from "../src/consent.ts";

const cases = JSON.parse(readFileSync(process.argv[2], "utf8"));
const answers = cases.map((content) => {
  const home = mkdtempSync(join(tmpdir(), "bb-gate-"));
  try {
    if (content !== null) writeFileSync(join(home, "sharing_consent.json"), content, "utf8");
    return sharingConsentInForce(home);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
process.stdout.write(JSON.stringify(answers));
