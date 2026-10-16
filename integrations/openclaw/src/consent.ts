/**
 * Sharing gate — TypeScript mirror of `plugins/blackbox/community/consent.py`.
 *
 * Community sharing is OPT-IN (2026-10-16; it was on by default from
 * 2026-10-12): `${blackboxHome}/sharing_consent.json` allows sharing only when
 * it records an acceptance (`accepted_at`) and no opt-out (`withdrawn_at`); no
 * record means the default, sharing off. This module only READS the record
 * (`blackbox report --enable-sharing` and the dashboard toggle write it). An
 * unreadable or malformed record reads as no record, exactly as in Python.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";

const RECORD_FILE = "sharing_consent.json";

/** True only when the operator opted in (an `accepted_at` and no `withdrawn_at`). */
export function sharingConsentInForce(blackboxHome: string): boolean {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(join(blackboxHome, RECORD_FILE), "utf8"));
  } catch {
    return false;   // no record (or unreadable): the default, sharing off
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return false;
  const record = raw as Record<string, unknown>;
  // A field counts only as a non-empty string, exactly as consent.py's `_text` reads it.
  const text = (value: unknown): string => (typeof value === "string" ? value : "");
  return text(record.accepted_at) !== "" && text(record.withdrawn_at) === "";
}
