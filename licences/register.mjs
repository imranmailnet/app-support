// The seller's list of shops and their licences, kept locked in the public `app-support` repository as
// licences/register.enc. Shared by the "Renew licence" form (renew.mjs), the morning reminder (reminders.mjs) and
// the Licences page (index.html), in Node and in the browser alike (Web Crypto only, no imports).
//
// The list is locked with the seller's list password (the GitHub secret REGISTER_KEY, typed on the page), so the
// public sees random text. Requests from the Licences page are locked the same way before they are sent to the
// form, so even the run's inputs say nothing.

const enc = new TextEncoder();
const dec = new TextDecoder();
const subtle = () => globalThis.crypto.subtle;

export const REGISTER_PREFIX = 'MANIREG1.';
export const REQUEST_PREFIX = 'MANIREQ1.';
/** PBKDF2 rounds: slow enough that guessing a good password is hopeless. */
const ROUNDS = 310_000;

export function toB64url(bytes) {
  let text = '';
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64url(text) {
  const clean = text.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(clean + '='.repeat((4 - (clean.length % 4)) % 4)), (c) => c.charCodeAt(0));
}

async function keyFrom(password, salt) {
  const base = await subtle().importKey('raw', enc.encode(String(password)), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey({ name: 'PBKDF2', salt, iterations: ROUNDS, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

/** Locks any value with a password: prefix + salt(16) + iv(12) + AES-GCM text. */
export async function lockWith(password, value, prefix = REGISTER_PREFIX) {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const body = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv }, await keyFrom(password, salt), enc.encode(JSON.stringify(value))));
  const all = new Uint8Array(28 + body.length);
  all.set(salt, 0);
  all.set(iv, 16);
  all.set(body, 28);
  return prefix + toB64url(all);
}

/** Opens a locked text, or null when the password is wrong or it is not one. */
export async function openWith(password, text, prefix = REGISTER_PREFIX) {
  const clean = String(text ?? '').replace(/\s+/g, '');
  if (!clean.startsWith(prefix)) return null;
  try {
    const bytes = fromB64url(clean.slice(prefix.length));
    const plain = await subtle().decrypt({ name: 'AES-GCM', iv: bytes.subarray(16, 28) }, await keyFrom(password, bytes.subarray(0, 16)), bytes.subarray(28));
    return JSON.parse(dec.decode(plain));
  } catch {
    return null;
  }
}

/** An empty list. */
export const emptyRegister = () => ({ v: 1, updated: null, lastRequest: null, shops: {} });

// ---------------------------------------------------------------- Where a shop stands (as the app's licenseStatus)

/** Same as LICENSE_WARN_DAYS, LICENSE_GRACE_DAYS and LICENSE_LIMITED_DAYS in the app (a test checks). */
export const WARN_DAYS = 30;
export const GRACE_DAYS = 7;
export const LIMITED_DAYS = 30;

const DAY = 86_400_000;
export const addDays = (date, days) => new Date(Date.parse(`${date}T00:00:00Z`) + days * DAY).toISOString().slice(0, 10);
export const daysBetween = (from, to) => Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY);
export const saudiToday = (now = Date.now()) => new Date(now + 3 * 3_600_000).toISOString().slice(0, 10);

/**
 * Where a shop of the list stands on `today`: active, ending (within 30 days), grace (the 7 days after the last
 * day), limited (the locked month), stopped, unlocked (a 7-day unlock code running), or noEnd.
 * `daysLeft` counts to the last day (negative once past it); `nextDate` is when the state next changes.
 */
export function shopState(shop, today) {
  const end = shop.expires;
  if (!end) return { state: 'noEnd', daysLeft: null, nextDate: null };
  const daysLeft = daysBetween(today, end);
  if (daysLeft >= 0) return { state: daysLeft < WARN_DAYS ? 'ending' : 'active', daysLeft, nextDate: addDays(end, 1) };
  if (shop.unlockUntil && today <= shop.unlockUntil) return { state: 'unlocked', daysLeft, nextDate: addDays(shop.unlockUntil, 1) };
  const locksOn = addDays(end, GRACE_DAYS + 1);
  const stopsOn = addDays(locksOn, LIMITED_DAYS);
  if (today < locksOn) return { state: 'grace', daysLeft, nextDate: locksOn };
  if (today < stopsOn) return { state: 'limited', daysLeft, nextDate: stopsOn };
  return { state: 'stopped', daysLeft, nextDate: null };
}

/** Words for each state, for the page and the email. */
export const STATE_WORDS = {
  active: 'Active',
  ending: 'Ending soon',
  grace: 'Ended (7 days of grace)',
  limited: 'Ended (locked month)',
  stopped: 'Stopped',
  unlocked: 'Unlocked for 7 days',
  noEnd: 'No end date',
};

/** The last payment recorded for a shop, or null. */
export const lastPayment = (shop) => [...(shop.history ?? [])].reverse().find((h) => h.amount != null) ?? null;

/** Shows a Shop ID as ABCD-EFGH-JKMN. */
export const shopIdText = (code) => String(code ?? '').replace(/(.{4})(?=.)/g, '$1-');

// ---------------------------------------------------------------- Daily health reports (Stage 2)
// The same as packages/shared/src/health-report.ts in the app (a test checks): each shop's server sends a report
// locked with its Shop ID to the collector, filed under an id only the Shop ID gives.

export const HEALTH_REPORT_PREFIX = 'MANIHR1.';
/** No report for this many days = the shop's server is off, offline, or the report was switched off. */
export const QUIET_DAYS = 3;

const sha256 = async (text) => new Uint8Array(await subtle().digest('SHA-256', enc.encode(text)));

/** The id a shop's reports are filed under at the collector. */
export async function healthReportId(code) {
  return [...(await sha256(`health-id:${code}`))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Opens a shop's locked report with its Shop ID, or null. */
export async function openHealthReport(code, text) {
  const clean = String(text ?? '').replace(/\s+/g, '');
  if (!clean.startsWith(HEALTH_REPORT_PREFIX)) return null;
  try {
    const bytes = fromB64url(clean.slice(HEALTH_REPORT_PREFIX.length));
    const key = await subtle().importKey('raw', await sha256(`health-seal:${code}`), 'AES-GCM', false, ['decrypt']);
    return JSON.parse(dec.decode(await subtle().decrypt({ name: 'AES-GCM', iv: bytes.subarray(0, 12) }, key, bytes.subarray(12))));
  } catch {
    return null;
  }
}

/** Compares app versions such as 0.1.470 (newer = bigger). */
export function versionOrder(a, b) {
  const pa = String(a ?? '').split('.').map(Number);
  const pb = String(b ?? '').split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

/** Words for each of the server's own checks in a report. */
export const CHECK_WORDS = {
  server: 'Server',
  database: 'Database',
  disk: 'Disk space',
  backup: 'Backups',
  copy: 'Backup copy folder',
  liveCopy: 'Up-to-the-minute copy',
  drive: 'Google Drive',
  tidy: 'Nightly tidy-up',
  zatca: 'ZATCA',
  twoMachines: 'Two computers on one database',
  moved: 'Business moved to another computer',
  errors: 'Errors',
  testCopies: 'Test copies',
};

/**
 * What needs the seller's eye in a shop's latest report: `kind` quiet (no report for QUIET_DAYS), version (older
 * than the newest any shop runs), limits (more in use than the licence allows), key (the shop still runs another
 * licence key than the list's newest), pos (POS app to update) or check (a server check not ok). `tone` bad or warn.
 */
export function healthWarnings(shop, health, today, newestVersion) {
  const out = [];
  if (!health) return out;
  const r = health.report;
  const days = daysBetween(saudiToday(Date.parse(health.at)), today);
  if (days >= QUIET_DAYS) out.push({ kind: 'quiet', tone: 'bad', text: `No report for ${days} days` });
  if (!r) return out;
  if (newestVersion && versionOrder(r.app?.version, newestVersion) < 0) out.push({ kind: 'version', tone: 'warn', text: `Old version ${r.app?.version} (newest ${newestVersion})` });
  for (const [k, words] of [['branches', 'branches'], ['pos', 'POS counters'], ['users', 'users']]) {
    if (shop[k] != null && r.use?.[k] > shop[k]) out.push({ kind: 'limits', tone: 'bad', text: `${r.use[k]} ${words} in use, licence allows ${shop[k]}` });
  }
  if (shop.keyNo && r.licence?.keyNo && r.licence.keyNo !== shop.keyNo) out.push({ kind: 'key', tone: 'warn', text: `Shop still runs licence ${r.licence.keyNo}, not ${shop.keyNo}` });
  const behind = (r.pos ?? []).filter((p) => p.active && p.update && p.update !== 'ok');
  if (behind.length) out.push({ kind: 'pos', tone: behind.some((p) => p.update === 'too_old') ? 'bad' : 'warn', text: `POS app to update: ${behind.map((p) => p.code).join(', ')}` });
  for (const c of r.checks ?? []) if (c.status !== 'ok') out.push({ kind: 'check', tone: c.status === 'bad' ? 'bad' : 'warn', text: `${CHECK_WORDS[c.key] ?? c.key}: ${checkText(c)}` });
  return out;
}

/** A check's figures in a few words. */
export function checkText(c) {
  const v = c.values ?? {};
  const at = (iso) => (iso ? `${String(iso).slice(8, 10)}/${String(iso).slice(5, 7)}/${String(iso).slice(0, 4)}` : '');
  switch (c.key) {
    case 'server': return [v.version && `version ${v.version}`, v.upHours != null && `up ${v.upHours} h`].filter(Boolean).join(', ');
    case 'database': return [v.mb != null && `${v.mb} MB`, v.businesses != null && `${v.businesses} businesses`].filter(Boolean).join(', ');
    case 'disk': return [v.freeGb != null && `${v.freeGb} GB free`, v.percent != null && `${v.percent}%`].filter(Boolean).join(', ');
    case 'backup': case 'copy': case 'drive': return v.state === 'none' ? 'not set up' : [v.state, v.at && `last ${at(v.at)}`, v.mb != null && `${v.mb} MB`].filter(Boolean).join(', ');
    case 'liveCopy': return v.state === 'none' ? 'not set up' : String(v.state ?? '');
    case 'tidy': return v.at ? `last ${at(v.at)}` : 'never ran';
    case 'zatca': return [`${v.waiting ?? 0} waiting`, `${v.rejected ?? 0} rejected`, v.oldestHours != null && `oldest ${v.oldestHours} h`].filter(Boolean).join(', ');
    default: return v.count != null ? String(v.count) : '';
  }
}
