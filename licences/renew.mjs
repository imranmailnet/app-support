// The "Renew licence" form's work, run by GitHub Actions in the public `app-support` repository
// (`.github/workflows/renew-licence.yml`, copied from `support/licences/` of the app's repository; steps in
// `docs/licence-renewal.md`).
//
// It makes a shop's new licence key (or a 7-day unlock code), signed with the seller's signing key (the GitHub
// secret LICENSE_SIGNING_KEY, the same line as in SIGNING-KEY-KEEP-SECRET.txt), seals it with the shop's Shop ID
// and writes it to licences/<file>.txt, where every shop's server looks every few hours. The run's summary shows
// the same sealed text as the "offline code" to paste on a shop with no internet.
//
// The repository is public, so nothing here names a shop: the file name and the sealed text are worked out from
// the Shop ID, and the Shop ID and name typed in the form are hidden in the run's log. With the secret REGISTER_KEY
// it also keeps the seller's list of shops (licences/register.enc, locked with that password, register.mjs), and
// takes requests from the Licences page (index.html) locked with the same password in the `request` box. The sums are the same as
// `packages/shared/src/license.ts` and `support.ts` (a test there checks they agree).

import { createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, randomBytes, sign } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { emptyRegister, lockWith, openWith, REQUEST_PREFIX } from './register.mjs';

/** The parts of the app a licence can include (FEATURES in the app) and the plans (LICENSE_PLANS). */
export const FEATURES = ['repairs', 'manufacturing', 'hr', 'whatsapp', 'vehicles'];
export const PLANS = ['full', 'standard', 'basic'];
/** How long an unlock code runs (UNLOCK_MOST_DAYS in the app). */
export const UNLOCK_DAYS = 7;

const LETTERS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const PREFIX = 'MANILIC1.';
const sha = (data) => createHash('sha256').update(data).digest();

export const cleanCode = (text) => String(text ?? '').toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1').replace(/[^0-9A-Z]/g, '');

/** The file name of a shop's online licence. */
export const fileName = (code) => `${sha(`licence-file:${code}`).subarray(0, 16).toString('hex')}.txt`;

/** Seals what the file holds ({ key, unlock }) with the Shop ID. */
export function seal(code, content) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', sha(`licence-seal:${code}`), iv);
  const body = Buffer.concat([cipher.update(JSON.stringify(content), 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return PREFIX + Buffer.concat([iv, body]).toString('base64url');
}

/** Opens a sealed text, or null. */
export function unseal(code, text) {
  const clean = String(text).replace(/\s+/g, '');
  if (!clean.startsWith(PREFIX)) return null;
  try {
    const bytes = Buffer.from(clean.slice(PREFIX.length), 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', sha(`licence-seal:${code}`), bytes.subarray(0, 12));
    decipher.setAuthTag(bytes.subarray(bytes.length - 16));
    return JSON.parse(Buffer.concat([decipher.update(bytes.subarray(12, bytes.length - 16)), decipher.final()]).toString('utf8'));
  } catch {
    return null;
  }
}

/** Signs terms with the signing key's 32-byte seed: "<terms>.<signature>", as the key maker does. */
export function signTerms(seed, terms) {
  const body = Buffer.from(JSON.stringify(terms), 'utf8');
  const key = createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' });
  return `${body.toString('base64url')}.${sign(null, body, key).toString('base64url')}`;
}

export const termsOf = (key) => {
  try {
    return JSON.parse(Buffer.from(String(key).split('.')[0], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
};

// The support secret, as the key maker puts it in every key (support.ts).
export const supportSecret = (seed, code) => createHmac('sha256', seed).update(`support-secret:${code}`).digest();
export const wrapSecret = (secret, code) => {
  const mask = sha(`support-wrap:${code}`);
  return Buffer.from(secret.map((b, i) => b ^ mask[i])).toString('base64url');
};
export const supportFile = (seed) => [...sha(Buffer.concat([Buffer.from('support-file:'), seed])).subarray(0, 4)].map((b) => LETTERS[b & 31]).join('');

const DAY = 86_400_000;
const addDays = (date, days) => new Date(Date.parse(`${date}T00:00:00Z`) + days * DAY).toISOString().slice(0, 10);
/** A year from `start`: the day before the same date next year. */
const yearFrom = (start) => {
  const d = new Date(`${start}T00:00:00Z`);
  d.setUTCFullYear(d.getUTCFullYear() + 1);
  d.setUTCDate(d.getUTCDate() - 1);
  return d.toISOString().slice(0, 10);
};
const saudiToday = (now) => new Date(now + 3 * 3_600_000).toISOString().slice(0, 10);

export class Stop extends Error {}

function limitFrom(text, before) {
  const v = String(text ?? '').trim().toLowerCase();
  if (!v) return before ?? null;
  if (v === '0' || v === 'none' || v === 'no limit') return null;
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1) throw new Stop(`"${text}" is not a number. Type a whole number, 0 for no limit, or leave it empty to keep it as it is.`);
  return n;
}

function featuresFrom(text, before) {
  const v = String(text ?? '').trim().toLowerCase();
  if (!v) return before ?? [...FEATURES];
  if (v === 'all') return [...FEATURES];
  if (v === 'none') return [];
  const list = v.split(/[\s,]+/).filter(Boolean);
  const wrong = list.filter((f) => !FEATURES.includes(f));
  if (wrong.length) throw new Stop(`Unknown part "${wrong.join(', ')}". Use: ${FEATURES.join(', ')}, all or none.`);
  return FEATURES.filter((f) => list.includes(f));
}

/**
 * Works out the shop's new file. `inputs` are the form's boxes, `existing` what its file held before (or null).
 * Returns the content to seal and the lines for the run's summary (which never name the shop).
 */
export function renew({ seed, inputs, existing, now = Date.now() }) {
  const code = cleanCode(inputs.shop);
  if (code.length !== 12 || [...code].some((c) => !LETTERS.includes(c))) throw new Stop('The Shop ID has 12 letters and digits, like ABCD-EFGH-JKMN. Copy it from the shop\'s Licence page.');
  const today = saudiToday(now);
  const old = existing?.key ? termsOf(existing.key) : null;
  const action = String(inputs.action ?? '');

  if (action.startsWith('7-day')) {
    const unlock = { v: 1, kind: 'unlock', no: `U-${today.replace(/-/g, '')}-${code.slice(0, 4)}`, for: code, issued: today, until: addDays(today, UNLOCK_DAYS) };
    const content = { ...(existing?.key ? { key: existing.key } : {}), unlock: signTerms(seed, unlock) };
    return { code, content, summary: [`7-day unlock code until ${unlock.until} (the last day it works).`] };
  }

  let expires;
  if (action.startsWith('Renew for 1 year')) {
    // Renewing early adds the year after the current last day, so no days are lost.
    const start = old?.expires && old.expires >= today ? addDays(old.expires, 1) : today;
    expires = yearFrom(start);
  } else if (action.startsWith('Renew until')) {
    expires = String(inputs.until ?? '').trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expires) || Number.isNaN(Date.parse(`${expires}T00:00:00Z`))) throw new Stop('Type the last day as year-month-day, for example 2027-12-31.');
    if (expires < today) throw new Stop('The last day is in the past.');
  } else if (action.startsWith('No end')) {
    expires = null;
  } else {
    if (!old) throw new Stop('This shop has no online licence yet. Choose "Renew for 1 year" or "Renew until the date below", and type the shop\'s name.');
    expires = old.expires ?? null;
  }

  const holder = String(inputs.name ?? '').trim() || old?.holder;
  if (!holder) throw new Stop('This is the shop\'s first online licence: type its name in "Shop name".');
  const plan = !inputs.plan || inputs.plan === 'keep' ? (old?.plan ?? 'full') : inputs.plan;
  if (!PLANS.includes(plan)) throw new Stop(`Unknown plan "${inputs.plan}".`);

  const terms = {
    v: 1,
    no: `L-${today.replace(/-/g, '')}-${code.slice(0, 4)}`,
    for: code,
    holder: holder.slice(0, 200),
    issued: today,
    made: new Date(now).toISOString(),
    expires,
    plan,
    branches: limitFrom(inputs.branches, old?.branches),
    pos: limitFrom(inputs.pos, old?.pos),
    users: limitFrom(inputs.users, old?.users),
    features: featuresFrom(inputs.features, old?.features),
    support: wrapSecret(supportSecret(seed, code), code),
    supportFile: supportFile(seed),
  };
  const limit = (n) => (n == null ? 'no limit' : String(n));
  return {
    code,
    // A renewal replaces any unlock code: the shop is open again by its key.
    content: { key: signTerms(seed, terms) },
    summary: [
      `Licence until ${expires ?? 'no end date'}, plan ${plan}.`,
      `Branches ${limit(terms.branches)}, POS counters ${limit(terms.pos)}, users ${limit(terms.users)}.`,
      `Extra parts: ${terms.features.length ? terms.features.join(', ') : 'none'}.`,
    ],
  };
}

/** Actions that change no licence: they only add a shop to the list, change its details or note a payment. */
export const LIST_ONLY = ['Add to list only (no change)', 'Edit details only', 'Record payment only'];
const listOnly = (action) => LIST_ONLY.includes(String(action ?? ''));

const DETAIL_FIELDS = ['name', 'vat', 'contact', 'phone', 'city', 'notes', 'archived'];

/**
 * Brings the seller's list up to date after a run: the shop's licence as its file now holds it, the details typed,
 * one line of history (with the payment, when one was typed) and the offline code. Returns the list.
 */
export function updateRegister({ register, code, action, before, after, sealed, details = {}, payment = null, summary = [], by = null, rid = null, now = Date.now() }) {
  const list = register ?? emptyRegister();
  const at = new Date(now).toISOString();
  const known = list.shops[code];
  if (!known && action === 'Record payment only') throw new Stop('This shop is not on the list yet. Add it first.');
  const shop = known ?? { code, addedAt: at, history: [], unlocks: 0 };
  const key = after?.key ? termsOf(after.key) : null;
  if (key) {
    shop.name = key.holder ?? shop.name;
    for (const f of ['plan', 'branches', 'pos', 'users', 'features', 'expires', 'issued']) shop[f] = key[f] ?? null;
    shop.keyNo = key.no;
  }
  const unlock = after?.unlock ? termsOf(after.unlock) : null;
  if (unlock && after.unlock !== before?.unlock) {
    shop.unlockUntil = unlock.until;
    shop.unlocks = (shop.unlocks ?? 0) + 1;
  } else if (!after?.unlock) shop.unlockUntil = null;
  for (const f of DETAIL_FIELDS) {
    const v = details[f];
    if (v === undefined || v === null) continue;
    shop[f] = typeof v === 'string' ? v.trim().slice(0, f === 'notes' ? 2000 : 200) : v;
  }
  if (!shop.name) throw new Stop('Type the shop\'s name.');
  if (sealed) shop.offlineCode = sealed;
  shop.online = !!after?.key || !!after?.unlock || !!shop.online;
  const money = payment && String(payment.amount ?? '').trim() !== '' ? Number(payment.amount) : null;
  if (money != null && !(Number.isFinite(money) && money >= 0)) throw new Stop('The amount paid is not a number.');
  const line = { at, by, action, text: summary.join(' '), rid };
  if (money != null) Object.assign(line, { amount: Math.round(money * 100) / 100, paidOn: String(payment.paidOn ?? '').trim() || at.slice(0, 10), receipt: String(payment.receipt ?? '').trim().slice(0, 60), note: String(payment.note ?? '').trim().slice(0, 300) });
  shop.history = [...(shop.history ?? []), line].slice(-200);
  shop.updatedAt = at;
  list.shops[code] = shop;
  list.updated = at;
  list.lastRequest = rid;
  return list;
}

async function main() {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  const say = (text) => (summaryFile ? appendFileSync(summaryFile, `${text}\n`) : console.log(text));
  try {
    const event = JSON.parse(readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    let inputs = event.inputs ?? {};
    const listKey = String(process.env.REGISTER_KEY ?? '');
    // From the Licences page: everything comes locked with the list password, so the run's inputs say nothing.
    const fromPage = !!String(inputs.request ?? '').trim();
    let request = null;
    if (fromPage) {
      if (!listKey) throw new Stop('The list password is missing. Add the secret REGISTER_KEY (Settings, Secrets and variables, Actions).');
      request = await openWith(listKey, inputs.request, REQUEST_PREFIX);
      if (!request) throw new Stop('The request could not be opened: the password typed on the Licences page is not the same as the REGISTER_KEY secret.');
      inputs = request.inputs ?? {};
    }
    // The repository is public: the shop's ID and name never show in the log.
    for (const secret of [inputs.shop, cleanCode(inputs.shop), inputs.name]) if (secret && String(secret).trim()) console.log(`::add-mask::${String(secret).trim()}`);
    const seed = Buffer.from(String(process.env.SIGNING_KEY ?? '').trim(), 'base64url');
    if (seed.length !== 32) throw new Stop('The signing key is missing or wrong. Add the secret LICENSE_SIGNING_KEY (Settings, Secrets and variables, Actions) with the long line from SIGNING-KEY-KEEP-SECRET.txt.');
    const code = cleanCode(inputs.shop);
    if (code.length !== 12 || [...code].some((c) => !LETTERS.includes(c))) throw new Stop('The Shop ID has 12 letters and digits, like ABCD-EFGH-JKMN. Copy it from the shop\'s Licence page.');
    const path = `licences/${fileName(code)}`;
    let existing = null;
    if (existsSync(path)) {
      existing = unseal(code, readFileSync(path, 'utf8'));
      if (!existing) throw new Stop('This shop\'s licence file could not be opened. Check the Shop ID.');
    }

    // The list, when the seller keeps one.
    const registerPath = 'licences/register.enc';
    let register = null;
    if (listKey) {
      register = existsSync(registerPath) ? await openWith(listKey, readFileSync(registerPath, 'utf8')) : emptyRegister();
      if (!register) throw new Stop('The list (register.enc) could not be opened with the REGISTER_KEY secret. Put back the password it was made with.');
    }
    if (listOnly(inputs.action) && !register) throw new Stop('Keeping a list needs the secret REGISTER_KEY (Settings, Secrets and variables, Actions).');

    let result = null;
    let sealed = null;
    if (!listOnly(inputs.action)) {
      result = renew({ seed, inputs, existing });
      sealed = seal(result.code, result.content);
      mkdirSync('licences', { recursive: true });
      writeFileSync(path, `${sealed}\n`);
    }
    if (register) {
      const details = { ...(request?.details ?? {}) };
      if (!fromPage && String(inputs.name ?? '').trim()) details.name = inputs.name;
      if (details.name === undefined && listOnly(inputs.action) && existing?.key) details.name = termsOf(existing.key)?.holder;
      const updated = updateRegister({
        register,
        code,
        action: inputs.action,
        before: existing,
        after: result ? result.content : existing,
        sealed,
        details,
        payment: request?.payment ?? null,
        summary: result?.summary ?? [],
        by: process.env.GITHUB_ACTOR ?? null,
        rid: request?.rid ?? null,
      });
      writeFileSync(registerPath, `${await lockWith(listKey, updated)}\n`);
    }

    say('## Done');
    if (fromPage) {
      // The page reads the result from the locked list; the public summary says nothing about the shop.
      say('');
      say('Open the Licences page to see it.');
      return;
    }
    for (const line of result?.summary ?? ['Added to the list. The licence is as it was.']) say(`- ${line}`);
    if (!sealed) return;
    say('');
    say('The shop\'s server picks it up by itself within a few hours (or at once with **Check now** on its Licence page).');
    say('If the shop has no internet, send it this code to paste on its Licence page:');
    say('');
    say('```');
    say(sealed);
    say('```');
  } catch (err) {
    const message = err instanceof Stop ? err.message : `Something went wrong: ${err.message}`;
    console.log(`::error::${message}`);
    say(`## Not done\n\n${message}`);
    process.exit(1);
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) await main();
