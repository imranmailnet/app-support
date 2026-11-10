/**
 * The health report collector: a Cloudflare Worker (free plan) with one KV namespace bound as REPORTS and a secret
 * READ_KEY. Shops' servers POST their locked daily report to /report; the seller's Licences page reads them with
 * POST /lookup (Bearer READ_KEY), naming the ids it knows (each worked out from a Shop ID). Reports are locked with
 * the Shop ID before they leave the shop, so this worker only ever holds random-looking text. Setup steps:
 * docs/health-report.md.
 */
const PREFIX = 'MANIHR1.';
const MOST_BYTES = 32_000;
const KEEP = 30;
const SOONEST_MS = 50 * 60_000;
const KEEP_SECONDS = 120 * 86_400;
const MOST_IDS = 2_000;

const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json', ...cors } });
const isId = (id) => typeof id === 'string' && /^[0-9a-f]{64}$/.test(id);

/** Same length strings compared in the same time, so the key can't be guessed letter by letter. */
function sameText(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function report(request, env) {
  const text = await request.text();
  if (text.length > MOST_BYTES) return json({ error: 'too big' }, 413);
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    return json({ error: 'not json' }, 400);
  }
  if (!isId(body?.id) || typeof body.report !== 'string' || !body.report.startsWith(PREFIX) || !/^[A-Za-z0-9_.-]+$/.test(body.report)) return json({ error: 'not a report' }, 400);
  const key = `r:${body.id}`;
  const old = await env.REPORTS.get(key, 'json');
  const now = Date.now();
  if (old?.at && now - Date.parse(old.at) < SOONEST_MS) return json({ ok: true, kept: false }, 429);
  const history = [{ at: new Date(now).toISOString(), report: body.report }, ...(old?.history ?? [])].slice(0, KEEP);
  await env.REPORTS.put(key, JSON.stringify({ at: history[0].at, history }), { expirationTtl: KEEP_SECONDS });
  return json({ ok: true, kept: true });
}

async function lookup(request, env) {
  const auth = request.headers.get('Authorization') ?? '';
  if (!env.READ_KEY || !sameText(auth, `Bearer ${env.READ_KEY}`)) return json({ error: 'wrong key' }, 401);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'not json' }, 400);
  }
  const ids = Array.isArray(body?.ids) ? [...new Set(body.ids.filter(isId))].slice(0, MOST_IDS) : [];
  const out = {};
  for (let i = 0; i < ids.length; i += 50) {
    const part = ids.slice(i, i + 50);
    const rows = await Promise.all(part.map((id) => env.REPORTS.get(`r:${id}`, 'json')));
    part.forEach((id, n) => {
      const row = rows[n];
      if (row) out[id] = body.history ? row.history : row.history.slice(0, 1);
    });
  }
  return json({ reports: out });
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    try {
      if (request.method === 'POST' && pathname === '/report') return await report(request, env);
      if (request.method === 'POST' && pathname === '/lookup') return await lookup(request, env);
      if (request.method === 'GET' && pathname === '/') return json({ ok: true, what: 'health report collector' });
    } catch (err) {
      return json({ error: String(err?.message ?? err) }, 500);
    }
    return json({ error: 'not found' }, 404);
  },
};
