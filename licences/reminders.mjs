// The morning reminder: run by GitHub Actions in the public `app-support` repository every morning
// (`.github/workflows/licence-reminders.yml`, copied from `support/licences/`; steps in docs/licence-renewal.md).
// It opens the seller's list with the secret REGISTER_KEY and emails the seller the shops whose agreement ends within
// 30 days or has ended (not yet stopped for long), and the 7-day unlocks running out. The log is public, so it shows
// only counts, never a shop.
//
// Email settings are GitHub secrets: MAIL_USER (the sending address, for example a Gmail address), MAIL_PASSWORD
// (for Gmail an app password), MAIL_TO (where to send; empty = MAIL_USER), MAIL_HOST and MAIL_PORT (empty = Gmail).

import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { daysBetween, lastPayment, openWith, saudiToday, shopIdText, shopState, STATE_WORDS } from './register.mjs';

/** How long after stopping a shop still shows in the email. */
const STOPPED_SHOWN_DAYS = 30;

/** The shops to remind about on `today`, soonest first. */
export function dueShops(register, today) {
  const rows = [];
  for (const shop of Object.values(register?.shops ?? {})) {
    if (shop.archived) continue;
    const s = shopState(shop, today);
    const recentStop = s.state === 'stopped' && s.daysLeft > -(7 + 30 + STOPPED_SHOWN_DAYS);
    const unlockEnding = s.state === 'unlocked' && daysBetween(today, shop.unlockUntil) <= 2;
    if (['ending', 'grace', 'limited'].includes(s.state) || recentStop || unlockEnding) rows.push({ shop, ...s });
  }
  return rows.sort((a, b) => a.daysLeft - b.daysLeft);
}

const esc = (t) => String(t ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const leftWords = (d) => (d > 0 ? `${d} days left` : d === 0 ? 'last day today' : `ended ${-d} days ago`);

/** The email: subject, plain text and HTML. */
export function reminderEmail(rows, today, pageUrl) {
  const ending = rows.filter((r) => r.daysLeft >= 0).length;
  const ended = rows.length - ending;
  const subject = `Licences: ${ending} ending soon, ${ended} ended (${today})`;
  const line = (r) => {
    const paid = lastPayment(r.shop);
    return [r.shop.name, shopIdText(r.shop.code), r.shop.phone ?? '', `last day ${r.shop.expires}`, leftWords(r.daysLeft), STATE_WORDS[r.state], paid ? `last paid ${paid.amount} on ${paid.paidOn}` : ''].filter(Boolean).join(' · ');
  };
  const text = [`Licences to follow up on ${today}:`, '', ...rows.map(line), '', pageUrl ? `Open the Licences page: ${pageUrl}` : ''].join('\n');
  const cell = 'padding:6px 10px;border-bottom:1px solid #e2e8f0;text-align:left';
  const colour = (r) => (r.daysLeft >= 7 ? '#b45309' : '#b91c1c');
  const html = `<div style="font:14px/1.5 system-ui,sans-serif;color:#1e293b">
<p>Licences to follow up on <b>${esc(today)}</b>: ${ending} ending soon, ${ended} ended.</p>
<table style="border-collapse:collapse">
<tr>${['Shop', 'Shop ID', 'Phone', 'Last day', 'Days', 'State', 'Last paid'].map((h) => `<th style="${cell}">${h}</th>`).join('')}</tr>
${rows
  .map((r) => {
    const paid = lastPayment(r.shop);
    return `<tr><td style="${cell}"><b>${esc(r.shop.name)}</b></td><td style="${cell};font-family:monospace">${esc(shopIdText(r.shop.code))}</td><td style="${cell}">${esc(r.shop.phone)}</td><td style="${cell}">${esc(r.shop.expires)}</td><td style="${cell};color:${colour(r)};font-weight:600">${esc(leftWords(r.daysLeft))}</td><td style="${cell}">${esc(STATE_WORDS[r.state])}</td><td style="${cell}">${paid ? esc(`${paid.amount} on ${paid.paidOn}`) : ''}</td></tr>`;
  })
  .join('\n')}
</table>
${pageUrl ? `<p><a href="${esc(pageUrl)}">Open the Licences page</a></p>` : ''}
</div>`;
  return { subject, text, html };
}

async function main() {
  const listKey = String(process.env.REGISTER_KEY ?? '');
  if (!listKey) return console.log('No REGISTER_KEY secret: nothing to remind about.');
  if (!process.env.MAIL_USER || !process.env.MAIL_PASSWORD) return console.log('No MAIL_USER / MAIL_PASSWORD secrets: no email is sent.');
  const path = 'licences/register.enc';
  if (!existsSync(path)) return console.log('No list yet.');
  const register = await openWith(listKey, readFileSync(path, 'utf8'));
  if (!register) {
    console.log('::error::The list could not be opened with the REGISTER_KEY secret.');
    process.exit(1);
  }
  const today = saudiToday();
  const rows = dueShops(register, today);
  console.log(`${rows.length} shop(s) to remind about.`);
  if (!rows.length) return;
  const [owner, repo] = String(process.env.GITHUB_REPOSITORY ?? '/').split('/');
  const pageUrl = owner && repo ? `https://${owner.toLowerCase()}.github.io/${repo}/licences/` : '';
  const { subject, text, html } = reminderEmail(rows, today, pageUrl);
  const { createTransport } = await import('nodemailer');
  const port = Number(process.env.MAIL_PORT || 465);
  const mail = createTransport({ host: process.env.MAIL_HOST || 'smtp.gmail.com', port, secure: port === 465, auth: { user: process.env.MAIL_USER, pass: process.env.MAIL_PASSWORD } });
  await mail.sendMail({ from: process.env.MAIL_USER, to: process.env.MAIL_TO || process.env.MAIL_USER, subject, text, html });
  console.log('Email sent.');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    await main();
  } catch (err) {
    console.log(`::error::The reminder email could not be sent: ${err.message}`);
    process.exit(1);
  }
}
