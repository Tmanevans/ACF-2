// ACF pass checker. Runs on Netlify's server, so the list below is never sent to visitors.
// ===== APPROVED LIST: one per line, "email, Name to print on the pass" =====
const APPROVED_LIST = `
demo@acf.test, Demo Guest
`;
// ===========================================================================
const crypto = require("crypto");

const approved = new Map();
for (const raw of APPROVED_LIST.split("\n")) {
  const line = raw.trim();
  if (!line || line.startsWith("#")) continue;
  const i = line.indexOf(",");
  if (i < 1) continue;
  const email = line.slice(0, i).trim().toLowerCase();
  const name = line.slice(i + 1).trim();
  if (email && name) approved.set(email, name);
}

// Best-effort limit on guessing (per server instance)
const hits = new Map();
function limited(ip) {
  const now = Date.now(), win = 10 * 60 * 1000;
  const arr = (hits.get(ip) || []).filter(t => now - t < win);
  arr.push(now); hits.set(ip, arr);
  return arr.length > 25;
}

const json = (statusCode, obj) => ({
  statusCode,
  headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  body: JSON.stringify(obj),
});

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return json(405, { error: "method_not_allowed" });
  const ip = (event.headers["x-nf-client-connection-ip"] || event.headers["x-forwarded-for"] || "").split(",")[0].trim();
  if (limited(ip)) return json(429, { error: "too_many_requests" });

  let email = "";
  try { email = String(JSON.parse(event.body || "{}").email || "").trim().toLowerCase(); } catch (e) {}
  if (!/^\S+@\S+\.\S+$/.test(email) || email.length > 200) return json(400, { error: "invalid_email" });

  const name = approved.get(email);
  if (!name) {
    await new Promise(r => setTimeout(r, 400));
    return json(404, { error: "not_approved" });
  }
  // Pass ID: signed with PASS_SECRET (set in Netlify) so it can't be guessed or forged
  const secret = process.env.PASS_SECRET || "acf-2026";
  const code = "ACF26-" + crypto.createHmac("sha256", secret).update(email).digest("hex").slice(0, 6).toUpperCase();
  return json(200, { name, code });
};
