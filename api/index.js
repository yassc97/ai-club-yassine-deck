// Server-side password gate for the AI Club deck.
// Validates password via SHA-256, sets HttpOnly cookie, serves deck only when authed.
// The deck HTML is NEVER returned without a valid cookie.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// SHA-256 of "ai-club-2026". To change the password, recompute:
//   echo -n "NEW_PASSWORD" | shasum -a 256
const PASSWORD_HASH = '284e631139f740ea61eb87ab723ed047286a00f40d658fd7087923ba805486bb';

const COOKIE_NAME = 'deck_auth';
const COOKIE_VALUE = '1';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 30; // 30 days

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const pair of header.split(';')) {
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    out[k] = decodeURIComponent(v);
  }
  return out;
}

function loginPage(opts = {}) {
  const { error = false } = opts;
  return `<!doctype html>
<html lang="fr">
<head>
<meta charset="utf-8">
<title>AI Club x Yassine — Accès</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root{
  --primary-100:#0D261E;--primary-80:#3B504A;--primary-60:#6F8580;--primary-40:#A0B3AD;
  --primary-20:#D2DFDB;--primary-10:#EAF1EE;--primary-5:#F3F7F6;
  --highlight-darkest:#004734;--highlight-dark:#006647;--highlight:#008F63;
  --highlight-medium:#CCE8DF;--highlight-light:#F0FAF6;
  --status-danger:#ED3821;--status-danger-light:#FDECEA;
  --white:#FFFFFF;--extra-yellow:#FFE016;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%;font-family:'Inter',system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased;font-feature-settings:'case' 1}
body{background:linear-gradient(135deg,#001F1D 0%,#0D261E 100%);display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:var(--white);border-radius:16px;padding:48px 44px 36px;max-width:440px;width:100%;box-shadow:0 24px 48px rgba(0,0,0,0.25),0 2px 8px rgba(0,0,0,0.08)}
.badge{display:inline-flex;align-items:center;gap:8px;padding:5px 11px;background:var(--highlight-light);color:var(--highlight-dark);border-radius:999px;font-size:11px;font-weight:600;letter-spacing:.12em;text-transform:uppercase;margin-bottom:24px}
.badge .dot{width:6px;height:6px;background:var(--highlight);border-radius:50%}
h1{font-size:24px;font-weight:700;line-height:1.25;letter-spacing:-.015em;color:var(--primary-100);margin-bottom:8px}
.desc{font-size:14px;color:var(--primary-60);line-height:1.5;margin-bottom:28px;font-weight:500}
.field{margin-bottom:12px}
label{display:block;font-size:11px;font-weight:600;color:var(--primary-80);letter-spacing:.06em;text-transform:uppercase;margin-bottom:8px}
input[type=password]{width:100%;padding:13px 14px;border:1.5px solid var(--primary-20);border-radius:8px;font-size:14px;font-family:inherit;font-weight:500;color:var(--primary-100);outline:none;transition:border-color 0.15s,box-shadow 0.15s;background:var(--white)}
input[type=password]:focus{border-color:var(--highlight);box-shadow:0 0 0 3px rgba(0,143,99,0.12)}
input[type=password]:hover{border-color:var(--primary-40)}
button{width:100%;margin-top:14px;padding:13px;background:var(--highlight-dark);color:var(--white);border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;letter-spacing:.01em;transition:background 0.12s,transform 0.05s}
button:hover{background:var(--highlight-darkest)}
button:active{transform:translateY(1px)}
.error{margin-top:14px;padding:10px 14px;background:var(--status-danger-light);color:var(--status-danger);border-radius:8px;font-size:13px;font-weight:500;text-align:center}
.foot{margin-top:28px;padding-top:20px;border-top:1px solid var(--primary-10);font-size:12px;color:var(--primary-60);text-align:center;line-height:1.5}
.foot b{color:var(--primary-80);font-weight:600}
</style>
</head>
<body>
  <div class="card">
    <span class="badge"><span class="dot"></span>AI Club · Spicy Lemon</span>
    <h1>Accès protégé.</h1>
    <p class="desc">Entrer le mot de passe partagé pour accéder au deck de préparation.</p>
    <form method="POST" action="/">
      <div class="field">
        <label for="password">Mot de passe</label>
        <input type="password" id="password" name="password" autofocus autocomplete="current-password" required>
      </div>
      <button type="submit">Accéder au deck</button>
      ${error ? '<div class="error">Mot de passe incorrect</div>' : ''}
    </form>
    <div class="foot">
      Contact : <b>yassine@themobilefirst.co</b>
    </div>
  </div>
</body>
</html>`;
}

function send(res, status, html, headers = {}) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
  res.end(html);
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

module.exports = async (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const authed = cookies[COOKIE_NAME] === COOKIE_VALUE;

  // POST: validate password
  if (req.method === 'POST') {
    const body = await readBody(req);
    const params = new URLSearchParams(body);
    const pwd = params.get('password') || '';
    const hash = crypto.createHash('sha256').update(pwd).digest('hex');

    if (hash === PASSWORD_HASH) {
      const cookie = `${COOKIE_NAME}=${COOKIE_VALUE}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`;
      res.statusCode = 303;
      res.setHeader('Set-Cookie', cookie);
      res.setHeader('Location', '/');
      res.end();
      return;
    }
    // wrong password
    send(res, 401, loginPage({ error: true }));
    return;
  }

  // GET: if authed, serve deck; else show login
  if (authed) {
    try {
      const deckPath = path.join(process.cwd(), 'deck.html');
      const html = fs.readFileSync(deckPath, 'utf-8');
      send(res, 200, html);
    } catch (err) {
      send(res, 500, `<h1>Erreur de chargement du deck</h1><pre>${String(err.message || err)}</pre>`);
    }
    return;
  }

  send(res, 200, loginPage());
};
