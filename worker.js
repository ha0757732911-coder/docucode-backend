// ===== CORS HEADERS =====
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

async function hashPassword(password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, km, 256
  );
  return JSON.stringify({ h: [...new Uint8Array(bits)], s: [...salt] });
}

async function checkPassword(password, stored) {
  const { h, s } = JSON.parse(stored);
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new Uint8Array(s), iterations: 100000, hash: 'SHA-256' }, km, 256
  );
  const newH = [...new Uint8Array(bits)];
  return h.length === newH.length && h.every((b, i) => b === newH[i]);
}

function b64(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64buf(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function makeToken(payload, secret) {
  const enc = new TextEncoder();
  const h = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const p = b64(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${h}.${p}`));
  return `${h}.${p}.${b64buf(sig)}`;
}

async function readToken(token, secret) {
  try {
    const [h, p, s] = token.split('.');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sigBytes = Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const ok = await crypto.subtle.verify('HMAC', key, sigBytes, enc.encode(`${h}.${p}`));
    if (!ok) return null;
    return JSON.parse(atob(p.replace(/-/g, '+').replace(/_/g, '/')));
  } catch { return null; }
}

async function getAuthUser(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token || token === 'guest') return null;
  return readToken(token, env.JWT_SECRET);
}

async function handleRegister(request, env) {
  const { email, password } = await request.json();
  if (!email || !password) return json({ error: 'Email and password are required' }, 400);
  if (password.length < 6) return json({ error: 'Password must be at least 6 characters' }, 400);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(email.toLowerCase()).first();
  if (existing) return json({ error: 'This email is already registered' }, 400);

  const hash = await hashPassword(password);
  const result = await env.DB.prepare(
    'INSERT INTO users (email, password_hash) VALUES (?, ?) RETURNING id, role'
  ).bind(email.toLowerCase(), hash).first();

  const token = await makeToken({ id: result.id, role: result.role }, env.JWT_SECRET);
  return json({ token, email: email.toLowerCase(), role: result.role });
}

async function handleLogin(request, env) {
  const { email, password } = await request.json();
  if (!email || !password) return json({ error: 'Email and password are required' }, 400);

  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?')
    .bind(email.toLowerCase()).first();
  if (!user) return json({ error: 'Invalid email or password' }, 401);

  const ok = await checkPassword(password, user.password_hash);
  if (!ok) return json({ error: 'Invalid email or password' }, 401);

  const token = await makeToken({ id: user.id, role: user.role }, env.JWT_SECRET);
  return json({ token, email: user.email, role: user.role });
}

async function handleDocument(request, env) {
  const user = await getAuthUser(request, env);
  if (!user) return json({ error: 'Please log in to generate documentation' }, 401);

  const { code, style = 'pep257', fileName = 'untitled.py' } = await request.json();
  if (!code?.trim()) return json({ error: 'No code provided' }, 400);

  const styleName = style === 'google' ? 'Google style' : 'PEP 257';
  const prompt = `You are a Python documentation expert. Your task is to add ${styleName} docstrings and helpful inline comments to the Python code below.

Important rules:
- Keep ALL original code lines exactly as they are
- Only ADD docstrings (triple-quoted strings) and # comments
- Never remove or change any existing logic
- Return ONLY the Python code, no explanation, no markdown, no backticks

Python code:
${code}`;

  const aiRes = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${env.GEMINI_API_KEY}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
    }
  );

  if (!aiRes.ok) {
    const errText = await aiRes.text();
    return json({ error: 'AI service failed: ' + errText }, 500);
  }

  const aiData = await aiRes.json();
  let documentedCode = aiData.candidates?.[0]?.content?.parts?.[0]?.text || '';
  documentedCode = documentedCode.replace(/^```python\n?/, '').replace(/\n?```$/, '').trim();

  await env.DB.prepare(
    'INSERT INTO history (user_id, file_name, original_code, documented_code, style) VALUES (?, ?, ?, ?, ?)'
  ).bind(user.id, fileName, code, documentedCode, style).run();

  return json({ documentedCode });
}

async function handleGetHistory(request, env) {
  const user = await getAuthUser(request, env);
  if (!user) return json({ error: 'Please log in' }, 401);

  const { results } = await env.DB.prepare(
    'SELECT id, file_name, style, original_code, documented_code, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
  ).bind(user.id).all();

  return json(results || []);
}

async function handleDeleteHistory(request, env, id) {
  const user = await getAuthUser(request, env);
  if (!user) return json({ error: 'Please log in' }, 401);

  await env.DB.prepare('DELETE FROM history WHERE id = ? AND user_id = ?')
    .bind(parseInt(id), user.id).run();
  return json({ success: true });
}

async function handleAdminUsers(request, env) {
  const user = await getAuthUser(request, env);
  if (!user || user.role !== 'admin') return json({ error: 'Admins only' }, 403);

  const { results } = await env.DB.prepare(
    'SELECT id, email, role, created_at FROM users ORDER BY created_at DESC'
  ).all();
  return json(results || []);
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/api/auth/register' && request.method === 'POST')
        return handleRegister(request, env);
      if (path === '/api/auth/login' && request.method === 'POST')
        return handleLogin(request, env);
      if (path === '/api/document' && request.method === 'POST')
        return handleDocument(request, env);
      if (path === '/api/history' && request.method === 'GET')
        return handleGetHistory(request, env);
      if (path === '/api/admin/users' && request.method === 'GET')
        return handleAdminUsers(request, env);

      const delMatch = path.match(/^\/api\/history\/(\d+)$/);
      if (delMatch && request.method === 'DELETE')
        return handleDeleteHistory(request, env, delMatch[1]);

      return json({ status: 'DocuCode API is running!' });
    } catch (err) {
      console.error(err);
      return json({ error: String(err.message) }, 500);
    }
  }
};
