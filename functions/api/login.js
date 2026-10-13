const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

async function verifyPassword(password, storedHash) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hash === storedHash;
}

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method === 'OPTIONS') return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
  if (request.method !== 'POST') return new Response(JSON.stringify({ ok: false, msg: 'Method Not Allowed' }), { status: 405, headers: corsHeaders });

  try {
    const body = await request.json();
    const { username, password } = body;
    if (!username || !password) return new Response(JSON.stringify({ ok: false, msg: '请填写用户名和密码' }), { headers: corsHeaders });

    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      return new Response(JSON.stringify({ ok: false, msg: '账号或密码错误' }), { headers: corsHeaders });
    }

    const token = 'sk_' + crypto.randomUUID().replace(/-/g, '');
    await env.DB.prepare('INSERT INTO sessions (token, username, created_at) VALUES (?, ?, ?)').bind(token, username, Date.now()).run();
    return new Response(JSON.stringify({ ok: true, token }), { headers: corsHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, msg: e.message }), { status: 500, headers: corsHeaders });
  }
}
