// functions/[[path]].js

const TOTP = {
  async generateSecret() {
    const bytes = crypto.getRandomValues(new Uint8Array(20));
    return btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '').replace(/\//g, '');
  },
  async generateTOTP(secret, window = 0) {
    const key = Uint8Array.from(atob(secret), c => c.charCodeAt(0));
    const epoch = Math.floor(Date.now() / 30000) + window;
    const msg = new Uint8Array(8);
    for (let i = 7; i >= 0; i--) { msg[i] = epoch & 0xff; epoch >>>= 8; }
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, msg));
    const offset = sig[19] & 0xf;
    const code = ((sig[offset] & 0x7f) << 24 | (sig[offset + 1] << 16) | (sig[offset + 2] << 8) | sig[offset + 3]) % 1000000;
    return code.toString().padStart(6, '0');
  },
  async verify(secret, token) { return token === await this.generateTOTP(secret); }
};

const AES_KEY = (env) => {
  const raw = env.WORKER + ':default';
  return crypto.subtle.importKey('raw', new TextEncoder().encode(raw).slice(0, 32), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
};

async function encryptTOTP(secret, env) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await AES_KEY(env);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(secret));
  return btoa(String.fromCharCode(...iv)) + '.' + btoa(String.fromCharCode(...new Uint8Array(ct)));
}

async function decryptTOTP(cipher, env) {
  const [ivB64, ctB64] = cipher.split('.');
  const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
  const ct = Uint8Array.from(atob(ctB64), c => c.charCodeAt(0));
  const key = await AES_KEY(env);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}

function makeSession() { return crypto.randomUUID(); }

async function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' } });
}

async function getBody(req) {
  try { return await req.json(); } catch { return {}; }
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method;

  if (method === 'OPTIONS') return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' } });

  // ---------- /auth/start ----------
  if (pathname === '/auth/start' && method === 'GET') {
    const state = crypto.randomUUID();
    await env.USERS.put('oauth_state:' + state, '1', { expirationTtl: 600 });
    const redirect = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(url.origin + '/auth/callback')}&state=${state}&scope=read:user`;
    return Response.redirect(redirect, 302);
  }

  // ---------- /auth/callback ----------
  if (pathname === '/auth/callback' && method === 'GET') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!code || !state) return json({ ok: false, msg: '参数缺失' }, 400);
    const stateValid = await env.USERS.get('oauth_state:' + state);
    if (!stateValid) return json({ ok: false, msg: 'state 无效或过期' }, 400);
    await env.USERS.delete('oauth_state:' + state);

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: url.origin + '/auth/callback' })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return json({ ok: false, msg: 'GitHub token 获取失败' }, 400);

    const userRes = await fetch('https://api.github.com/user', { headers: { 'Authorization': `token ${tokenData.access_token}` } });
    const ghUser = await userRes.json();

    let user = await env.DB.prepare('SELECT * FROM users WHERE github_id = ?').bind(String(ghUser.id)).first();
    if (!user) {
      const username = ghUser.login + '_gh';
      const password = crypto.randomUUID();
      const hashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashHex = Array.from(new Uint8Array(hashed)).map(b => b.toString(16).padStart(2, '0')).join('');
      await env.DB.prepare('INSERT INTO users (username, password_hash, github_id, created_at) VALUES (?, ?, ?, ?)').bind(username, hashHex, String(ghUser.id), Date.now()).run();
      user = { username, github_id: String(ghUser.id) };
    }

    const session = makeSession();
    await env.USERS.put('session:' + session, JSON.stringify({ username: user.username, github_id: user.github_id }), { expirationTtl: 2592000 });
    return Response.redirect(url.origin + '/?session=' + session, 302);
  }

  // ---------- /api/register ----------
  if (pathname === '/api/register' && method === 'POST') {
    const { username, password } = await getBody(request);
    if (!username || !password) return json({ ok: false, msg: '用户名和密码不能为空' }, 400);
    if (username.length < 3 || username.length > 32) return json({ ok: false, msg: '用户名长度 3-32' }, 400);
    const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
    if (existing) return json({ ok: false, msg: '用户名已存在' }, 409);
    const hashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
    const hashHex = Array.from(new Uint8Array(hashed)).map(b => b.toString(16).padStart(2, '0')).join('');
    await env.DB.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)').bind(username, hashHex, Date.now()).run();
    return json({ ok: true, msg: '注册成功' });
  }

  // ---------- /api/login ----------
  if (pathname === '/api/login' && method === 'POST') {
    const { username, password, totp } = await getBody(request);
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user) return json({ ok: false, msg: '用户不存在' }, 401);
    const hashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
    const hashHex = Array.from(new Uint8Array(hashed)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (hashHex !== user.password_hash) return json({ ok: false, msg: '密码错误' }, 401);
    if (user.totp_secret_encrypted) {
      if (!totp) return json({ ok: false, msg: '需要2FA验证码', need_totp: true }, 401);
      const secret = await decryptTOTP(user.totp_secret_encrypted, env);
      if (!await TOTP.verify(secret, totp)) return json({ ok: false, msg: '2FA验证码错误' }, 401);
    }
    const session = makeSession();
    await env.USERS.put('session:' + session, JSON.stringify({ username: user.username }), { expirationTtl: 2592000 });
    return json({ ok: true, msg: '登录成功', session });
  }

  // ---------- /api/me ----------
  if (pathname === '/api/me' && method === 'GET') {
    const session = request.headers.get('X-Session') || url.searchParams.get('session');
    if (!session) return json({ ok: false, msg: '未登录' }, 401);
    const data = await env.USERS.get('session:' + session);
    if (!data) return json({ ok: false, msg: 'session过期' }, 401);
    const u = JSON.parse(data);
    const user = await env.DB.prepare('SELECT username, github_id IS NOT NULL as has_github, totp_secret_encrypted IS NOT NULL as totp_enabled FROM users WHERE username = ?').bind(u.username).first();
    return json({ ok: true, user });
  }

  // ---------- /api/totp/setup ----------
  if (pathname === '/api/totp/setup' && method === 'POST') {
    const session = request.headers.get('X-Session');
    if (!session) return json({ ok: false, msg: '未登录' }, 401);
    const data = await env.USERS.get('session:' + session);
    if (!data) return json({ ok: false, msg: 'session过期' }, 401);
    const { username } = JSON.parse(data);
    const secret = await TOTP.generateSecret();
    const encrypted = await encryptTOTP(secret, env);
    await env.DB.prepare('UPDATE users SET totp_secret_encrypted = ? WHERE username = ?').bind(encrypted, username).run();
    const otpauth = `otpauth://totp/AI-CHAT:${username}?secret=${secret}&issuer=AI-CHAT`;
    return json({ ok: true, secret, otpauth });
  }

  // ---------- /api/totp/verify ----------
  if (pathname === '/api/totp/verify' && method === 'POST') {
    const session = request.headers.get('X-Session');
    if (!session) return json({ ok: false, msg: '未登录' }, 401);
    const data = await env.USERS.get('session:' + session);
    if (!data) return json({ ok: false, msg: 'session过期' }, 401);
    const { username } = JSON.parse(data);
    const { totp: code } = await getBody(request);
    const user = await env.DB.prepare('SELECT totp_secret_encrypted FROM users WHERE username = ?').bind(username).first();
    if (!user || !user.totp_secret_encrypted) return json({ ok: false, msg: '未绑定2FA' }, 400);
    const secret = await decryptTOTP(user.totp_secret_encrypted, env);
    if (!await TOTP.verify(secret, code)) return json({ ok: false, msg: '验证码错误' }, 401);
    await env.DB.prepare('UPDATE users SET totp_verified = 1 WHERE username = ?').bind(username).run();
    return json({ ok: true, msg: '2FA验证成功' });
  }

  // ---------- /api/change-password ----------
  if (pathname === '/api/change-password' && method === 'POST') {
    const session = request.headers.get('X-Session');
    if (!session) return json({ ok: false, msg: '未登录' }, 401);
    const data = await env.USERS.get('session:' + session);
    if (!data) return json({ ok: false, msg: 'session过期' }, 401);
    const { username } = JSON.parse(data);
    const { old_password, new_password, totp: code } = await getBody(request);
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user) return json({ ok: false, msg: '用户不存在' }, 401);
    const oldHashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(old_password));
    const oldHex = Array.from(new Uint8Array(oldHashed)).map(b => b.toString(16).padStart(2, '0')).join('');
    if (oldHex !== user.password_hash) return json({ ok: false, msg: '旧密码错误' }, 401);
    if (user.totp_secret_encrypted) {
      if (!code) return json({ ok: false, msg: '需要2FA验证码' }, 401);
      const secret = await decryptTOTP(user.totp_secret_encrypted, env);
      if (!await TOTP.verify(secret, code)) return json({ ok: false, msg: '2FA验证码错误' }, 401);
    }
    const newHashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(new_password));
    const newHex = Array.from(new Uint8Array(newHashed)).map(b => b.toString(16).padStart(2, '0')).join('');
    await env.DB.prepare('UPDATE users SET password_hash = ? WHERE username = ?').bind(newHex, username).run();
    return json({ ok: true, msg: '密码修改成功' });
  }

  // ---------- /api/change-username ----------
  if (pathname === '/api/change-username' && method === 'POST') {
    const session = request.headers.get('X-Session');
    if (!session) return json({ ok: false, msg: '未登录' }, 401);
    const data = await env.USERS.get('session:' + session);
    if (!data) return json({ ok: false, msg: 'session过期' }, 401);
    const { username: oldUsername } = JSON.parse(data);
    const { new_username } = await getBody(request);
    if (!new_username || new_username.length < 3 || new_username.length > 32) return json({ ok: false, msg: '用户名长度 3-32' }, 400);
    const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(new_username).first();
    if (existing) return json({ ok: false, msg: '用户名已被使用' }, 409);
    await env.DB.prepare('UPDATE users SET username = ? WHERE username = ?').bind(new_username, oldUsername).run();
    await env.USERS.put('session:' + session, JSON.stringify({ username: new_username }), { expirationTtl: 2592000 });
    return json({ ok: true, msg: '用户名修改成功' });
  }

  // ---------- /api/apikeys ----------
  if (pathname === '/api/apikeys' && method === 'GET') {
    const session = request.headers.get('X-Session');
    if (!session) return json({ ok: false, msg: '未登录' }, 401);
    const data = await env.USERS.get('session:' + session);
    if (!data) return json({ ok: false, msg: 'session过期' }, 401);
    const { username } = JSON.parse(data);
    const keys = await env.DB.prepare('SELECT id, name, created_at, last_used FROM api_keys WHERE username = ?').bind(username).all();
    return json({ ok: true, keys: keys.results || [] });
  }

  if (pathname === '/api/apikeys' && method === 'POST') {
    const session = request.headers.get('X-Session');
    if (!session) return json({ ok: false, msg: '未登录' }, 401);
    const data = await env.USERS.get('session:' + session);
    if (!data) return json({ ok: false, msg: 'session过期' }, 401);
    const { username } = JSON.parse(data);
    const { name } = await getBody(request);
    const key = 'ak_' + crypto.randomUUID().replace(/-/g, '');
    await env.DB.prepare('INSERT INTO api_keys (username, key, name, created_at) VALUES (?, ?, ?, ?)').bind(username, key, name || 'default', Date.now()).run();
    return json({ ok: true, key });
  }

  // ---------- /api/gift/redeem ----------
  if (pathname === '/api/gift/redeem' && method === 'POST') {
    const session = request.headers.get('X-Session');
    if (!session) return json({ ok: false, msg: '未登录' }, 401);
    const data = await env.USERS.get('session:' + session);
    if (!data) return json({ ok: false, msg: 'session过期' }, 401);
    const { username } = JSON.parse(data);
    const { code } = await getBody(request);
    const gift = await env.DB.prepare('SELECT * FROM gift_codes WHERE code = ? AND (expires_at IS NULL OR expires_at > ?)').bind(code, Date.now()).first();
    if (!gift) return json({ ok: false, msg: '礼品码无效或已过期' }, 400);
    const already = await env.DB.prepare('SELECT id FROM gift_redeem WHERE username = ? AND code = ?').bind(username, code).first();
    if (already) return json({ ok: false, msg: '已使用过该礼品码' }, 409);
    await env.DB.prepare('INSERT INTO gift_redeem (username, code, redeemed_at) VALUES (?, ?, ?)').bind(username, code, Date.now()).run();
    return json({ ok: true, msg: '兑换成功', reward: gift.reward });
  }

  // ---------- 兜底 ----------
  return new Response('Not Found', { status: 404 });
}
