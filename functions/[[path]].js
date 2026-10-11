// functions/[[path]].js
// AI-CHAT 私有站点后端
// KV 绑定名: HE_SITE_KV

/// ============ 配置 ============
const SESSION_TTL = 60 * 60 * 24 * 7;
const TOTP_WINDOW = 1;
const TOTP_RATE_LIMIT = 5;
const TRIAL_DAYS = 7;

const WORKERS_AI_MODELS = [
  { id: '@cf/deepseek-ai/deepseek-v4-flash-0731', name: 'DeepSeek V4 Flash' },
  { id: '@cf/qwen/qwen3-30b-a3b-fp8', name: 'Qwen3 30B A3B' },
  { id: '@cf/meta/llama-3.1-8b-instruct', name: 'Llama 3.1 8B' },
  { id: '@cf/meta/llama-3.1-8b-instruct-fp8-fast', name: 'Llama 3.1 8B Fast' }
];

/// ============ 工具 ============
function b64url_encode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function b64url_decode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'Content-Type': 'application/json' }
  });
}
function html(content, status = 200) {
  return new Response(content, {
    status, headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}
function randBase32(len = 32) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[bytes[i] % 32];
  return s;
}
function getCookie(req, name) {
  const cookie = req.headers.get('Cookie') || '';
  const m = cookie.match(new RegExp('(^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[2]) : null;
}
function setCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax`;
}

/// ============ 密码哈希 (Web Crypto, SHA-256) ============
async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(salt + password),
    { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: new TextEncoder().encode(salt), iterations: 100000, hash: 'SHA-256' },
    key, 256
  );
  return b64url_encode(bits);
}

/// ============ AES-GCM ============
async function aesEncrypt(plaintext, keyStr) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(keyStr.padEnd(32, '0').slice(0, 32)),
    { name: 'AES-GCM' }, false, ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  return b64url_encode(iv) + '.' + b64url_encode(ct);
}
async function aesDecrypt(ciphertext, keyStr) {
  try {
    const [ivB64, ctB64] = ciphertext.split('.');
    const iv = b64url_decode(ivB64);
    const ct = b64url_decode(ctB64);
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(keyStr.padEnd(32, '0').slice(0, 32)),
      { name: 'AES-GCM' }, false, ['decrypt']
    );
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(pt);
  } catch { return null; }
}

/// ============ TOTP ============
async function totpVerify(secretBase32, inputCode) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = [];
  for (const c of secretBase32) { const idx = chars.indexOf(c.toUpperCase()); if (idx >= 0) bytes.push(idx); }
  const bin = [];
  let buffer = 0, bits = 0;
  for (const b of bytes) { buffer = (buffer << 5) | b; bits += 5; if (bits >= 8) { bits -= 8; bin.push((buffer >> bits) & 0xff); } }
  const keyBytes = new Uint8Array(bin);
  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const counter = Math.floor((Date.now() + i * 30000) / 30000);
    const counterBytes = new Uint8Array(8);
    let c = counter;
    for (let j = 7; j >= 0; j--) { counterBytes[j] = c & 0xff; c >>= 8; }
    const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, counterBytes));
    const offset = sig[sig.length - 1] & 0xf;
    const code = (((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff)) % 1000000;
    if (String(code).padStart(6, '0') === inputCode) return true;
  }
  return false;
}

/// ============ KV ============
async function getUser(env, username) {
  const d = await env.HE_SITE_KV.get('user:' + username);
  return d ? JSON.parse(d) : null;
}
async function putUser(env, username, user) {
  await env.HE_SITE_KV.put('user:' + username, JSON.stringify(user));
}
async function getSession(env, sid) {
  const d = await env.HE_SITE_KV.get('sess:' + sid);
  return d ? JSON.parse(d) : null;
}
async function putSession(env, sid, sess) {
  await env.HE_SITE_KV.put('sess:' + sid, JSON.stringify(sess), { expirationTtl: SESSION_TTL });
}

/// ============ 路由 ============

// 密码注册
async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, msg: '格式错误' }, 400); }
  const { username, password } = body;
  if (!username || !password) return json({ ok: false, msg: '用户名和密码不能为空' }, 400);
  if (password.length < 6) return json({ ok: false, msg: '密码至少6位' }, 400);

  const existing = await getUser(env, username);
  if (existing) return json({ ok: false, msg: '用户已存在' }, 409);

  const salt = b64url_encode(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await hashPassword(password, salt);
  const now = Date.now();
  const user = {
    username, provider: 'password', salt, passwordHash: hash,
    createdAt: now, firstLoginAt: now, totp_enabled: false, trial_start: now
  };
  await putUser(env, username, user);

  const sessionId = b64url_encode(crypto.getRandomValues(new Uint8Array(32)));
  await putSession(env, sessionId, { username, createdAt: now });

  return json({ ok: true, msg: '注册成功' }, 201, { 'Set-Cookie': setCookie('session_id', sessionId, SESSION_TTL) });
}

// 密码登录
async function handlePasswordLogin(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, msg: '格式错误' }, 400); }
  const { username, password } = body;
  if (!username || !password) return json({ ok: false, msg: '用户名和密码不能为空' }, 400);

  const user = await getUser(env, username);
  if (!user || user.provider !== 'password') return json({ ok: false, msg: '用户不存在' }, 401);

  const hash = await hashPassword(password, user.salt);
  if (hash !== user.passwordHash) return json({ ok: false, msg: '密码错误' }, 401);

  const sessionId = b64url_encode(crypto.getRandomValues(new Uint8Array(32)));
  await putSession(env, sessionId, { username, createdAt: Date.now() });

  return new Response(JSON.stringify({ ok: true, msg: '登录成功' }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': setCookie('session_id', sessionId, SESSION_TTL)
    }
  });
}

// GitHub OAuth 发起
async function handleGitHubAuth(request, env) {
  const clientId = env.GITHUB_CLIENT_ID;
  if (!clientId) return json({ ok: false, msg: '未配置 GITHUB_CLIENT_ID' }, 500);
  const redirectUri = new URL(request.url).origin + '/auth/callback';
  const state = b64url_encode(crypto.getRandomValues(new Uint8Array(16)));
  await env.HE_SITE_KV.put('oauth_state:' + state, '1', { expirationTtl: 300 });
  const authUrl = `https://github.com/login/oauth/authorize` +
    `?client_id=${encodeURIComponent(clientId)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&scope=${encodeURIComponent('read:user user:email')}` +
    `&state=${encodeURIComponent(state)}`;
  return new Response(null, { status: 302, headers: { 'Location': authUrl } });
}

// GitHub 回调
async function handleGitHubCallback(request, env) {
  const url = new URL(request.url);
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  if (!code) return html('<h1>授权失败</h1>', 400);
  const saved = await env.HE_SITE_KV.get('oauth_state:' + state);
  if (!saved) return html('<h1>state验证失败</h1>', 403);
  await env.HE_SITE_KV.delete('oauth_state:' + state);

  const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code })
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) return html('<h1>Token获取失败</h1>', 400);

  const ghRes = await fetch('https://api.github.com/user', {
    headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'Accept': 'application/vnd.github+json' }
  });
  const gh = await ghRes.json();
  const login = gh.login;
  const now = Date.now();

  let user = await getUser(env, login);
  if (!user) {
    // 首次登录 → 自动创建
    user = {
      username: login, provider: 'github', githubId: gh.id, avatar: gh.avatar_url,
      createdAt: now, firstLoginAt: now, totp_enabled: false, trial_start: now
    };
    await putUser(env, login, user);
  }

  const sessionId = b64url_encode(crypto.getRandomValues(new Uint8Array(32)));
  await putSession(env, sessionId, { username: login, createdAt: now });

  // 跳转前端，前端根据 totp_enabled 决定弹窗
  const redirectPage = `
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>登录中...</title></head>
<body>
<script>
localStorage.setItem('logged_in','true');
localStorage.setItem('username', ${JSON.stringify(login)});
${user.totp_enabled ? `localStorage.setItem('need_totp_verify','true');` : `localStorage.setItem('need_2fa_setup','true');`}
location.href='/';
</script>
</body>
</html>`;

  return new Response(redirectPage, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Set-Cookie': setCookie('session_id', sessionId, SESSION_TTL)
    }
  });
}

// TOTP 校验（已绑用户每次登录）
async function handleTotpVerify(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const { code } = await request.json();
  if (!code || !/^\d{6}$/.test(code)) return json({ ok: false, msg: '验证码格式错误' }, 400);

  const user = await getUser(env, sess.username);
  if (!user || !user.totp_enabled) return json({ ok: false, msg: '未启用2FA' }, 400);

  // 频率限制
  const rateKey = 'totp_rate:' + sess.username;
  const rateData = await env.HE_SITE_KV.get(rateKey);
  let attempts = 0;
  if (rateData) { const rd = JSON.parse(rateData); if (Date.now() - rd.since < 60000) attempts = rd.count; }
  if (attempts >= TOTP_RATE_LIMIT) return json({ ok: false, msg: '尝试次数过多，请60秒后再试' }, 429);
  await env.HE_SITE_KV.put(rateKey, JSON.stringify({ since: Date.now(), count: attempts + 1 }), { expirationTtl: 60 });

  const plainSecret = await aesDecrypt(user.totp_secret, user.username + ':' + (env.CF_API_TOKEN || 'default'));
  if (!plainSecret) return json({ ok: false, msg: '解密失败' }, 500);

  const valid = await totpVerify(plainSecret, code);
  if (!valid) return json({ ok: false, msg: '验证码错误' }, 401);

  await env.HE_SITE_KV.delete(rateKey);
  return json({ ok: true, msg: '验证通过' });
}

// 生成 TOTP secret
async function handleTotpSetup(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const secret = randBase32(32);
  const user = await getUser(env, sess.username);
  if (!user) return json({ ok: false, msg: '用户不存在' }, 404);

  user.totp_secret_temp = secret;
  await putUser(env, sess.username, user);

  const otpauth = `otpauth://totp/AI-CHAT:${sess.username}?secret=${secret}&issuer=AI-CHAT`;
  return json({ ok: true, secret, otpauth });
}

// 确认绑定 TOTP
async function handleTotpEnable(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const { code } = await request.json();
  if (!code || !/^\d{6}$/.test(code)) return json({ ok: false, msg: '验证码格式错误' }, 400);

  const user = await getUser(env, sess.username);
  if (!user || !user.totp_secret_temp) return json({ ok: false, msg: '请先生成secret' }, 400);

  const valid = await totpVerify(user.totp_secret_temp, code);
  if (!valid) return json({ ok: false, msg: '验证码错误' }, 401);

  const encrypted = await aesEncrypt(user.totp_secret_temp, user.username + ':' + (env.CF_API_TOKEN || 'default'));
  user.totp_secret = encrypted;
  user.totp_enabled = true;
  delete user.totp_secret_temp;
  await putUser(env, sess.username, user);

  return json({ ok: true, msg: '2FA已启用' });
}

// 跳过2FA
async function handleSkip2FA(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const user = await getUser(env, sess.username);
  if (!user) return json({ ok: false, msg: '用户不存在' }, 404);
  user.trial_start = user.trial_start || Date.now();
  await putUser(env, sess.username, user);

  return json({ ok: true, msg: '已跳过' });
}

// 检查用户状态
async function handleCheckStatus(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const user = await getUser(env, sess.username);
  if (!user) return json({ ok: false, msg: '用户不存在' }, 404);

  const now = Date.now();
  const trialStart = user.trial_start || user.firstLoginAt || now;
  const trialEnd = trialStart + TRIAL_DAYS * 86400000;
  const daysLeft = Math.max(0, Math.ceil((trialEnd - now) / 86400000));
  const trialExpired = now > trialEnd;

  return json({
    ok: true, username: sess.username,
    totp_enabled: user.totp_enabled || false,
    trial_expired: trialExpired, days_left: daysLeft
  });
}

// 模型列表
async function handleModels(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const user = await getUser(env, sess.username);
  if (user) {
    const trialStart = user.trial_start || user.firstLoginAt || Date.now();
    if (Date.now() > trialStart + TRIAL_DAYS * 86400000 && !user.totp_enabled) {
      return json({ ok: false, msg: '试用期已结束，请绑定2FA' }, 403);
    }
  }

  return json({ ok: true, data: WORKERS_AI_MODELS.map(m => ({ id: m.id, name: m.name })) });
}

// 聊天
async function handleChat(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const user = await getUser(env, sess.username);
  if (user) {
    const trialStart = user.trial_start || user.firstLoginAt || Date.now();
    if (Date.now() > trialStart + TRIAL_DAYS * 86400000 && !user.totp_enabled) {
      return json({ ok: false, msg: '试用期已结束，请绑定2FA' }, 403);
    }
  }

  let body;
  try { body = await request.json(); } catch { return json({ ok: false, msg: '请求格式错误' }, 400); }
  if (!body.model || !body.model.startsWith('@cf/')) return json({ ok: false, msg: '请选择模型' }, 400);

  const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai/v1/chat/completions`;
  let upstreamRes;
  try {
    upstreamRes = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + env.CF_API_TOKEN },
      body: JSON.stringify(body)
    });
  } catch { return json({ ok: false, msg: '网络错误' }, 502); }

  if (!upstreamRes.ok) {
    const errBody = await upstreamRes.text();
    return json({ ok: false, msg: '上游错误: ' + errBody }, upstreamRes.status);
  }

  const data = await upstreamRes.json();
  return json({ ok: true, data });
}

// 登出
async function handleLogout(request, env) {
  const sid = getCookie(request, 'session_id');
  if (sid) await env.HE_SITE_KV.delete('sess:' + sid);
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'session_id=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax'
    }
  });
}

/// ============ 入口 ============
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
  }

  if (path === '/auth/github' && request.method === 'GET') return handleGitHubAuth(request, env);
  if (path === '/auth/callback' && request.method === 'GET') return handleGitHubCallback(request, env);
  if (path === '/api/register' && request.method === 'POST') return handleRegister(request, env);
  if (path === '/api/login' && request.method === 'POST') return handlePasswordLogin(request, env);
  if (path === '/api/totp-verify' && request.method === 'POST') return handleTotpVerify(request, env);
  if (path === '/api/totp-setup' && request.method === 'POST') return handleTotpSetup(request, env);
  if (path === '/api/totp-enable' && request.method === 'POST') return handleTotpEnable(request, env);
  if (path === '/api/skip-2fa' && request.method === 'POST') return handleSkip2FA(request, env);
  if (path === '/api/check-status' && request.method === 'GET') return handleCheckStatus(request, env);
  if (path === '/api/logout' && request.method === 'POST') return handleLogout(request, env);
  if (path === '/v1/models' && request.method === 'GET') return handleModels(request, env);
  if (path === '/v1/chat/completions' && request.method === 'POST') return handleChat(request, env);

  return fetch(request);
}
