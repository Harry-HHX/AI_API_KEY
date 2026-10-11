// functions/[[path]].js
// AI-CHAT 完整版后端
// KV: USERS / API_KEYS / GIFT_CODE
// 变量: WORKER / CF_ACCOUNT_ID / CF_API_TOKEN / GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET

/// ============ 配置 ============
const SESSION_TTL = 60 * 60 * 24 * 7;
const TOTP_WINDOW = 1;
const TOTP_RATE_LIMIT = 5;
const TRIAL_DAYS = 7;
const DAILY_LIMIT_NO_2FA = 20;

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
    status, headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
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
function randToken(len = 24) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return b64url_encode(bytes);
}
function getCookie(req, name) {
  const cookie = req.headers.get('Cookie') || '';
  const m = cookie.match(new RegExp('(^|; )' + name + '=([^;]*)'));
  return m ? decodeURIComponent(m[2]) : null;
}
function setCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax`;
}

/// ============ 密码哈希 ============
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

/// ============ KV 操作 ============
// USERS
async function getUser(env, username) {
  const d = await env.USERS.get('user:' + username);
  return d ? JSON.parse(d) : null;
}
async function putUser(env, username, user) {
  await env.USERS.put('user:' + username, JSON.stringify(user));
}
async function getSession(env, sid) {
  const d = await env.USERS.get('sess:' + sid);
  return d ? JSON.parse(d) : null;
}
async function putSession(env, sid, sess) {
  await env.USERS.put('sess:' + sid, JSON.stringify(sess), { expirationTtl: SESSION_TTL });
}

// API_KEYS
async function createApiKey(env, username) {
  const key = 'sk_' + randToken(28);
  await env.API_KEYS.put('key:' + key, JSON.stringify({ username, createdAt: Date.now(), active: true }));
  const existing = await env.API_KEYS.get('user_keys:' + username);
  const keys = existing ? JSON.parse(existing) : [];
  keys.push(key);
  await env.API_KEYS.put('user_keys:' + username, JSON.stringify(keys));
  return key;
}
async function getUserKeys(env, username) {
  const d = await env.API_KEYS.get('user_keys:' + username);
  return d ? JSON.parse(d) : [];
}
async function validateApiKey(env, key) {
  const d = await env.API_KEYS.get('key:' + key);
  if (!d) return null;
  const info = JSON.parse(d);
  return info.active ? info : null;
}
async function getQuota(env, username) {
  const today = new Date().toISOString().slice(0, 10);
  const d = await env.API_KEYS.get('quota:' + username + ':' + today);
  return d ? JSON.parse(d) : { used: 0, date: today };
}
async function incQuota(env, username) {
  const today = new Date().toISOString().slice(0, 10);
  const key = 'quota:' + username + ':' + today;
  const d = await env.API_KEYS.get(key);
  const q = d ? JSON.parse(d) : { used: 0, date: today };
  q.used++;
  await env.API_KEYS.put(key, JSON.stringify(q), { expirationTtl: 86400 * 2 });
  return q;
}

// GIFT_CODE
async function getGiftCode(env, code) {
  const d = await env.GIFT_CODE.get('code:' + code);
  return d ? JSON.parse(d) : null;
}
async function useGiftCode(env, code, username) {
  const gift = await getGiftCode(env, code);
  if (!gift) return { ok: false, msg: '礼品码不存在' };
  if (gift.used) return { ok: false, msg: '礼品码已被使用' };
  gift.used = true;
  gift.usedBy = username;
  gift.usedAt = Date.now();
  await env.GIFT_CODE.put('code:' + code, JSON.stringify(gift));
  const record = { code, type: gift.type, value: gift.value, at: Date.now() };
  const existing = await env.GIFT_CODE.get('user_gifts:' + username);
  const gifts = existing ? JSON.parse(existing) : [];
  gifts.push(record);
  await env.GIFT_CODE.put('user_gifts:' + username, JSON.stringify(gifts));
  return { ok: true, gift };
}

/// ============ 路由 ============

// 注册
async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch { return json({ ok: false, msg: '格式错误' }, 400); }
  const { username, password } = body;
  if (!username || !password) return json({ ok: false, msg: '用户名和密码不能为空' }, 400);
  if (password.length < 6) return json({ ok: false, msg: '密码至少6位' }, 400);
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return json({ ok: false, msg: '用户名3-20位，仅字母数字下划线' }, 400);

  if (await getUser(env, username)) return json({ ok: false, msg: '用户已存在' }, 409);

  const salt = b64url_encode(crypto.getRandomValues(new Uint8Array(16)));
  const hash = await hashPassword(password, salt);
  const now = Date.now();
  const user = {
    username, provider: 'password', salt, passwordHash: hash,
    createdAt: now, firstLoginAt: now, totp_enabled: false, trial_start: now
  };
  await putUser(env, username, user);

  // 自动生成 API Key
  const apiKey = await createApiKey(env, username);

  const sessionId = b64url_encode(crypto.getRandomValues(new Uint8Array(32)));
  await putSession(env, sessionId, { username, createdAt: now });

  return new Response(JSON.stringify({ ok: true, msg: '注册成功', api_key: apiKey }), {
    status: 201,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': setCookie('session_id', sessionId, SESSION_TTL)
    }
  });
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

  return new Response(JSON.stringify({ ok: true, msg: '登录成功', totp_enabled: user.totp_enabled }), {
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
  await env.USERS.put('oauth_state:' + state, '1', { expirationTtl: 300 });
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
  const saved = await env.USERS.get('oauth_state:' + state);
  if (!saved) return html('<h1>state验证失败</h1>', 403);
  await env.USERS.delete('oauth_state:' + state);

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
  const isNew = !user;
  if (!user) {
    user = {
      username: login, provider: 'github', githubId: gh.id, avatar: gh.avatar_url,
      createdAt: now, firstLoginAt: now, totp_enabled: false, trial_start: now
    };
    await putUser(env, login, user);
    await createApiKey(env, login);
  }

  const sessionId = b64url_encode(crypto.getRandomValues(new Uint8Array(32)));
  await putSession(env, sessionId, { username: login, createdAt: now });

  const redirectPage = `
<!DOCTYPE html>
<html lang="zh-CN">
<head><meta charset="UTF-8"><title>登录中...</title></head>
<body>
<script>
localStorage.setItem('logged_in','true');
localStorage.setItem('username', ${JSON.stringify(login)});
${user.totp_enabled ? `localStorage.setItem('need_totp_verify','true');` : `localStorage.setItem('need_2fa_setup','${isNew ? 'true' : 'false'}');`}
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

// TOTP 校验
async function handleTotpVerify(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const { code } = await request.json();
  if (!code || !/^\d{6}$/.test(code)) return json({ ok: false, msg: '验证码格式错误' }, 400);

  const user = await getUser(env, sess.username);
  if (!user || !user.totp_enabled) return json({ ok: false, msg: '未启用2FA' }, 400);

  const rateKey = 'totp_rate:' + sess.username;
  const rateData = await env.USERS.get(rateKey);
  let attempts = 0;
  if (rateData) { const rd = JSON.parse(rateData); if (Date.now() - rd.since < 60000) attempts = rd.count; }
  if (attempts >= TOTP_RATE_LIMIT) return json({ ok: false, msg: '尝试次数过多，请60秒后再试' }, 429);
  await env.USERS.put(rateKey, JSON.stringify({ since: Date.now(), count: attempts + 1 }), { expirationTtl: 60 });

  const plainSecret = await aesDecrypt(user.totp_secret, user.username + ':' + (env.WORKER || 'default'));
  if (!plainSecret) return json({ ok: false, msg: '解密失败' }, 500);

  const valid = await totpVerify(plainSecret, code);
  if (!valid) return json({ ok: false, msg: '验证码错误' }, 401);

  await env.USERS.delete(rateKey);
  return json({ ok: true, msg: '验证通过' });
}

// TOTP 生成 secret
async function handleTotpSetup(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const secret = randBase32(32);
  const user = await getUser(env, sess.username);
  user.totp_secret_temp = secret;
  await putUser(env, sess.username, user);

  const otpauth = `otpauth://totp/AI-CHAT:${sess.username}?secret=${secret}&issuer=AI-CHAT`;
  return json({ ok: true, secret, otpauth });
}

// TOTP 确认绑定
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

  const encrypted = await aesEncrypt(user.totp_secret_temp, user.username + ':' + (env.WORKER || 'default'));
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
  return json({ ok: true });
}

// 检查状态
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

// API Key 列表
async function handleApiKeys(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const keys = await getUserKeys(env, sess.username);
  return json({ ok: true, keys });
}

// 生成新 API Key
async function handleCreateKey(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const key = await createApiKey(env, sess.username);
  return json({ ok: true, key });
}

// 删除 API Key
async function handleDeleteKey(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const { key } = await request.json();
  if (!key) return json({ ok: false, msg: '缺少key' }, 400);

  const info = await validateApiKey(env, key);
  if (!info || info.username !== sess.username) return json({ ok: false, msg: '无权限' }, 403);

  // 标记为非活跃
  info.active = false;
  await env.API_KEYS.put('key:' + key, JSON.stringify(info));

  // 从用户列表移除
  const keys = await getUserKeys(env, sess.username);
  const filtered = keys.filter(k => k !== key);
  await env.API_KEYS.put('user_keys:' + sess.username, JSON.stringify(filtered));

  return json({ ok: true, msg: '已删除' });
}

// 礼品码兑换
async function handleRedeemGift(request, env) {
  const sid = getCookie(request, 'session_id');
  if (!sid) return json({ ok: false, msg: '未登录' }, 401);
  const sess = await getSession(env, sid);
  if (!sess) return json({ ok: false, msg: '会话过期' }, 401);

  const { code } = await request.json();
  if (!code) return json({ ok: false, msg: '请输入礼品码' }, 400);

  const result = await useGiftCode(env, code, sess.username);
  if (!result.ok) return json({ ok: false, msg: result.msg }, 400);

  const gift = result.gift;
  const user = await getUser(env, sess.username);

  // 根据类型发放奖励
  if (gift.type === 'extra_quota') {
    // 增加今日配额（额外条数）
    const today = new Date().toISOString().slice(0, 10);
    const qkey = 'quota:' + sess.username + ':' + today;
    const qd = await env.API_KEYS.get(qkey);
    const q = qd ? JSON.parse(qd) : { used: 0, date: today };
    q.used = Math.max(0, q.used - gift.value);
    await env.API_KEYS.put(qkey, JSON.stringify(q), { expirationTtl: 86400 * 2 });
  } else if (gift.type === 'extend_trial') {
    // 延长试用期
    user.trial_start = (user.trial_start || Date.now()) + gift.value * 86400000;
    await putUser(env, sess.username, user);
  } else if (gift.type === 'permanent') {
    // 永久无限制
    user.totp_enabled = true;
    user.permanent = true;
    await putUser(env, sess.username, user);
  }

  return json({ ok: true, msg: '兑换成功', type: gift.type, value: gift.value });
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
    if (Date.now() > trialStart + TRIAL_DAYS * 86400000 && !user.totp_enabled && !user.permanent) {
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
  if (!user) return json({ ok: false, msg: '用户不存在' }, 404);

  // 试用期检查
  const trialStart = user.trial_start || user.firstLoginAt || Date.now();
  const trialExpired = Date.now() > trialStart + TRIAL_DAYS * 86400000;
  if (trialExpired && !user.totp_enabled && !user.permanent) {
    return json({ ok: false, msg: '试用期已结束，请绑定2FA解锁' }, 403);
  }

  // 配额检查（未绑2FA时）
  if (!user.totp_enabled && !user.permanent) {
    const quota = await getQuota(env, sess.username);
    if (quota.used >= DAILY_LIMIT_NO_2FA) {
      return json({ ok: false, msg: `今日聊天次数已用完(${DAILY_LIMIT_NO_2FA}条)，绑定2FA解锁无限制` }, 429);
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

  // 成功才计次
  if (!user.totp_enabled && !user.permanent) {
    await incQuota(env, sess.username);
  }

  const data = await upstreamRes.json();
  return json({ ok: true, data });
}

// 登出
async function handleLogout(request, env) {
  const sid = getCookie(request, 'session_id');
  if (sid) await env.USERS.delete('sess:' + sid);
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
  const method = request.method;

  if (method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' } });
  }

  // 路由表
  const routes = {
    'POST /api/register': handleRegister,
    'POST /api/login': handlePasswordLogin,
    'GET /auth/github': handleGitHubAuth,
    'GET /auth/callback': handleGitHubCallback,
    'POST /api/totp/verify': handleTotpVerify,
    'POST /api/totp/setup': handleTotpSetup,
    'POST /api/totp/enable': handleTotpEnable,
    'POST /api/totp/skip': handleSkip2FA,
    'GET /api/status': handleCheckStatus,
    'GET /api/keys': handleApiKeys,
    'POST /api/keys/create': handleCreateKey,
    'POST /api/keys/delete': handleDeleteKey,
    'POST /api/gift/redeem': handleRedeemGift,
    'GET /api/models': handleModels,
    'POST /api/chat': handleChat,
    'POST /api/logout': handleLogout,
  };

  const key = method + ' ' + path;
  const handler = routes[key];
  if (handler) return handler(request, env);

  // 前端页面
  if (path === '/' || path === '/index.html') {
    return env.ASSETS.fetch(request);
  }

  return json({ ok: false, msg: 'Not Found' }, 404);
}
