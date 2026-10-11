// functions/[[path]].js
// D1 绑定名: DB
// KV 绑定名: USERS (仅用于 session 存储)
// 环境变量: WORKER (TOTP AES-GCM 加密密钥), GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
// ============ 工具函数 ============
function b64urlEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  return Uint8Array.from(bin, c => c.charCodeAt(0));
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derived = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt || 'ai-chat-salt'), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  return b64urlEncode(derived);
}

async function encryptTOTPSecret(secret, username, workerVal) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(username + ':' + workerVal), { name: 'AES-GCM' }, false, ['encrypt']);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(secret));
  return b64urlEncode(iv) + ':' + b64urlEncode(encrypted);
}

async function decryptTOTPSecret(encryptedData, username, workerVal) {
  try {
    const [ivStr, dataStr] = encryptedData.split(':');
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(username + ':' + workerVal), { name: 'AES-GCM' }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64urlDecode(ivStr) }, key, b64urlDecode(dataStr));
    return new TextDecoder().decode(decrypted);
  } catch { return null; }
}

function generateSessionToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return b64urlEncode(arr);
}

function getSessionToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/session=([^;]+)/);
  return match ? match[1] : null;
}

async function getSessionUser(request, env) {
  const token = getSessionToken(request);
  if (!token) return null;
  const sessionData = await env.USERS.get('sess:' + token);
  if (!sessionData) return null;
  try {
    const { userId, username, totpEnabled, trialStart } = JSON.parse(sessionData);
    return { userId, username, totpEnabled, trialStart };
  } catch { return null; }
}

async function setSessionCookie(response, token) {
  response.headers.set('Set-Cookie', `session=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800`);
}

// ============ TOTP 内联（不依赖外部模块） ============
function base32Encode(buffer) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '', result = '';
  for (const b of new Uint8Array(buffer)) { bits += b.toString(2).padStart(8, '0'); }
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    result += chars[parseInt(chunk, 2)];
  }
  return result;
}

async function generateTOTPSecretLocal() {
  const buf = new Uint8Array(20);
  crypto.getRandomValues(buf);
  const secret = base32Encode(buf);
  return secret;
}

async function verifyTOTPLocal(secret, token) {
  const epoch = Math.floor(Date.now() / 30000);
  for (const offset of [0, -1, 1]) {
    const time = epoch + offset;
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', base32ToBytes(secret), { name: 'HMAC' }, false, ['sign']);
    const hmac = await crypto.subtle.sign('HMAC', key, enc.encode(String(time).padStart(8, '0')));
    const bytes = new Uint8Array(hmac);
    const offset_ = bytes[bytes.length - 1] & 0xf;
    const code = (((bytes[offset_] & 0x7f) << 24) | ((bytes[offset_ + 1] & 0xff) << 16) | ((bytes[offset_ + 2] & 0xff) << 8) | (bytes[offset_ + 3] & 0xff)) % 1000000;
    if (String(code).padStart(6, '0') === token) return true;
  }
  return false;
}

function base32ToBytes(b32) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of b32.toUpperCase().replace(/=+$/, '')) {
    bits += chars.indexOf(c).toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i < bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8).padEnd(8, '0'), 2));
  }
  return new Uint8Array(bytes);
}

// ============ 路由分发 ============
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS
  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': url.origin,
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true'
      }
    });
  }

  try {
    // ============ 公开路由 ============
    if (path === '/api/status' && method === 'GET') {
      const user = await getSessionUser(request, env);
      if (!user) return json({ ok: false });
      const daysLeft = user.totpEnabled ? -1 : Math.max(0, 7 - Math.floor((Date.now() - user.trialStart) / 86400000));
      return json({
        ok: true, username: user.username, totp_enabled: !!user.totpEnabled,
        trial_expired: !user.totpEnabled && daysLeft <= 0, days_left: daysLeft
      });
    }

    if (path === '/api/register' && method === 'POST') {
      const { username, password } = await request.json();
      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return json({ ok: false, msg: '用户名3-20位字母数字下划线' });
      if (password.length < 6) return json({ ok: false, msg: '密码至少6位' });

      const exists = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
      if (exists) return json({ ok: false, msg: '账号已存在' });

      const hashed = await hashPassword(password, username);
      const trialStart = Date.now();
      const result = await env.DB.prepare('INSERT INTO users (username, password, trial_start) VALUES (?, ?, ?)')
        .bind(username, hashed, trialStart).run();

      const userId = result.meta?.last_row_id;
      // 自动生成 API Key
      const apiKey = 'ak_' + b64urlEncode(crypto.getRandomValues(new Uint8Array(24)));
      await env.DB.prepare('INSERT INTO api_keys (user_id, key) VALUES (?, ?)').bind(userId, apiKey).run();

      const token = generateSessionToken();
      await env.USERS.put('sess:' + token, JSON.stringify({ userId, username, totpEnabled: 0, trialStart }), { expirationTtl: 604800 });

      const res = json({ ok: true, msg: '注册成功' });
      await setSessionCookie(res, token);
      return res;
    }

    if (path === '/api/login' && method === 'POST') {
      const { username, password } = await request.json();
      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      if (!user) return json({ ok: false, msg: '账号不存在' });

      const hashed = await hashPassword(password, username);
      if (hashed !== user.password) return json({ ok: false, msg: '密码错误' });

      const token = generateSessionToken();
      await env.USERS.put('sess:' + token, JSON.stringify({
        userId: user.id, username: user.username,
        totpEnabled: user.totp_enabled, trialStart: user.trial_start
      }), { expirationTtl: 604800 });

      const res = json({ ok: true, totp_enabled: !!user.totp_enabled });
      await setSessionCookie(res, token);
      return res;
    }

    if (path === '/api/logout' && method === 'POST') {
      const token = getSessionToken(request);
      if (token) await env.USERS.delete('sess:' + token);
      const res = json({ ok: true });
      res.headers.set('Set-Cookie', 'session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
      return res;
    }

    // ============ 需要登录的路由 ============
    const sessionUser = await getSessionUser(request, env);
    if (!sessionUser) return json({ ok: false, msg: '未登录' }, 401);

    if (path === '/api/totp/setup' && method === 'POST') {
      const secret = await generateTOTPSecretLocal();
      const encrypted = await encryptTOTPSecret(secret, sessionUser.username, env.WORKER);
      const otpauth = `otpauth://totp/AI-CHAT:${sessionUser.username}?secret=${secret}&issuer=AI-CHAT`;
      return json({ ok: true, secret, otpauth, encrypted });
    }

    if (path === '/api/totp/enable' && method === 'POST') {
      const { code } = await request.json();
      const user = await env.DB.prepare('SELECT totp_secret FROM users WHERE id = ?').bind(sessionUser.userId).first();
      if (!user || !user.totp_secret) return json({ ok: false, msg: '请先获取密钥' });

      const decrypted = await decryptTOTPSecret(user.totp_secret, sessionUser.username, env.WORKER);
      if (!decrypted) return json({ ok: false, msg: '解密失败' });

      const valid = await verifyTOTPLocal(decrypted, code);
      if (!valid) return json({ ok: false, msg: '验证码错误' });

      await env.DB.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').bind(sessionUser.userId).run();
      return json({ ok: true });
    }

    if (path === '/api/totp/skip' && method === 'POST') {
      return json({ ok: true });
    }

    if (path === '/api/totp/verify' && method === 'POST') {
      const { code } = await request.json();
      const user = await env.DB.prepare('SELECT totp_secret FROM users WHERE id = ?').bind(sessionUser.userId).first();
      if (!user || !user.totp_secret) return json({ ok: false, msg: '未设置2FA' });

      const decrypted = await decryptTOTPSecret(user.totp_secret, sessionUser.username, env.WORKER);
      if (!decrypted) return json({ ok: false, msg: '解密失败' });

      const valid = await verifyTOTPLocal(decrypted, code);
      if (!valid) return json({ ok: false, msg: '验证码错误' });

      return json({ ok: true });
    }

    if (path === '/api/keys' && method === 'GET') {
      const keys = await env.DB.prepare('SELECT key FROM api_keys WHERE user_id = ?').bind(sessionUser.userId).all();
      return json({ ok: true, keys: keys.results.map(r => r.key) });
    }

    if (path === '/api/keys/create' && method === 'POST') {
      const apiKey = 'ak_' + b64urlEncode(crypto.getRandomValues(new Uint8Array(24)));
      await env.DB.prepare('INSERT INTO api_keys (user_id, key) VALUES (?, ?)').bind(sessionUser.userId, apiKey).run();
      return json({ ok: true, key: apiKey });
    }

    if (path === '/api/keys/delete' && method === 'POST') {
      const { key } = await request.json();
      await env.DB.prepare('DELETE FROM api_keys WHERE user_id = ? AND key = ?').bind(sessionUser.userId, key).run();
      return json({ ok: true });
    }

    if (path === '/api/gift/redeem' && method === 'POST') {
      const { code } = await request.json();
      const gift = await env.DB.prepare('SELECT * FROM gift_codes WHERE code = ?').bind(code).first();
      if (!gift) return json({ ok: false, msg: '礼品码不存在' });
      if (gift.used >= gift.max_uses) return json({ ok: false, msg: '礼品码已用完' });

      await env.DB.prepare('INSERT INTO gift_redeem (user_id, code, type, value) VALUES (?, ?, ?, ?)')
        .bind(sessionUser.userId, code, gift.type, gift.value).run();
      await env.DB.prepare('UPDATE gift_codes SET used = used + 1 WHERE code = ?').bind(code).run();

      if (gift.type === 'permanent') {
        await env.DB.prepare('UPDATE users SET totp_enabled = 1 WHERE id = ?').bind(sessionUser.userId).run();
      }
      return json({ ok: true, type: gift.type, value: gift.value });
    }

    // GitHub OAuth 占位（不绑AI时保留路由）
    if (path === '/auth/github' && method === 'GET') {
      const state = b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
      await env.USERS.put('oauth:' + state, sessionUser.userId.toString(), { expirationTtl: 600 });
      const githubUrl = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(url.origin + '/auth/callback')}&state=${state}&scope=user:email`;
      return Response.redirect(githubUrl, 302);
    }

    if (path === '/auth/callback' && method === 'GET') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      if (!code || !state) return new Response('Missing params', { status: 400 });

      const stateData = await env.USERS.get('oauth:' + state);
      if (!stateData) return new Response('Invalid state', { status: 400 });

      // 这里需要你填 GITHUB_CLIENT_SECRET 才能换 token
      // 简化版：直接返回成功页，实际要 fetch github token
      return Response.redirect(url.origin, 302);
    }

    return new Response('Not Found', { status: 404 });

  } catch (err) {
    console.error(err);
    return json({ ok: false, msg: '服务器错误: ' + err.message }, 500);
  }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Credentials': 'true' }
  });
}
