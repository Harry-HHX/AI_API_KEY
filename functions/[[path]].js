// ========== 工具函数 ==========
async function getBody(request) {
  try { return await request.json(); } catch { return {}; }
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
  });
}

function getUsername(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/user=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

function sha256(str) {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(str)).then(
    buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
  );
}

// ========== TOTP 生成 ==========
async function generateTOTP(secret_b64, env) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.WORKER), { name: 'AES-GCM' }, false, ['decrypt']);
  const encrypted = Uint8Array.from(atob(secret_b64), c => c.charCodeAt(0));
  const iv = encrypted.slice(0, 12);
  const data = encrypted.slice(12);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  const secret = new TextDecoder().decode(decrypted);

  let epoch = Math.floor(Date.now() / 30000);
  const h = new Uint8Array(8);
  for (let i = 7; i >= 0; i--, epoch >>= 8) h[i] = epoch & 0xff;
  const key2 = await crypto.subtle.importKey('raw', Uint8Array.from(atob(secret), c => c.charCodeAt(0)), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key2, h));
  const offset = sig[19] & 0xf;
  const code = ((sig[offset] & 0x7f) << 24 | (sig[offset + 1] & 0xff) << 16 | (sig[offset + 2] & 0xff) << 8 | (sig[offset + 3] & 0xff)) % 1000000;
  return String(code).padStart(6, '0');
}

// ========== 路由入口 ==========
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method;

  // ========== /api/me ==========
  if (pathname === '/api/me' && method === 'GET') {
    const username = getUsername(request);
    if (!username) return json({ ok: false, msg: '未登录' }, 401);
    const user = await env.DB.prepare('SELECT username, created_at FROM users WHERE username = ?').bind(username).first();
    if (!user) return json({ ok: false, msg: '用户不存在' }, 401);
    return json({ ok: true, user });
  }

  // ========== /api/register ==========
  if (pathname === '/api/register' && method === 'POST') {
    const body = await getBody(request);
    if (!body.username || !body.password) return json({ ok: false, msg: '用户名和密码不能为空' }, 400);
    const hash = await sha256(body.password);
    try {
      await env.DB.prepare('INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)')
        .bind(body.username, hash, Date.now()).run();
      return json({ ok: true, msg: '注册成功' });
    } catch (e) {
      return json({ ok: false, msg: '注册失败: ' + e.message }, 400);
    }
  }

  // ========== /api/login ==========
  if (pathname === '/api/login' && method === 'POST') {
    const body = await getBody(request);
    if (!body.username || !body.password) return json({ ok: false, msg: '用户名和密码不能为空' }, 400);
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(body.username).first();
    if (!user) return json({ ok: false, msg: '用户不存在' }, 401);
    const hash = await sha256(body.password);
    if (hash !== user.password_hash) return json({ ok: false, msg: '密码错误' }, 401);
    // 2FA 检查
    if (user.totp_verified) {
      if (!body.totp_code) return json({ ok: false, msg: '需要2FA验证码', need_totp: true }, 401);
      const code = await generateTOTP(user.totp_secret_encrypted, env);
      if (code !== body.totp_code) return json({ ok: false, msg: '2FA验证码错误' }, 401);
    }
    return new Response(JSON.stringify({ ok: true, msg: '登录成功' }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': `user=${body.username}; Path=/; Max-Age=2592000; SameSite=Lax`
      }
    });
  }

  // ========== /api/logout ==========
  if (pathname === '/api/logout' && method === 'POST') {
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': `user=; Path=/; Max-Age=0`
      }
    });
  }

  // ========== /auth/start ==========
  if (pathname === '/auth/start' && method === 'GET') {
    const state = crypto.randomUUID();
    await env.DB.prepare('INSERT OR REPLACE INTO oauth_states (state, created_at) VALUES (?, ?)')
      .bind(state, Date.now()).run();
    const redirect = `https://github.com/login/oauth/authorize?client_id=${env.GITHUB_CLIENT_ID}&redirect_uri=${encodeURIComponent(url.origin + '/auth/callback')}&scope=read:user&state=${state}`;
    return new Response('', { status: 302, headers: { 'Location': redirect } });
  }

  // ========== /auth/callback ==========
  if (pathname === '/auth/callback' && method === 'GET') {
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!code || !state) return new Response('缺少参数', { status: 400 });

    const saved = await env.DB.prepare('SELECT * FROM oauth_states WHERE state = ?').bind(state).first();
    if (!saved) return new Response('state 无效或过期', { status: 400 });
    await env.DB.prepare('DELETE FROM oauth_states WHERE state = ?').bind(state).run();

    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code })
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) return new Response('获取 token 失败', { status: 400 });

    const userRes = await fetch('https://api.github.com/user', { headers: { 'Authorization': `Bearer ${tokenData.access_token}` } });
    const ghUser = await userRes.json();

    let user = await env.DB.prepare('SELECT * FROM users WHERE github_id = ?').bind(String(ghUser.id)).first();
    if (!user) {
      const fallback = ghUser.login + '_' + Math.random().toString(36).slice(2, 6);
      const existing = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(fallback).first();
      const finalName = existing ? fallback + Math.random().toString(36).slice(2, 4) : fallback;
      await env.DB.prepare('INSERT INTO users (username, password_hash, github_id, created_at) VALUES (?, ?, ?, ?)')
        .bind(finalName, '', String(ghUser.id), Date.now()).run();
      user = await env.DB.prepare('SELECT * FROM users WHERE github_id = ?').bind(String(ghUser.id)).first();
    }

    return new Response('', {
      status: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': `user=${user.username}; Path=/; Max-Age=2592000; SameSite=Lax`
      }
    });
  }

  // ========== /api/apikeys ==========
  if (pathname === '/api/apikeys') {
    const username = getUsername(request);
    if (!username) return json({ ok: false, msg: '未登录' }, 401);
    if (method === 'GET') {
      const keys = await env.DB.prepare('SELECT id, name, key, used_tokens, token_limit, created_at, last_used FROM api_keys WHERE username = ?').bind(username).all();
      return json({ ok: true, data: keys.results });
    }
    if (method === 'POST') {
      const body = await getBody(request);
      const key = 'ak_' + crypto.randomUUID();
      const name = body.name || 'default';
      await env.DB.prepare('INSERT INTO api_keys (username, key, name, created_at) VALUES (?, ?, ?, ?)')
        .bind(username, key, name, Date.now()).run();
      return json({ ok: true, key });
    }
  }

  // ========== /api/apikeys/delete ==========
  if (pathname === '/api/apikeys/delete' && method === 'POST') {
    const username = getUsername(request);
    if (!username) return json({ ok: false, msg: '未登录' }, 401);
    const body = await getBody(request);
    await env.DB.prepare('DELETE FROM api_keys WHERE key = ? AND username = ?').bind(body.key, username).run();
    return json({ ok: true });
  }

  // ========== /api/gift ==========
  if (pathname === '/api/gift' && method === 'POST') {
    const username = getUsername(request);
    if (!username) return json({ ok: false, msg: '未登录' }, 401);
    const body = await getBody(request);
    const code = await env.DB.prepare('SELECT * FROM gift_codes WHERE code = ?').bind(body.code).first();
    if (!code) return json({ ok: false, msg: '礼品码不存在' }, 400);
    if (code.expires_at && code.expires_at < Date.now()) return json({ ok: false, msg: '礼品码已过期' }, 400);
    const used = await env.DB.prepare('SELECT id FROM gift_redeem WHERE username = ? AND code = ?').bind(username, body.code).first();
    if (used) return json({ ok: false, msg: '已兑换过' }, 400);
    const reward = JSON.parse(code.reward);
    if (reward.tokens) {
      const apiKey = await env.DB.prepare('SELECT * FROM api_keys WHERE username = ? ORDER BY created_at DESC LIMIT 1').bind(username).first();
      if (apiKey) {
        await env.DB.prepare('UPDATE api_keys SET token_limit = token_limit + ? WHERE key = ?').bind(reward.tokens, apiKey.key).run();
      }
    }
    await env.DB.prepare('INSERT INTO gift_redeem (username, code, redeemed_at) VALUES (?, ?, ?)').bind(username, body.code, Date.now()).run();
    return json({ ok: true, msg: '兑换成功' });
  }

  // ========== /api/2fa/setup ==========
  if (pathname === '/api/2fa/setup' && method === 'POST') {
    const username = getUsername(request);
    if (!username) return json({ ok: false, msg: '未登录' }, 401);
    const secret = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(20))));
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.WORKER), { name: 'AES-GCM' }, false, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(secret));
    const combined = new Uint8Array(iv.length + encrypted.byteLength);
    combined.set(iv); combined.set(new Uint8Array(encrypted), iv.length);
    const encrypted_b64 = btoa(String.fromCharCode(...combined));
    await env.DB.prepare('UPDATE users SET totp_secret_encrypted = ? WHERE username = ?').bind(encrypted_b64, username).run();
    const otpauth = `otpauth://totp/AI-CHAT:${username}?secret=${secret}&issuer=AI-CHAT`;
    return json({ ok: true, secret, otpauth });
  }

  // ========== /api/2fa/verify ==========
  if (pathname === '/api/2fa/verify' && method === 'POST') {
    const username = getUsername(request);
    if (!username) return json({ ok: false, msg: '未登录' }, 401);
    const body = await getBody(request);
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    const code = await generateTOTP(user.totp_secret_encrypted, env);
    if (code === body.code) {
      await env.DB.prepare('UPDATE users SET totp_verified = 1 WHERE username = ?').bind(username).run();
      return json({ ok: true });
    }
    return json({ ok: false, msg: '验证码错误' });
  }

  // ========== /api/models ==========
  if (pathname === '/api/models' && method === 'GET') {
    const username = getUsername(request);
    if (!username) return json({ ok: false, msg: '未登录' }, 401);
    // 随机 1-10 秒防刷延迟
    await new Promise(r => setTimeout(r, Math.floor(Math.random() * 10000) + 1000));
    const WORKERS_AI_MODELS = [
      { id: '@cf/deepseek-ai/deepseek-v4-flash-0731', name: 'DeepSeek V4 Flash' },
      { id: '@cf/qwen/qwen3-30b-a3b-fp8', name: 'Qwen3 30B A3B' },
      { id: '@cf/meta/llama-3.1-8b-instruct', name: 'Llama 3.1 8B' },
      { id: '@cf/meta/llama-3.1-8b-instruct-fp8-fast', name: 'Llama 3.1 8B Fast' }
    ];
    return json({ ok: true, data: WORKERS_AI_MODELS });
  }

  // ========== /api/chat ==========
  if (pathname === '/api/chat' && method === 'POST') {
    const username = getUsername(request);
    if (!username) return json({ ok: false, msg: '未登录' }, 401);
    const body = await getBody(request);
    if (!body.message) return json({ ok: false, msg: 'message 不能为空' }, 400);

    const userKey = await env.DB.prepare('SELECT * FROM api_keys WHERE username = ? ORDER BY created_at DESC LIMIT 1').bind(username).first();
    if (!userKey) return json({ ok: false, msg: '请先创建API Key' }, 400);
    if ((userKey.used_tokens || 0) >= (userKey.token_limit || 100000)) return json({ ok: false, msg: '额度已用完' }, 403);

    const model = body.model || '@cf/deepseek-ai/deepseek-v4-flash-0731';
    const messages = [
      { role: 'system', content: 'You are AI-CHAT, a helpful assistant.' },
      ...(Array.isArray(body.history) ? body.history : []),
      { role: 'user', content: String(body.message) }
    ];

    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 30000);

      const cfRes = await fetch(
        `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai/run/${model}`,
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.CF_API_TOKEN}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ messages, max_tokens: 1024, temperature: 0.7 }),
          signal: controller.signal
        }
      );
      clearTimeout(timer);

      if (!cfRes.ok) {
        const errText = await cfRes.text();
        return json({ ok: false, msg: 'AI 请求失败: ' + cfRes.status + ' ' + errText }, 500);
      }

      const cfData = await cfRes.json();
      const reply = cfData.result?.response || '无响应';

      // 额度扣减（按字符数粗略估算 token）
      const used = Math.ceil(JSON.stringify(messages).length / 4);
      await env.DB.prepare('UPDATE api_keys SET used_tokens = ?, last_used = ? WHERE key = ?')
        .bind((userKey.used_tokens || 0) + used, Date.now(), userKey.key).run();

      return json({ ok: true, reply });
    } catch (e) {
      if (e.name === 'AbortError') {
        return json({ ok: false, msg: 'AI 请求超时（30秒）' }, 504);
      }
      return json({ ok: false, msg: 'AI 请求失败：' + String(e) }, 500);
    }
  }

  // ========== 404 ==========
  return json({ ok: false, msg: 'Not Found' }, 404);
}
