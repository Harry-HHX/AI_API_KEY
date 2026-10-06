export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // 非 API 请求 → 交给 Pages 静态文件
  if (!path.startsWith('/api/') && !path.startsWith('/v1/')) {
    return context.next();
  }

  // ===== 路由分发 =====
  if (path === '/api/register' && method === 'POST') return handleRegister(request, env);
  if (path === '/api/login' && method === 'POST') return handleLogin(request, env);
  if (path === '/api/logout' && method === 'POST') return handleLogout(request, env);
  if (path === '/api/me' && method === 'GET') return handleMe(request, env);
  if (path === '/api/my-keys' && method === 'GET') return handleMyKeys(request, env);
  if (path === '/api/create-my-key' && method === 'POST') return handleCreateKey(request, env);
  if (path === '/api/delete-my-key' && method === 'DELETE') return handleDeleteKey(request, env, url);
  if (path === '/api/redeem' && method === 'POST') return handleRedeem(request, env);
  if (path === '/api/change-password' && method === 'POST') return handleChangePwd(request, env);
  if (path === '/api/set-nickname' && method === 'POST') return handleSetNickname(request, env);
  if (path === '/v1/models' && method === 'GET') return handleModels(request, env);
  if (path === '/v1/chat/completions' && method === 'POST') return handleChat(request, env);

  return json({ error: 'Not Found', path }, 404);
}

// ===== 工具函数 =====
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
  return match ? match[2] : null;
}

function setCookieHeader(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}`;
}

// ===== 注册 =====
async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); } catch(e) { return json({ error: '无效请求' }, 400); }

  const { username, password } = body;
  if (!username || !password) return json({ error: '请填写完整' }, 400);
  if (username.length < 2) return json({ error: '用户名至少2位' }, 400);
  if (password.length < 4) return json({ error: '密码至少4位' }, 400);

  const exist = await env.USERS.get('user:' + username);
  if (exist) return json({ error: '用户名已存在' }, 409);

  await env.USERS.put('user:' + username, JSON.stringify({
    username, password, nickname: '', createdAt: Date.now(),
    usedTokens: 0, tokenLimit: 1000000
  }));

  // 创建主 Key
  const apiKey = 'sk_' + crypto.randomUUID().replace(/-/g, '');
  await env.API_KEYS.put('user:' + username + ':primary', JSON.stringify({
    key: apiKey, isPrimary: true, tokenLimit: 1000000, usedTokens: 0, createdAt: Date.now()
  }));

  // 自动登录
  const sessToken = crypto.randomUUID();
  await env.USERS.put('sess:' + sessToken, JSON.stringify({ username, createdAt: Date.now() }), { expirationTtl: 604800 });

  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', setCookieHeader('sess_token', sessToken, 604800));
  return new Response(JSON.stringify({ success: true, apiKey }), { headers });
}

// ===== 登录 =====
async function handleLogin(request, env) {
  let body;
  try { body = await request.json(); } catch(e) { return json({ error: '无效请求' }, 400); }

  const { username, password } = body;
  if (!username || !password) return json({ error: '请填写完整' }, 400);

  const userData = await env.USERS.get('user:' + username, 'json');
  if (!userData || userData.password !== password) return json({ error: '用户名或密码错误' }, 401);

  const sessToken = crypto.randomUUID();
  await env.USERS.put('sess:' + sessToken, JSON.stringify({ username, createdAt: Date.now() }), { expirationTtl: 604800 });

  // 拿主 Key
  let apiKey = '';
  const keys = await env.API_KEYS.list({ prefix: 'user:' + username + ':' });
  for (let k of keys.keys) {
    let d = await env.API_KEYS.get(k.name, 'json');
    if (d && d.isPrimary) { apiKey = d.key; break; }
  }

  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', setCookieHeader('sess_token', sessToken, 604800));
  return new Response(JSON.stringify({ success: true, apiKey }), { headers });
}

// ===== 登出 =====
async function handleLogout(request, env) {
  const sessToken = getCookie(request, 'sess_token');
  if (sessToken) await env.USERS.delete('sess:' + sessToken);
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', setCookieHeader('sess_token', '', 0));
  return new Response(JSON.stringify({ success: true }), { headers });
}

// ===== 检查登录 =====
async function handleMe(request, env) {
  const sessToken = getCookie(request, 'sess_token');
  if (!sessToken) return json({ error: '未登录' }, 401);
  const session = await env.USERS.get('sess:' + sessToken, 'json');
  if (!session) return json({ error: '会话过期' }, 401);

  const userData = await env.USERS.get('user:' + session.username, 'json');
  if (!userData) return json({ error: '用户不存在' }, 401);

  let primaryKey = '';
  const keys = await env.API_KEYS.list({ prefix: 'user:' + session.username + ':' });
  for (let k of keys.keys) {
    let d = await env.API_KEYS.get(k.name, 'json');
    if (d && d.isPrimary) { primaryKey = d.key; break; }
  }

  return json({
    success: true,
    username: userData.username,
    nickname: userData.nickname || '',
    usedTokens: userData.usedTokens || 0,
    tokenLimit: userData.tokenLimit || 1000000,
    apiKey: primaryKey
  });
}

// ===== 我的 Keys =====
async function handleMyKeys(request, env) {
  const sessToken = getCookie(request, 'sess_token');
  if (!sessToken) return json({ error: '未登录' }, 401);
  const session = await env.USERS.get('sess:' + sessToken, 'json');
  if (!session) return json({ error: '未登录' }, 401);

  const keys = await env.API_KEYS.list({ prefix: 'user:' + session.username + ':' });
  let result = [];
  for (let k of keys.keys) {
    let d = await env.API_KEYS.get(k.name, 'json');
    if (d) {
      result.push({
        key: d.key,
        isPrimary: d.isPrimary || false,
        tokenLimit: d.tokenLimit || 1000000,
        usedTokens: d.usedTokens || 0,
        remaining: (d.tokenLimit || 1000000) - (d.usedTokens || 0)
      });
    }
  }
  return json({ success: true, keys: result });
}

// ===== 创建 Key =====
async function handleCreateKey(request, env) {
  const sessToken = getCookie(request, 'sess_token');
  if (!sessToken) return json({ error: '未登录' }, 401);
  const session = await env.USERS.get('sess:' + sessToken, 'json');
  if (!session) return json({ error: '未登录' }, 401);

  const keys = await env.API_KEYS.list({ prefix: 'user:' + session.username + ':' });
  if (keys.keys.length >= 3) return json({ error: '最多创建3个Key' }, 400);

  const newKey = 'sk_' + crypto.randomUUID().replace(/-/g, '');
  await env.API_KEYS.put('user:' + session.username + ':key_' + Date.now(), JSON.stringify({
    key: newKey, isPrimary: false, tokenLimit: 100000, usedTokens: 0, createdAt: Date.now()
  }));
  return json({ success: true, key: newKey });
}

// ===== 删除 Key =====
async function handleDeleteKey(request, env, url) {
  const sessToken = getCookie(request, 'sess_token');
  if (!sessToken) return json({ error: '未登录' }, 401);
  const session = await env.USERS.get('sess:' + sessToken, 'json');
  if (!session) return json({ error: '未登录' }, 401);

  const key = url.searchParams.get('key');
  if (!key) return json({ error: '缺少key参数' }, 400);

  const keys = await env.API_KEYS.list({ prefix: 'user:' + session.username + ':' });
  for (let k of keys.keys) {
    let d = await env.API_KEYS.get(k.name, 'json');
    if (d && d.key === key) {
      if (d.isPrimary) return json({ error: '不能删除主Key' }, 400);
      await env.API_KEYS.delete(k.name);
      return json({ success: true });
    }
  }
  return json({ error: 'Key不存在' }, 404);
}

// ===== 兑换码 =====
async function handleRedeem(request, env) {
  const sessToken = getCookie(request, 'sess_token');
  if (!sessToken) return json({ error: '未登录' }, 401);
  const session = await env.USERS.get('sess:' + sessToken, 'json');
  if (!session) return json({ error: '未登录' }, 401);

  let body;
  try { body = await request.json(); } catch(e) { return json({ error: '无效请求' }, 400); }
  const { code } = body;
  if (!code) return json({ error: '请输入兑换码' }, 400);

  const giftData = await env.GIFT_CODE.get('code:' + code, 'json');
  if (!giftData) return json({ error: '兑换码不存在' }, 404);
  if (giftData.used) return json({ error: '兑换码已使用' }, 400);

  const keys = await env.API_KEYS.list({ prefix: 'user:' + session.username + ':' });
  for (let k of keys.keys) {
    let d = await env.API_KEYS.get(k.name, 'json');
    if (d && d.isPrimary) {
      d.tokenLimit = (d.tokenLimit || 1000000) + (giftData.tokens || 100000);
      await env.API_KEYS.put(k.name, JSON.stringify(d));
      break;
    }
  }

  giftData.used = true;
  giftData.usedBy = session.username;
  giftData.usedAt = Date.now();
  await env.GIFT_CODE.put('code:' + code, JSON.stringify(giftData));

  return json({ success: true, addedTokens: giftData.tokens || 100000 });
}

// ===== 改密码 =====
async function handleChangePwd(request, env) {
  const sessToken = getCookie(request, 'sess_token');
  if (!sessToken) return json({ error: '未登录' }, 401);
  const session = await env.USERS.get('sess:' + sessToken, 'json');
  if (!session) return json({ error: '未登录' }, 401);

  let body;
  try { body = await request.json(); } catch(e) { return json({ error: '无效请求' }, 400); }
  const { oldPassword, newPassword, confirmPassword } = body;
  if (!oldPassword || !newPassword || !confirmPassword) return json({ error: '请填写完整' }, 400);
  if (newPassword !== confirmPassword) return json({ error: '两次密码不一致' }, 400);

  const userData = await env.USERS.get('user:' + session.username, 'json');
  if (!userData || userData.password !== oldPassword) return json({ error: '原密码错误' }, 401);

  userData.password = newPassword;
  await env.USERS.put('user:' + session.username, JSON.stringify(userData));
  return json({ success: true });
}

// ===== 设昵称 =====
async function handleSetNickname(request, env) {
  const sessToken = getCookie(request, 'sess_token');
  if (!sessToken) return json({ error: '未登录' }, 401);
  const session = await env.USERS.get('sess:' + sessToken, 'json');
  if (!session) return json({ error: '未登录' }, 401);

  let body;
  try { body = await request.json(); } catch(e) { return json({ error: '无效请求' }, 400); }
  const { nickname } = body;
  const userData = await env.USERS.get('user:' + session.username, 'json');
  userData.nickname = nickname || '';
  await env.USERS.put('user:' + session.username, JSON.stringify(userData));
  return json({ success: true });
}

// ===== 模型列表 =====
async function handleModels(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return json({ error: '需要API Key' }, 401);
  const key = auth.slice(7);

  // 验证 key
  let keyValid = false;
  const allKeys = await env.API_KEYS.list();
  for (let k of allKeys.keys) {
    let d = await env.API_KEYS.get(k.name, 'json');
    if (d && d.key === key) { keyValid = true; break; }
  }
  if (!keyValid) return json({ error: '无效的API Key' }, 401);

  const upstreamRes = await fetch('https://ai.mrcwoods.com/v1/models', {
    headers: { 'Authorization': 'Bearer ' + key }
  });
  return new Response(upstreamRes.body, {
    status: upstreamRes.status,
    headers: { 'Content-Type': 'application/json' }
  });
}

// ===== 聊天 =====
async function handleChat(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return json({ error: '需要API Key' }, 401);
  const key = auth.slice(7);

  // 验证 key + 额度
  let keyData = null;
  let keyName = null;
  const allKeys = await env.API_KEYS.list();
  for (let k of allKeys.keys) {
    let d = await env.API_KEYS.get(k.name, 'json');
    if (d && d.key === key) { keyData = d; keyName = k.name; break; }
  }
  if (!keyData) return json({ error: '无效的API Key' }, 401);
  if ((keyData.usedTokens || 0) >= (keyData.tokenLimit || 100000)) return json({ error: '额度已用完' }, 403);

  const body = await request.json();

  const upstreamRes = await fetch('https://ai.mrcwoods.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + key
    },
    body: JSON.stringify(body)
  });

  // 非流式直接返回
  if (!body.stream) {
    const resData = await upstreamRes.json();
    const used = resData.usage?.total_tokens || 0;
    keyData.usedTokens = (keyData.usedTokens || 0) + used;
    await env.API_KEYS.put(keyName, JSON.stringify(keyData));
    return new Response(JSON.stringify(resData), { headers: { 'Content-Type': 'application/json' } });
  }

  // 流式透传
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const reader = upstreamRes.body.getReader();

  (async () => {
    let totalChars = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        totalChars += value.length;
        writer.write(value);
      }
      const estTokens = Math.ceil(totalChars / 4);
      keyData.usedTokens = (keyData.usedTokens || 0) + estTokens;
      await env.API_KEYS.put(keyName, JSON.stringify(keyData));
    } catch(e) {}
    writer.close();
  })();

  return new Response(readable, {
    status: upstreamRes.status,
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive'
    }
  });
}
