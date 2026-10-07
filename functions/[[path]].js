// functions/[[path]].js

const WORKERS_AI_MODELS = [
  { id: '@cf/deepseek-ai/deepseek-v4-flash-0731', name: 'DeepSeek V4 Flash' },
  { id: '@cf/qwen/qwen3-30b-a3b-fp8', name: 'Qwen3 30B A3B' },
  { id: '@cf/meta/llama-3.1-8b-instruct', name: 'Llama 3.1 8B' },
  { id: '@cf/meta/llama-3.1-8b-instruct-fp8-fast', name: 'Llama 3.1 8B Fast' }
];

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

function friendlyError(status, body) {
  if (status === 4006 || (body && body.includes && (body.includes('neurons') || body.includes('daily')))) {
    return { error: '免费额度已用完，明天 UTC 0 点重置，或联系管理员升级' };
  }
  if (status === 429) return { error: '请求太频繁，请稍后再试' };
  if (status === 400 && body && body.includes && body.includes('model')) return { error: '模型不可用，请换一个' };
  if (status >= 500) return { error: '上游服务暂时不可用，请稍后重试' };
  try {
    const parsed = JSON.parse(body);
    if (parsed.errors && parsed.errors[0]) return { error: parsed.errors[0].message || body };
  } catch(e) {}
  return { error: '请求失败，请重试' };
}

async function handleLogin(request, env) {
  const { username, password } = await request.json();
  const userData = await env.USERS.get(username);
  if (!userData) return json({ error: '用户不存在' }, 401);
  const user = JSON.parse(userData);
  if (user.password !== password) return json({ error: '密码错误' }, 401);
  const token = crypto.randomUUID();
  await env.USERS.put(username, JSON.stringify({ ...user, token }));
  // 不再设 Cookie，只返回 token
  return json({ token });
}

async function verifyAuth(request, env) {
  // 先从 Authorization 头读
  const auth = request.headers.get('Authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.slice(7);
    const allUsers = await env.USERS.list();
    for (const u of allUsers.keys) {
      const d = await env.USERS.get(u.name);
      if (d) {
        const user = JSON.parse(d);
        if (user.token === token) return user;
      }
    }
  }
  // 兜底：从 Cookie 读
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/auth_token=([^;]+)/);
  if (!match) return null;
  const token = match[1];
  const allUsers = await env.USERS.list();
  for (const u of allUsers.keys) {
    const d = await env.USERS.get(u.name);
    if (d) {
      const user = JSON.parse(d);
      if (user.token === token) return user;
    }
  }
  return null;
}

async function handleModels(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return json({ error: '需要API Key' }, 401);
  const key = auth.slice(7);

  const all = await env.API_KEYS.list();
  let ok = false;
  for (const k of all.keys) {
    const d = await env.API_KEYS.get(k.name, 'json');
    if (d && d.key === key) { ok = true; break; }
  }
  if (!ok) return json({ error: '无效的API Key' }, 401);

  await new Promise(r => setTimeout(r, Math.floor(Math.random() * 9000) + 1000));

  return json({ data: WORKERS_AI_MODELS.map(m => ({ id: m.id, name: m.name })) });
}

async function handleChat(request, env) {
  const auth = request.headers.get('Authorization');
  if (!auth || !auth.startsWith('Bearer ')) return json({ error: '需要API Key' }, 401);
  const userKey = auth.slice(7);

  let keyData = null, keyName = null;
  const all = await env.API_KEYS.list();
  for (const k of all.keys) {
    const d = await env.API_KEYS.get(k.name, 'json');
    if (d && d.key === userKey) { keyData = d; keyName = k.name; break; }
  }
  if (!keyData) return json({ error: '无效的API Key' }, 401);
  if ((keyData.usedTokens || 0) >= (keyData.tokenLimit || 100000)) return json({ error: '额度已用完' }, 403);

  const body = await request.json();
  if (!body.model || !body.model.startsWith('@cf/')) {
    return json({ error: '请选择列表中的模型' }, 400);
  }

  const url = `https://api.cloudflare.com/client/v4/accounts/${env.CF_ACCOUNT_ID}/ai/v1/chat/completions`;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 30000);

  let upstreamRes;
  try {
    upstreamRes = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + env.CF_API_TOKEN
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
  } catch (e) {
    clearTimeout(timeoutId);
    if (e.name === 'AbortError') return json({ error: '请求超时（30秒），上游响应太慢，请重试' }, 504);
    return json({ error: '网络错误，无法连接上游' }, 502);
  }
  clearTimeout(timeoutId);

  if (!upstreamRes.ok) {
    const errBody = await upstreamRes.text();
    const friendly = friendlyError(upstreamRes.status, errBody);
    return json(friendly, upstreamRes.status);
  }

  if (!body.stream) {
    const data = await upstreamRes.json();
    const used = data.usage?.total_tokens || Math.ceil(JSON.stringify(body).length / 4);
    keyData.usedTokens = (keyData.usedTokens || 0) + used;
    await env.API_KEYS.put(keyName, JSON.stringify(keyData));
    const responseData = { ...data };
    const remaining = (keyData.tokenLimit || 100000) - keyData.usedTokens;
    if (remaining < 1000) {
      responseData._warning = `⚠️ 你的剩余额度仅剩 ${remaining} tokens，快用完了`;
    }
    return new Response(JSON.stringify(responseData), { headers: { 'Content-Type': 'application/json' } });
  }

  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const reader = upstreamRes.body.getReader();

  (async () => {
    let disconnected = false;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) { if (!disconnected) writer.close(); break; }
        await writer.write(value);
      }
    } catch (e) {
      disconnected = true;
      const retryMsg = `data: ${JSON.stringify({ error: '连接中断，请重试', _retry: true })}\n\n`;
      try { await writer.write(new TextEncoder().encode(retryMsg)); } catch(e2) {}
      writer.close();
    }
  })();

  return new Response(readable, {
    status: upstreamRes.status,
    headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' }
  });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type,Authorization' } });
  }

  if (path === '/api/login' && request.method === 'POST') return handleLogin(request, env);
  if (path === '/v1/models' && request.method === 'GET') return handleModels(request, env);
  if (path === '/v1/chat/completions' && request.method === 'POST') return handleChat(request, env);

  // 静态文件回退
  return fetch(request);
}
