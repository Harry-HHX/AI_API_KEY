export async function onRequestPost(context) {
  const { env, request } = context;
  const { USERS, API_KEYS } = env;
  
  let body;
  try { body = await request.json(); } catch(e) { return json({ error: '无效请求' }, 400); }
  
  const { username, password } = body;
  if (!username || !password) return json({ error: '请填写用户名和密码' }, 400);
  
  const userData = await USERS.get('user:' + username, 'json');
  if (!userData || userData.password !== password) {
    return json({ error: '用户名或密码错误' }, 401);
  }
  
  // 创建 session
  const sessToken = crypto.randomUUID();
  const session = { username, createdAt: Date.now() };
  await USERS.put('sess:' + sessToken, JSON.stringify(session), { expirationTtl: 604800 });
  
  // 获取或创建 API Key
  let keys = await API_KEYS.list({ prefix: 'user:' + username + ':' });
  let apiKey = '';
  if (keys.keys.length === 0) {
    apiKey = 'sk_' + crypto.randomUUID().replace(/-/g, '');
    await API_KEYS.put('user:' + username + ':primary', JSON.stringify({
      key: apiKey, isPrimary: true, tokenLimit: 1000000, usedTokens: 0, createdAt: Date.now()
    }));
  } else {
    let primary = null;
    for (let k of keys.keys) {
      let d = await API_KEYS.get(k.name, 'json');
      if (d && d.isPrimary) { primary = d; break; }
    }
    if (primary) apiKey = primary.key;
  }
  
  const headers = new Headers({ 'Content-Type': 'application/json' });
  headers.append('Set-Cookie', `sess_token=${sessToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`);
  
  return new Response(JSON.stringify({ success: true, apiKey }), { headers });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });
}
