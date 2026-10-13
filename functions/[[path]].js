export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      }
    });
  }

  const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

  try {

    // ===== 用户注册 =====
    if (path === '/api/register' && method === 'POST') {
      const body = await request.json();
      const { username, password, tfa } = body;
      const bcrypt = await import('bcryptjs');
      const hash = await bcrypt.hash(password, 10);
      await env.DB.prepare('INSERT INTO users (username, password_hash, tfa_secret, created_at) VALUES (?, ?, ?, ?)')
        .bind(username, hash, tfa || null, Date.now()).run();
      return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
    }

    // ===== 用户登录 =====
    if (path === '/api/login' && method === 'POST') {
      const body = await request.json();
      const { username, password } = body;
      const bcrypt = await import('bcryptjs');
      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      if (!user || !(await bcrypt.compare(password, user.password_hash))) {
        return new Response(JSON.stringify({ ok: false, msg: '账号或密码错误' }), { headers: corsHeaders });
      }
      const token = 'sk_' + crypto.randomUUID().replace(/-/g, '');
      await env.DB.prepare('INSERT INTO sessions (token, username) VALUES (?, ?)').bind(token, username).run();
      return new Response(JSON.stringify({ ok: true, token }), { headers: corsHeaders });
    }

    // ===== 验证 session =====
    if (path === '/api/me' && method === 'GET') {
      const token = url.searchParams.get('t');
      const session = await env.DB.prepare('SELECT username FROM sessions WHERE token = ?').bind(token).first();
      if (!session) return new Response(JSON.stringify({ ok: false }), { headers: corsHeaders });
      const user = await env.DB.prepare('SELECT username, created_at, tfa_secret FROM users WHERE username = ?').bind(session.username).first();
      return new Response(JSON.stringify({
        ok: true,
        user: { username: user.username, created_at: user.created_at, tfa_enabled: !!user.tfa_secret }
      }), { headers: corsHeaders });
    }

    // ===== 聊天 =====
    if (path === '/api/chat' && method === 'POST') {
      const body = await request.json();
      const { message, model } = body;
      const modelMap = {
        'llama': '@cf/meta/llama-3.1-8b-instruct',
        'mistral': '@cf/mistral/mistral-7b-instruct-v0.1',
        'gemma': '@cf/google/gemma-2-9b-it',
        'qwen': '@cf/qwen/qwen1.5-7b-chat'
      };
      const target = modelMap[model] || modelMap['llama'];
      const aiResp = await env.AI.run(target, { messages: [{ role: 'user', content: message }] });
      return new Response(JSON.stringify({ ok: true, reply: aiResp.response || aiResp.text || '无回复' }), { headers: corsHeaders });
    }

    // ===== 创建 API Key =====
    if (path === '/api/keys/create' && method === 'POST') {
      const body = await request.json();
      const { token, name } = body;
      const session = await env.DB.prepare('SELECT username FROM sessions WHERE token = ?').bind(token).first();
      if (!session) return new Response(JSON.stringify({ ok: false, msg: '未登录' }), { headers: corsHeaders });
      const key = 'ak_' + crypto.randomUUID().replace(/-/g, '');
      await env.DB.prepare('INSERT INTO api_keys (key_value, username, name, created_at) VALUES (?, ?, ?, ?)').bind(key, session.username, name || 'default', Date.now()).run();
      return new Response(JSON.stringify({ ok: true, key, name }), { headers: corsHeaders });
    }

    // ===== 删除 API Key =====
    if (path.startsWith('/api/keys/delete/') && method === 'DELETE') {
      const keyId = path.split('/').pop();
      const token = url.searchParams.get('t');
      const session = await env.DB.prepare('SELECT username FROM sessions WHERE token = ?').bind(token).first();
      if (!session) return new Response(JSON.stringify({ ok: false, msg: '未登录' }), { headers: corsHeaders });
      await env.DB.prepare('DELETE FROM api_keys WHERE id = ? AND username = ?').bind(keyId, session.username).run();
      return new Response(JSON.stringify({ ok: true }), { headers: corsHeaders });
    }

    // ===== 获取 API Key 列表 =====
    if (path === '/api/keys/list' && method === 'GET') {
      const token = url.searchParams.get('t');
      const session = await env.DB.prepare('SELECT username FROM sessions WHERE token = ?').bind(token).first();
      if (!session) return new Response(JSON.stringify({ ok: false, msg: '未登录' }), { headers: corsHeaders });
      const keys = await env.DB.prepare('SELECT id, key_value, name, created_at FROM api_keys WHERE username = ?').bind(session.username).all();
      return new Response(JSON.stringify({ ok: true, keys: keys.results || [] }), { headers: corsHeaders });
    }

    // ===== 兑换礼品码 =====
    if (path === '/api/gift/redeem' && method === 'POST') {
      const body = await request.json();
      const { token, code } = body;
      const session = await env.DB.prepare('SELECT username FROM sessions WHERE token = ?').bind(token).first();
      if (!session) return new Response(JSON.stringify({ ok: false, msg: '未登录' }), { headers: corsHeaders });
      const gift = await env.DB.prepare('SELECT * FROM gift_codes WHERE code = ? AND used = 0').bind(code).first();
      if (!gift) return new Response(JSON.stringify({ ok: false, msg: '礼品码无效或已使用' }), { headers: corsHeaders });
      await env.DB.prepare('UPDATE gift_codes SET used = 1 WHERE code = ?').bind(code).run();
      await env.DB.prepare('INSERT INTO gift_redeem (code, username, redeemed_at) VALUES (?, ?, ?)').bind(code, session.username, Date.now()).run();
      return new Response(JSON.stringify({ ok: true, msg: '兑换成功' }), { headers: corsHeaders });
    }

    // ===== 生成礼品码 =====
    if (path === '/api/gift/generate' && method === 'POST') {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      let code = '';
      for (let i = 0; i < 8; i++) code += chars.charAt(Math.floor(Math.random() * chars.length));
      await env.DB.prepare('INSERT INTO gift_codes (code, used, created_at) VALUES (?, 0, ?)').bind(code, Date.now()).run();
      return new Response(JSON.stringify({ ok: true, code }), { headers: corsHeaders });
    }

    // ===== GitHub OAuth 开始 =====
    if (path === '/api/auth/github' && method === 'GET') {
      const githubAuthUrl = 'https://github.com/login/oauth/authorize'
        + '?client_id=' + encodeURIComponent(env.GITHUB_CLIENT_ID)
        + '&redirect_uri=' + encodeURIComponent(env.GITHUB_CALLBACK_URL)
        + '&scope=user:email';
      return Response.redirect(githubAuthUrl, 302);
    }

    // ===== GitHub OAuth 回调 =====
    if (path === '/auth/callback' && method === 'GET') {
      const code = url.searchParams.get('code');
      if (!code) return new Response('Missing code', { status: 400 });

      const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: JSON.stringify({ client_id: env.GITHUB_CLIENT_ID, client_secret: env.GITHUB_CLIENT_SECRET, code, redirect_uri: env.GITHUB_CALLBACK_URL })
      });
      const tokenData = await tokenRes.json();
      const accessToken = tokenData.access_token;
      if (!accessToken) return new Response('GitHub token exchange failed', { status: 400 });

      const userRes = await fetch('https://api.github.com/user', {
        headers: { 'Authorization': 'Bearer ' + accessToken, 'Accept': 'application/json' }
      });
      const ghUser = await userRes.json();

      let user = await env.DB.prepare('SELECT * FROM users WHERE github_id = ?').bind(String(ghUser.id)).first();
      if (!user) {
        const username = ghUser.login || ('gh_' + ghUser.id);
        await env.DB.prepare('INSERT INTO users (username, github_id, avatar_url, created_at) VALUES (?, ?, ?, ?)').bind(username, String(ghUser.id), ghUser.avatar_url || null, Date.now()).run();
        user = await env.DB.prepare('SELECT * FROM users WHERE github_id = ?').bind(String(ghUser.id)).first();
      }

      const token = 'sk_' + crypto.randomUUID().replace(/-/g, '');
      await env.DB.prepare('INSERT INTO sessions (token, username) VALUES (?, ?)').bind(token, user.username).run();

      return Response.redirect('/?t=' + token, 302);
    }

    return new Response(JSON.stringify({ ok: false, msg: 'Not Found' }), { status: 404, headers: corsHeaders });

  } catch (e) {
    return new Response(JSON.stringify({ ok: false, msg: e.message }), { status: 500, headers: corsHeaders });
  }
}
