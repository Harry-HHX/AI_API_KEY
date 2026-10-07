// public/app.js

const WORKER = '';

// ========== 登录 ==========
async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const res = await fetch(WORKER + '/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });

  const data = await res.json();
  if (res.ok) {
    document.getElementById('loginSection').style.display = 'none';
    document.getElementById('mainSection').style.display = 'block';
  } else {
    alert(data.error || '登录失败');
  }
}

// ========== 获取 API Key ==========
function getApiKey() {
  return document.getElementById('apiKey').value.trim();
}

// ========== 加载模型 ==========
async function loadModels() {
  const btn = document.getElementById('loadModelsBtn');
  const select = document.getElementById('modelSelect');
  const loading = document.getElementById('modelLoading');

  btn.disabled = true;
  btn.textContent = '请求中...';
  loading.style.display = 'inline-block';
  select.style.display = 'none';
  select.innerHTML = '<option value="">-- 请选择模型 --</option>';

  try {
    const res = await fetch(WORKER + '/v1/models', {
      headers: { 'Authorization': 'Bearer ' + getApiKey() }
    });
    const data = await res.json();

    if (!res.ok) {
      alert(data.error || '加载模型失败');
      return;
    }

    data.data.forEach(m => {
      const opt = document.createElement('option');
      opt.value = m.id;
      opt.textContent = m.name;
      select.appendChild(opt);
    });

    select.style.display = 'inline-block';

  } catch (e) {
    alert('网络错误，请重试');
  } finally {
    btn.disabled = false;
    btn.textContent = '加载模型';
    loading.style.display = 'none';
  }
}

// ========== 发送消息 ==========
async function sendMessage() {
  const model = document.getElementById('modelSelect').value;
  const message = document.getElementById('messageInput').value;
  const output = document.getElementById('output');

  if (!model) { alert('请先加载并选择模型'); return; }
  if (!message.trim()) { alert('请输入内容'); return; }

  output.textContent = '思考中...';

  try {
    const res = await fetch(WORKER + '/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + getApiKey()
      },
      body: JSON.stringify({
        model: model,
        messages: [{ role: 'user', content: message }],
        stream: false
      })
    });

    const data = await res.json();
    if (!res.ok) {
      output.textContent = data.error || '请求失败';
      return;
    }

    const reply = data.choices?.[0]?.message?.content || '（无回复）';
    output.textContent = reply;

    if (data._warning) {
      alert(data._warning);
    }

  } catch (e) {
    output.textContent = '网络错误：' + e.message;
  }
}
