var WORKER = 'https://ai-api-key.harry-hhx.workers.dev';
var currentKey = '';

function api(path, opts) {
  opts = opts || {};
  opts.credentials = 'include';
  return fetch(WORKER + path, opts).then(function(r) {
    if (r.status === 401) { location.reload(); return Promise.reject(); }
    return r;
  });
}

// 登录/注册
var isReg = false;
document.getElementById('authSwitch').onclick = function() {
  isReg = !isReg;
  document.getElementById('authTitle').textContent = isReg ? '注册' : '登录';
  document.getElementById('authBtn').textContent = isReg ? '注册' : '登录';
  document.getElementById('authSwitch').textContent = isReg ? '已有账号？去登录' : '没有账号？去注册';
  document.getElementById('authMsg').textContent = '';
};
document.getElementById('authBtn').onclick = function() {
  var u = document.getElementById('user').value.trim();
  var p = document.getElementById('pwd').value;
  if (!u || !p) { document.getElementById('authMsg').textContent = '请填写完整'; return; }
  var endpoint = isReg ? '/api/register' : '/api/login';
  fetch(WORKER + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username: u, password: p })
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.success) {
      document.getElementById('auth').style.display = 'none';
      document.getElementById('app').style.display = 'block';
      currentKey = d.apiKey || '';
      loadKeys();
    } else {
      document.getElementById('authMsg').textContent = d.error;
    }
  });
};

// 自动检查登录
api('/api/me').then(function(r) { return r.json(); }).then(function(d) {
  if (d.success) {
    document.getElementById('auth').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    currentKey = d.apiKey || '';
    loadKeys();
  }
}).catch(function() {});

// 面板切换
function showPanel(name) {
  document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
  document.getElementById(name + 'Panel').classList.add('active');
  if (name === 'keys') loadKeys();
  if (name === 'account') loadAccount();
}

// 加载 Keys
function loadKeys() {
  api('/api/my-keys').then(function(r) { return r.json(); }).then(function(d) {
    var list = document.getElementById('keyList');
    list.innerHTML = '';
    if (!d.success) return;
    d.keys.forEach(function(k) {
      var pct = Math.min(100, (k.usedTokens / k.tokenLimit) * 100);
      var div = document.createElement('div');
      div.className = 'card';
      div.innerHTML =
        '<div style="font-size:12px;color:rgba(255,255,255,0.4);">' + (k.isPrimary ? '主 Key' : '自建 Key') + '</div>' +
        '<div class="key-text">' + k.key + '</div>' +
        '<div style="font-size:12px;">已用 ' + k.usedTokens + ' / ' + k.tokenLimit + ' | 剩余 ' + k.remaining + '</div>' +
        '<div class="progress"><div class="progress-fill" style="width:' + pct + '%"></div></div>' +
        '<div class="actions">' +
        '<button onclick="copyKey(\'' + k.key + '\')">复制</button>' +
        '<button class="primary" onclick="useKey(\'' + k.key + '\')">使用</button>' +
        (k.isPrimary ? '' : '<button class="danger" onclick="deleteKey(\'' + k.key + '\')">删除</button>') +
        '</div>';
      list.appendChild(div);
    });
  });
}

function copyKey(k) { navigator.clipboard.writeText(k).then(function() { alert('已复制'); }); }
function useKey(k) { currentKey = k; document.getElementById('apiKeyInput').value = k; showPanel('chat'); }

function createKey() {
  api('/api/create-my-key', { method: 'POST' }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.success) { alert('创建成功'); loadKeys(); } else alert(d.error);
  });
}

function deleteKey(k) {
  if (!confirm('确定删除？')) return;
  api('/api/delete-my-key?key=' + encodeURIComponent(k), { method: 'DELETE' }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.success) loadKeys(); else alert(d.error);
  });
}

function redeem() {
  var code = document.getElementById('redeemCode').value.trim();
  if (!code) { alert('请输入兑换码'); return; }
  api('/api/redeem', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: code }) })
    .then(function(r) { return r.json(); }).then(function(d) {
      if (d.success) { alert('兑换成功'); document.getElementById('redeemCode').value = ''; loadKeys(); } else alert(d.error);
    });
}

// 聊天
function loadModels() {
  if (!currentKey) { alert('请先选择一个 Key'); return; }
  api('/v1/models', { headers: { 'Authorization': 'Bearer ' + currentKey } })
    .then(function(r) { return r.json(); }).then(function(d) {
      var sel = document.getElementById('model'); sel.innerHTML = '';
      (d.data || []).forEach(function(m) { var o = document.createElement('option'); o.value = m.id; o.textContent = m.id; sel.appendChild(o); });
    });
}

function send() {
  if (!currentKey) { alert('请先选择 Key'); return; }
  var msg = document.getElementById('message').value.trim();
  var model = document.getElementById('model').value;
  if (!msg || !model) { alert('输入消息并加载模型'); return; }
  var area = document.getElementById('chatArea');
  var u = document.createElement('div'); u.className = 'chat-msg chat-user'; u.textContent = msg; area.appendChild(u);
  document.getElementById('message').value = '';
  var ai = document.createElement('div'); ai.className = 'chat-msg chat-ai'; area.appendChild(ai); area.scrollTop = area.scrollHeight;
  api('/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + currentKey },
    body: JSON.stringify({ model: model, messages: [{ role: 'user', content: msg }], stream: true })
  }).then(function(res) {
    if (!res.ok) { res.json().then(function(e) { ai.className = 'chat-msg chat-err'; ai.textContent = e.error; }); return; }
    var reader = res.body.getReader(); var dec = new TextDecoder(); var text = '';
    function read() {
      return reader.read().then(function(r) {
        if (r.done) return;
        var lines = dec.decode(r.value, { stream: true }).split('\n');
        for (var i = 0; i < lines.length; i++) {
          var line = lines[i];
          if (line.indexOf('data: ') === 0 && line !== 'data: [DONE]') {
            try { var j = JSON.parse(line.slice(6)); var c = j.choices && j.choices[0] && j.choices[0].delta && j.choices[0].delta.content; if (c) { text += c; ai.textContent = text; } } catch(e) {}
          }
        }
        area.scrollTop = area.scrollHeight;
        return read();
      });
    }
    read();
  });
}

// 账户
function loadAccount() {
  api('/api/me').then(function(r) { return r.json(); }).then(function(d) {
    if (!d.success) return;
    document.getElementById('accUser').textContent = d.username;
    document.getElementById('accNick').textContent = d.nickname || '(未设置)';
    document.getElementById('accUsed').textContent = d.usedTokens;
    document.getElementById('accTotal').textContent = d.tokenLimit;
  });
}

function saveNick() {
  var n = document.getElementById('nickname').value.trim();
  api('/api/set-nickname', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nickname: n }) })
    .then(function(r) { return r.json(); }).then(function(d) { if (d.success) { alert('已保存'); loadAccount(); } });
}

function changePwd() {
  var o = document.getElementById('oldPwd').value;
  var n = document.getElementById('newPwd').value;
  var c = document.getElementById('confirmPwd').value;
  if (!o || !n || !c) { alert('请填写完整'); return; }
  api('/api/change-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ oldPassword: o, newPassword: n, confirmPassword: c }) })
    .then(function(r) { return r.json(); }).then(function(d) { if (d.success) alert('修改成功'); else alert(d.error); });
}

function logout() {
  api('/api/logout', { method: 'POST' }).then(function() { location.reload(); });
}
