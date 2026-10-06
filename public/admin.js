var WORKER = '';

function api(path, opts) {
  opts = opts || {};
  opts.credentials = 'include';
  return fetch(WORKER + path, opts).then(function(r) {
    if (r.status === 401) { location.reload(); return Promise.reject(); }
    return r;
  });
}

// 管理员登录（复用普通登录，Worker 端校验 role）
function adminLogin() {
  var u = document.getElementById('adminUser').value.trim();
  var p = document.getElementById('adminPwd').value;
  fetch(WORKER + '/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username: u, password: p })
  }).then(function(r) { return r.json(); }).then(function(d) {
    if (d.success) {
      // 登录成功后检查是不是管理员
      api('/api/me').then(function(r) { return r.json(); }).then(function(me) {
        // 这里简单判断：用户名是 admin 或者你预设的管理员名
        // 实际应该 Worker 返回 role 字段
        if (me.username === 'admin') {
          document.getElementById('adminAuth').style.display = 'none';
          document.getElementById('adminApp').style.display = 'block';
          loadKeys();
          loadGifts();
        } else {
          document.getElementById('adminMsg').textContent = '不是管理员';
        }
      });
    } else {
      document.getElementById('adminMsg').textContent = d.error;
    }
  });
}

function createKey() {
  var limit = parseInt(document.getElementById('keyLimit').value) || 100000;
  var note = document.getElementById('keyNote').value;
  api('/admin/create-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tokenLimit: limit, note: note }) })
    .then(function(r) { return r.json(); }).then(function(d) {
      if (d.success) { document.getElementById('keyMsg').textContent = '创建成功: ' + d.key; loadKeys(); }
      else document.getElementById('keyMsg').textContent = d.error;
    });
}

function loadKeys() {
  api('/admin/list-keys').then(function(r) { return r.json(); }).then(function(d) {
    var list = document.getElementById('keyList'); list.innerHTML = '';
    (d.keys || []).forEach(function(k) {
      var div = document.createElement('div'); div.className = 'card';
      div.innerHTML = '<div class="key-text">' + k.key + '</div><div style="font-size:12px;">已用 ' + k.usedTokens + ' / ' + k.tokenLimit + ' | ' + (k.note || '') + '</div><div class="actions"><button onclick="resetKey(\'' + k.key + '\')">重置</button><button class="danger" onclick="deleteKey(\'' + k.key + '\')">删除</button></div>';
      list.appendChild(div);
    });
  });
}

function resetKey(k) {
  api('/admin/reset-key', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key: k }) })
    .then(function() { loadKeys(); });
}

function deleteKey(k) {
  if (!confirm('确定删除？')) return;
  api('/admin/delete-key?key=' + encodeURIComponent(k), { method: 'DELETE' })
    .then(function() { loadKeys(); });
}

function createGifts() {
  var count = parseInt(document.getElementById('giftCount').value) || 1;
  var tokens = parseInt(document.getElementById('giftTokens').value) || 1000;
  api('/admin/create-gift', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ count: count, tokens: tokens }) })
    .then(function(r) { return r.json(); }).then(function(d) {
      if (d.success) { document.getElementById('giftMsg').textContent = '生成了 ' + d.codes.length + ' 个'; loadGifts(); }
      else document.getElementById('giftMsg').textContent = d.error;
    });
}

function loadGifts() {
  api('/admin/list-gifts').then(function(r) { return r.json(); }).then(function(d) {
    var list = document.getElementById('giftList'); list.innerHTML = '';
    (d.gifts || []).forEach(function(g) {
      var div = document.createElement('div'); div.className = 'card';
      div.innerHTML = '<span style="font-family:monospace;">' + g.code + '</span> <span style="font-size:12px;">(' + g.tokens + ')</span> <span style="font-size:12px;color:' + (g.used ? '#ff6b6b' : '#51cf66') + '">' + (g.used ? '已用' : '未用') + '</span>';
      list.appendChild(div);
    });
  });
}
