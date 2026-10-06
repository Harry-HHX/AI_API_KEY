// app.js - 修复版
(function() {
  'use strict';

  var WORKER = 'https://ai-api-key.harry-hhx.workers.dev';
  var currentKey = '';

  function api(path, opts) {
    opts = opts || {};
    opts.credentials = 'include';
    return fetch(WORKER + path, opts).then(function(r) {
      if (r.status === 401) { location.reload(); return Promise.reject('unauthorized'); }
      return r;
    }).catch(function(e) {
      console.error('API error:', e);
      return Promise.reject(e);
    });
  }

  function onDOMReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else {
      fn();
    }
  }

  onDOMReady(function() {
    console.log('DOM ready, binding events');

    // 登录/注册切换
    var isReg = false;
    var authSwitch = document.getElementById('authSwitch');
    if (authSwitch) {
      authSwitch.onclick = function() {
        isReg = !isReg;
        var title = document.getElementById('authTitle');
        var btn = document.getElementById('authBtn');
        var sw = document.getElementById('authSwitch');
        var msg = document.getElementById('authMsg');
        if (title) title.textContent = isReg ? '注册' : '登录';
        if (btn) btn.textContent = isReg ? '注册' : '登录';
        if (sw) sw.textContent = isReg ? '已有账号？去登录' : '没有账号？去注册';
        if (msg) msg.textContent = '';
      };
    }

    // 登录按钮
    var authBtn = document.getElementById('authBtn');
    if (authBtn) {
      authBtn.onclick = function() {
        console.log('authBtn clicked');
        var uEl = document.getElementById('user');
        var pEl = document.getElementById('pwd');
        var msgEl = document.getElementById('authMsg');
        if (!uEl || !pEl) { console.error('input not found'); return; }
        var u = uEl.value.trim();
        var p = pEl.value;
        if (!u || !p) { if (msgEl) msgEl.textContent = '请填写完整'; return; }
        var endpoint = isReg ? '/api/register' : '/api/login';
        fetch(WORKER + endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ username: u, password: p })
        }).then(function(r) { return r.json(); }).then(function(d) {
          console.log('auth response:', d);
          if (d.success) {
            var authEl = document.getElementById('auth');
            var appEl = document.getElementById('app');
            if (authEl) authEl.style.display = 'none';
            if (appEl) appEl.style.display = 'block';
            currentKey = d.apiKey || '';
            loadKeys();
          } else {
            if (msgEl) msgEl.textContent = d.error || '操作失败';
          }
        }).catch(function(e) {
          console.error('auth error:', e);
          if (msgEl) msgEl.textContent = '网络错误，请重试';
        });
      };
    }

    // 自动检查登录
    fetch(WORKER + '/api/me', { credentials: 'include' })
      .then(function(r) { return r.json(); })
      .then(function(d) {
        console.log('me response:', d);
        if (d && d.success) {
          var authEl = document.getElementById('auth');
          var appEl = document.getElementById('app');
          if (authEl) authEl.style.display = 'none';
          if (appEl) appEl.style.display = 'block';
          currentKey = d.apiKey || '';
          loadKeys();
        }
      })
      .catch(function(e) { console.log('me check failed:', e); });

    // 面板切换
    window.showPanel = function(name) {
      var panels = document.querySelectorAll('.panel');
      for (var i = 0; i < panels.length; i++) panels[i].classList.remove('active');
      var target = document.getElementById(name + 'Panel');
      if (target) target.classList.add('active');
      if (name === 'keys') loadKeys();
      if (name === 'account') loadAccount();
    };

    // 加载 Keys
    function loadKeys() {
      api('/api/my-keys').then(function(r) { return r.json(); }).then(function(d) {
        var list = document.getElementById('keyList');
        if (!list) return;
        list.innerHTML = '';
        if (!d.success) return;
        for (var i = 0; i < d.keys.length; i++) {
          var k = d.keys[i];
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
        }
      }).catch(function(e) { console.error('loadKeys error:', e); });
    }

    // 复制到全局
    window.copyKey = function(k) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(k).then(function() { alert('已复制'); }).catch(function() { alert('复制失败'); });
      } else {
        alert('当前浏览器不支持复制');
      }
    };
    window.useKey = function(k) { currentKey = k; var input = document.getElementById('apiKeyInput'); if (input) input.value = k; window.showPanel('chat'); };
    window.createKey = function() {
      api('/api/create-my-key', { method: 'POST' }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.success) { alert('创建成功'); loadKeys(); } else alert(d.error || '创建失败');
      });
    };
    window.deleteKey = function(k) {
      if (!confirm('确定删除？')) return;
      api('/api/delete-my-key?key=' + encodeURIComponent(k), { method: 'DELETE' }).then(function(r) { return r.json(); }).then(function(d) {
        if (d.success) loadKeys(); else alert(d.error || '删除失败');
      });
    };
    window.redeem = function() {
      var codeEl = document.getElementById('redeemCode');
      if (!codeEl) return;
      var code = codeEl.value.trim();
      if (!code) { alert('请输入兑换码'); return; }
      api('/api/redeem', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: code }) })
        .then(function(r) { return r.json(); }).then(function(d) {
          if (d.success) { alert('兑换成功'); codeEl.value = ''; loadKeys(); } else alert(d.error || '兑换失败');
        });
    };
    window.loadModels = function() {
      if (!currentKey) { alert('请先选择一个 Key'); return; }
      api('/v1/models', { headers: { 'Authorization': 'Bearer ' + currentKey } })
        .then(function(r) { return r.json(); }).then(function(d) {
          var sel = document.getElementById('model'); if (!sel) return; sel.innerHTML = '';
          var models = d.data || [];
          for (var i = 0; i < models.length; i++) { var o = document.createElement('option'); o.value = models[i].id; o.textContent = models[i].id; sel.appendChild(o); }
        });
    };
    window.send = function() {
      if (!currentKey) { alert('请先选择 Key'); return; }
      var msgEl = document.getElementById('message');
      var modelEl = document.getElementById('model');
      if (!msgEl || !modelEl) return;
      var msg = msgEl.value.trim();
      var model = modelEl.value;
      if (!msg || !model) { alert('输入消息并加载模型'); return; }
      var area = document.getElementById('chatArea'); if (!area) return;
      var u = document.createElement('div'); u.className = 'chat-msg chat-user'; u.textContent = msg; area.appendChild(u);
      msgEl.value = '';
      var ai = document.createElement('div'); ai.className = 'chat-msg chat-ai'; area.appendChild(ai); area.scrollTop = area.scrollHeight;
      api('/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + currentKey },
        body: JSON.stringify({ model: model, messages: [{ role: 'user', content: msg }], stream: true })
      }).then(function(res) {
        if (!res.ok) { res.json().then(function(e) { ai.className = 'chat-msg chat-err'; ai.textContent = e.error || '请求失败'; }); return; }
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
      }).catch(function(e) { ai.className = 'chat-msg chat-err'; ai.textContent = '发送失败'; });
    };
    window.loadAccount = function() {
      api('/api/me').then(function(r) { return r.json(); }).then(function(d) {
        if (!d.success) return;
        var el;
        el = document.getElementById('accUser'); if (el) el.textContent = d.username || '';
        el = document.getElementById('accNick'); if (el) el.textContent = d.nickname || '(未设置)';
        el = document.getElementById('accUsed'); if (el) el.textContent = d.usedTokens || 0;
        el = document.getElementById('accTotal'); if (el) el.textContent = d.tokenLimit || DEFAULT_TOKEN_LIMIT;
      });
    };
    window.saveNick = function() {
      var nEl = document.getElementById('nickname');
      if (!nEl) return;
      var n = nEl.value.trim();
      api('/api/set-nickname', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nickname: n }) })
        .then(function(r) { return r.json(); }).then(function(d) { if (d.success) { alert('已保存'); window.loadAccount(); } });
    };
    window.changePwd = function() {
      var o = document.getElementById('oldPwd');
      var n = document.getElementById('newPwd');
      var c = document.getElementById('confirmPwd');
      if (!o || !n || !c) { alert('请填写完整'); return; }
      if (!o.value || !n.value || !c.value) { alert('请填写完整'); return; }
      if (n.value !== c.value) { alert('两次密码不一致'); return; }
      api('/api/change-password', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ oldPassword: o.value, newPassword: n.value, confirmPassword: c.value }) })
        .then(function(r) { return r.json(); }).then(function(d) { if (d.success) alert('修改成功'); else alert(d.error || '修改失败'); });
    };
    window.logout = function() {
      api('/api/logout', { method: 'POST' }).then(function() { location.reload(); }).catch(function() { location.reload(); });
    };

    console.log('All events bound, app ready');
  });
})();
