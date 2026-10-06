alert('app.js loaded');

var WORKER = 'https://ai-api-key.harry-hhx.workers.dev';

var isReg = false;

function authSwitch() {
  isReg = !isReg;
  document.getElementById('authTitle').textContent = isReg ? '注册' : '登录';
  document.getElementById('authBtn').textContent = isReg ? '注册' : '登录';
  document.getElementById('authSwitch').textContent = isReg ? '已有账号？去登录' : '没有账号？去注册';
  document.getElementById('authMsg').textContent = '';
}

function authBtnClick() {
  alert('按钮点了！');
  var u = document.getElementById('user').value.trim();
  var p = document.getElementById('pwd').value;
  if (!u || !p) { document.getElementById('authMsg').textContent = '请填写完整'; return; }
  var endpoint = isReg ? '/api/register' : '/api/login';
  alert('准备请求: ' + endpoint);
  fetch(WORKER + endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username: u, password: p })
  }).then(function(r) {
    alert('收到响应 status: ' + r.status);
    return r.json();
  }).then(function(d) {
    alert('响应内容: ' + JSON.stringify(d));
    if (d.success) {
      document.getElementById('auth').style.display = 'none';
      document.getElementById('app').style.display = 'block';
    } else {
      document.getElementById('authMsg').textContent = d.error;
    }
  }).catch(function(e) {
    alert('出错了: ' + e);
  });
}

document.getElementById('authSwitch').onclick = authSwitch;
document.getElementById('authBtn').onclick = authBtnClick;

alert('事件绑定完成');
