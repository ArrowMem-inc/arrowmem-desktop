// Arrowmesh screens. Draws what the loopback daemon says; stores nothing (no browser storage, no cookie, no file).
// The only way out is the Rust command mesh_call, which holds the token and speaks only to the loopback daemon.
// Words are the approved render's "[CA]" placeholders, UNCLEARED; a value the daemon sends is shown as sent.
var invoke = window.__TAURI__.core.invoke;
var PAGE = document.body.getAttribute('data-page');
function $(id) { return document.getElementById(id); }
function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }
function clear(n) { while (n.firstChild) { n.removeChild(n.firstChild); } }

// api() resolves {status, body} for ANY http status; a local refusal or an unreachable daemon rejects with a short code.
function api(method, path, body) { return invoke('mesh_call', { method: method, path: path, body: body === undefined ? null : body }); }
// Locked is HTTP 423 only. A 503 is an unhealthy daemon, not a locked vault: its error is shown as sent.
function isLocked(r) { return r.status === 423; }
function toVault() { if (PAGE !== 'vault') { location.replace('mesh-vault.html'); } }

// ---- shell: drawer behind the menu control at the narrow break, as chat.html does ----
(function () {
  var m = $('menu'), app = $('app');
  m.addEventListener('click', function () { var o = app.classList.toggle('open'); m.setAttribute('aria-expanded', o ? 'true' : 'false'); });
})();

// ---- status poll: sidebar dot, and the locked rule (locked keeps the shell on the Vault sheet) ----
var ST = null;
function applyStatus(s) {
  ST = s;
  var up = !!(s && s.model_up);
  $('acct-dot').className = 'dot' + (s ? '' : ' dot--off');
  if (s && s.vault_unlocked === false) { toVault(); }
  if (PAGE === 'chat') { $('model-dot').className = 'dot' + (up ? '' : ' dot--off'); }
  if (PAGE === 'vault') { showVault(s); }
  if (PAGE === 'status') { drawStatus(s); }
  if (PAGE === 'peers' && s) { $('psub').textContent = '[CA] reachable count ' + s.peers_reachable + ' / ' + s.peers_total; }
}
function pollStatus() {
  return api('GET', '/v1/status').then(function (r) {
    if (r.status === 200 && r.body) { applyStatus(r.body); return r.body; }
    applyStatus(null); return null;
  }).catch(function () { applyStatus(null); return null; });
}

// ---- vault ----
function showVault(s) {
  var locked = !s || s.vault_unlocked === false;
  $('locked').hidden = !locked; $('unlocked').hidden = locked;
  $('lock-now').hidden = locked;
  $('vsub').textContent = locked ? '[CA] locked state' : '[CA] unlocked state';
  if (!locked) { drawConvs(); }
}
function drawConvs() {
  api('GET', '/v1/vault/conversations').then(function (r) {
    if (isLocked(r)) { return pollStatus(); }
    var ul = $('convs'); clear(ul);
    ((r.body && r.body.conversations) || []).forEach(function (c) {
      var li = el('li', 'row');
      li.appendChild(el('span', 'row__v', c.name)); li.appendChild(el('span', 'row__n', String(c.messages)));
      ul.appendChild(li);
    });
  }).catch(function () {});
}
function initVault() {
  // Export: Rust opens the native save dialog, fetches the sealed export and writes it to the chosen path. Only a status word comes back; the bytes never reach this page.
  $('export').addEventListener('click', function () {
    var b = $('export'); b.disabled = true; $('ealert').textContent = '';
    invoke('mesh_export').then(function (r) {
      if (r.outcome === 'refused') { if (r.status === 423) { return pollStatus(); } $('ealert').textContent = String(r.status); }
    }).catch(function (e) { $('ealert').textContent = String(e); }).then(function () { b.disabled = false; });
  });
  // Lock now: POST /v1/vault/lock (v1.1, branch locked-start). A daemon without the route answers 404 or 405: the button then goes disabled.
  $('lock-now').addEventListener('click', function () {
    var b = $('lock-now'); b.disabled = true;
    api('POST', '/v1/vault/lock', {}).then(function (r) {
      if (r.status === 200) { b.disabled = false; return pollStatus(); }
      if (r.status !== 404 && r.status !== 405) { b.disabled = false; }
    }).catch(function () { b.disabled = false; });
  });
  $('unlock-form').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var p = $('pass').value;
    if (!p) { return; }
    $('pass').value = ''; // the passphrase leaves the page at once; it is never kept
    $('unlock').disabled = true; $('ualert').textContent = '';
    api('POST', '/v1/vault/unlock', { passphrase: p }).then(function (r) {
      p = null;
      if (r.status === 200) { return pollStatus(); }
      // the daemon's own error text and wait, shown as sent (401 wrong passphrase, 429 retry_after seconds)
      $('ualert').textContent = r.status + (r.body && r.body.error ? ' ' + r.body.error : '') + (r.body && r.body.retry_after ? ' ' + r.body.retry_after : '');
    }).catch(function (e) { p = null; $('ualert').textContent = String(e); }).then(function () { $('unlock').disabled = false; });
  });
}

// ---- chat ----
var CONV = decodeURIComponent((location.hash || '').slice(1)) || 'default';
function addUser(text) {
  var t = el('div', 'turn turn--user'), m = el('div', 'msg msg--user');
  m.appendChild(el('p', 'who', '[CA] you')); m.appendChild(el('p', '', text)); t.appendChild(m); $('transcript').appendChild(t); return t;
}
var BRAND = document.querySelector('.brand__mark').innerHTML;
// B: the verdict is the mark alone until clicked; the label and category names show on click.
function verdict(flag, cats) {
  var v = el('div', 'verdict'), b = el('button', 'vmark' + (flag ? ' vmark--flag' : ''));
  b.type = 'button'; b.setAttribute('aria-expanded', 'false');
  b.innerHTML = flag ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 21V4h11l-2 4 2 4H6"/></svg>' : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12l5 5 9-10"/></svg>';
  var x = el('span', 'vmark__x', flag ? '[CA] gate: ' + cats.length + ' categories' : '[CA] gate: clear'); x.hidden = true; b.appendChild(x);
  v.appendChild(b);
  var names = [];
  if (flag) { cats.forEach(function (c) { var s = el('span', 'vmark', c); s.hidden = true; names.push(s); v.appendChild(s); }); }
  b.addEventListener('click', function () { var open = x.hidden; x.hidden = !open; names.forEach(function (s) { s.hidden = !open; }); b.setAttribute('aria-expanded', open ? 'true' : 'false'); });
  return v;
}
function addAssistant(text, flag, cats, noVerdict) {
  var t = el('div', 'turn'), a = el('span', 'avatar'); a.innerHTML = BRAND;
  var m = el('div', 'msg msg--assistant');
  m.appendChild(el('p', 'who', '[CA] model name')); if (text !== null) { m.appendChild(el('p', '', text)); }
  if (!noVerdict) { m.appendChild(verdict(flag, cats || [])); }
  t.appendChild(a); t.appendChild(m); $('transcript').appendChild(t);
}
function scrollEnd() { var s = $('scroll'); s.scrollTop = s.scrollHeight; }
function drawThreads() {
  api('GET', '/v1/vault/conversations').then(function (r) {
    if (isLocked(r)) { toVault(); return; }
    var ul = $('threads'); clear(ul);
    var list = (r.body && r.body.conversations) || [];
    if (!list.some(function (c) { return c.name === CONV; })) { list = [{ name: CONV, messages: 0 }].concat(list); }
    list.forEach(function (c) {
      var li = el('li'), b = el('button', 'thread');
      b.type = 'button'; if (c.name === CONV) { b.setAttribute('aria-current', 'true'); }
      b.appendChild(el('span', 'thread__t', c.name)); b.appendChild(el('span', 'thread__d', String(c.messages)));
      b.addEventListener('click', function () { location.hash = encodeURIComponent(c.name); location.reload(); });
      li.appendChild(b); ul.appendChild(li);
    });
  }).catch(function () {});
}
function drawHistory() {
  api('GET', '/v1/history?conv=' + encodeURIComponent(CONV)).then(function (r) {
    if (isLocked(r)) { toVault(); return; }
    clear($('transcript'));
    ((r.body && r.body.entries) || []).forEach(function (e) {
      if (e.kind === 'user') { addUser(e.text); } else if (e.kind === 'assistant') { addAssistant(e.text, false, [], true); }
      // peer_in and peer_out are not in the render's transcript: not drawn here
    });
    scrollEnd();
  }).catch(function () {});
}
function alertMsg(s) { $('alert').textContent = s; }
function finishChat(status, body) {
  if (status === 200 && body && body.choices && body.choices[0]) { addAssistant(body.choices[0].message.content, false, []); }
  else if (status === 403 && body && body.blocked) { addAssistant(null, true, body.categories || []); }
  else if (body && isLocked({ status: status, body: body })) { toVault(); }
  else { alertMsg(status + (body && body.error ? ' ' + body.error : '')); }
  scrollEnd(); drawThreads();
}
function poll(job, n) {
  api('GET', '/v1/chat/jobs/' + job).then(function (r) {
    if (r.status === 200 && r.body && r.body.state === 'done') { busy(false); finishChat(r.body.status, r.body.result); }
    else if (r.status === 200 && n < 600) { setTimeout(function () { poll(job, n + 1); }, 1000); }
    else { busy(false); alertMsg(String(r.status)); }
  }).catch(function (e) { busy(false); alertMsg(String(e)); });
}
function busy(b) { $('send').disabled = b; $('msg').disabled = b; if (!b) { $('msg').focus(); } }
function initChat() {
  $('conv-title').textContent = CONV;
  drawThreads(); drawHistory();
  var ta = $('msg');
  ta.addEventListener('input', function () { $('counter').textContent = String(ta.value.length); ta.style.height = 'auto'; ta.style.height = Math.min(ta.scrollHeight, 160) + 'px'; });
  function send() {
    var text = ta.value; if (!text.trim()) { return; }
    ta.value = ''; $('counter').textContent = '0'; ta.style.height = 'auto'; alertMsg('');
    addUser(text); scrollEnd(); busy(true);
    // the whole reply is gated before any of it is shown (no streaming): ask for a job, then poll
    api('POST', '/v1/chat', { conv: CONV, messages: [{ role: 'user', content: text }], async: true }).then(function (r) {
      text = null;
      if (r.status === 202 && r.body && r.body.job !== undefined) { poll(r.body.job, 0); }
      else { busy(false); finishChat(r.status, r.body); }
    }).catch(function (e) { text = null; busy(false); alertMsg(String(e)); });
  }
  $('send').addEventListener('click', send);
  ta.addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } });
}

// ---- peers ----
function tag(on, bad, word) { var t = el('span', 'tag'); t.appendChild(el('span', 'dot' + (bad ? ' dot--bad' : (on ? '' : ' dot--off')))); t.appendChild(document.createTextNode(word)); return t; }
function drawPeers() {
  api('GET', '/v1/peers?probe=1').then(function (r) {
    if (isLocked(r)) { toVault(); return; }
    var ul = $('peerlist'), sel = $('to'); clear(ul); clear(sel);
    ((r.body && r.body.peers) || []).forEach(function (p) {
      var li = el('li', 'row');
      li.appendChild(el('span', 'row__v', p.name)); li.appendChild(el('span', 'row__n', String(p.sign_pub).slice(-8)));
      var ok = p.active && p.reachable === true;
      li.appendChild(tag(ok, false, ok ? '[CA] reachable' : '[CA] not reachable')); ul.appendChild(li);
      if (p.active) { var o = el('option', '', p.name); o.value = p.name; sel.appendChild(o); }
    });
  }).catch(function () {});
}
function drawSends() {
  api('GET', '/v1/sends').then(function (r) {
    if (isLocked(r)) { toVault(); return; }
    var ul = $('sendlist'); clear(ul);
    ((r.body && r.body.sends) || []).forEach(function (s) {
      var li = el('li', 'row');
      li.appendChild(el('span', 'row__v', s.peer)); li.appendChild(el('span', 'row__n', String(s.id)));
      li.appendChild(s.state === 'delivered' ? tag(true, false, '[CA] delivered') : tag(false, true, '[CA] failed'));
      if (s.state === 'blocked' && s.categories && s.categories.length) { li.appendChild(el('span', 'row__n', s.categories.join(' '))); }
      ul.appendChild(li);
    });
  }).catch(function () {});
}
function initPeers() {
  drawPeers(); drawSends();
  $('sendbtn').addEventListener('click', function () {
    var peer = $('to').value, text = $('smsg').value; if (!peer || !text) { return; }
    $('smsg').value = ''; $('salert').textContent = ''; $('sendbtn').disabled = true;
    api('POST', '/v1/send', { peer: peer, text: text }).then(function (r) {
      text = null;
      if (r.status !== 200) { $('salert').textContent = r.status + (r.body && r.body.error ? ' ' + r.body.error : (r.body && r.body.blocked ? ' ' + (r.body.categories || []).join(' ') : '')); }
      drawSends();
    }).catch(function (e) { text = null; $('salert').textContent = String(e); }).then(function () { $('sendbtn').disabled = false; });
  });
}

// ---- status ----
function card(id, on, n) { $('c-' + id + '-dot').className = 'dot' + (on ? '' : ' dot--off'); $('c-' + id + '-n').textContent = String(n); }
function drawStatus(s) {
  if (!s) { $('n-recv').textContent = count(); $('n-gate').textContent = count(); inst('daemon', false, '[CA] unknown'); inst('model', false, '[CA] unknown'); inst('auto', false, '[CA] unknown'); return; }
  $('n-recv').textContent = count(s.messages_received); $('n-gate').textContent = count(s.gate_verdicts);
  card('model', s.model_up, s.model_up ? 1 : 0); card('gate', s.gate_up, s.gate_up ? 1 : 0);
  card('vault', s.vault_unlocked, s.vault_records); card('peers', s.peers_reachable > 0, s.peers_reachable);
  // Install rows: read only, from /v1/status. v1 has no field for the unit, the model supervision or auto start, so those say unknown.
  inst('daemon', true, '[CA] installed'); // this answer came from the daemon, so it is installed and running
  inst('model', s.model_up, s.model_up ? '[CA] installed' : '[CA] off');
  inst('auto', false, '[CA] unknown');
}
function inst(id, on, word) { $('i-' + id + '-dot').className = 'dot' + (on ? '' : ' dot--off'); $('i-' + id + '-w').textContent = word; }
function initStatus() {
  api('GET', '/v1/vault/conversations').then(function (r) { if (r.status === 200 && r.body) { $('n-conv').textContent = String(r.body.conversations.length); } }).catch(function () {});
  api('GET', '/v1/sends').then(function (r) { if (r.status === 200 && r.body) { $('n-sent').textContent = String(r.body.sends.length); } }).catch(function () {});
}
// messages received and gate verdicts come from /v1/status (v1.2) when present; absent shows the install rows' word.
function count(n) { return typeof n === 'number' && isFinite(n) && n >= 0 ? String(n) : '[CA] unknown'; }

pollStatus().then(function (s) {
  if (s && s.vault_unlocked === false && PAGE !== 'vault') { return; }
  if (PAGE === 'chat') { initChat(); }
  if (PAGE === 'peers') { initPeers(); }
  if (PAGE === 'status') { initStatus(); }
});
if (PAGE === 'vault') { initVault(); }
setInterval(pollStatus, 5000);
