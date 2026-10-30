// Thin page. Every state comes from the app as a machine value; this file only draws it. The six digits live only
// in the input while it is open: not stored, not logged, not set as a title; they are sent on Connect and dropped.
var invoke = window.__TAURI__.core.invoke;
var T = null, W = null, VIEW = null, PS = null, HID = '', SPENT = false, CLOSED = '';
function $(id) { return document.getElementById(id); }
function show(id, on) { $(id).hidden = !on; }
function lang(all) { return (navigator.language || 'en').toLowerCase().indexOf('fr') === 0 ? all.fr : all.en; }

function words() {
  var h = W;
  $('t-title').textContent = T.pair_title;
  // vc16 cannot scan or type: the lead line names only the paste until the phone release that can (the app says so with phone_can_type_code).
  $('t-scan').textContent = h.scan_paste;
  $('t-code-label').textContent = h.code_label;
  $('t-text-label').textContent = h.text_label;
  $('copy').textContent = h.copy;
  $('t-computer').textContent = h.computer;
  $('t-name').textContent = h.name;
  $('t-name-hint').textContent = h.name_hint;
  $('start').textContent = h.start;
  $('t-asked').textContent = h.asked;
  $('t-six').textContent = h.six;
  $('connect').textContent = T.pair_yes;
  $('notme').textContent = T.pair_no;
  $('t-notme-note').textContent = h.not_me_note;
  $('again').textContent = h.start;
  $('t-nonet').textContent = h.nonet;
  $('t-waits').textContent = h.waits;
  $('retry-net').textContent = h.try_again;
  $('t-down-h').textContent = h.down_h;
  $('t-down-p').textContent = h.down_p;
  $('restart').textContent = h.restart;
  $('k-service').textContent = h.row_service;
  $('t-models-h').textContent = h.models_h;
  $('t-found-h').textContent = h.models_found_h;
  $('t-found-p').textContent = h.models_found_p;
  $('k-model').textContent = h.row_model;
  $('k-phone').textContent = h.row_phone;
  $('k-fw').textContent = h.row_firewall;
  $('retry-fw').textContent = T.retry_firewall;
  $('qr').alt = T.qr_alt;
}

function row(name, dot, text) {
  $('dot-' + name).className = 'dot' + (dot ? ' ' + dot : '');
  $('v-' + name).textContent = text;
}

function draw() {
  if (!T || !VIEW) { return; }
  var r = VIEW.rows, waiting = PS && PS.state === 'revealed', down = VIEW.service === 'down';
  var rec = VIEW.service === 'recovering';
  row('service', down ? 'bad' : (rec ? '' : 'ok'), down ? W.service_down : (rec ? W.restarting : W.service_up));
  row('model', r.model === 'loaded' ? 'ok' : '', r.model === 'loaded' ? W.model_loaded : (r.model === 'idle' ? W.model_idle : W.model_unknown));
  row('phone', r.phone === 'linked' ? 'ok' : '', waiting ? W.phone_waiting : (r.phone === 'linked' ? W.phone_linked : (r.phone === 'none' ? W.phone_none : W.phone_unknown)));
  row('fw', r.firewall === 'open' ? 'ok' : (r.firewall === 'blocked' ? 'bad' : ''), r.firewall === 'open' ? W.fw_open : (r.firewall === 'blocked' ? W.fw_blocked : W.fw_unknown));
  show('retry-fw', r.firewall === 'blocked');
  var p = VIEW.pair;
  // The companion is down (a failed unit after an upgrade): no code, no picture, nothing that looks live. One card and a Restart button.
  show('down', down);
  if (down) { show('nonet', false); show('ask', false); show('done', false); show('pair', false); return; }
  show('nonet', !p);
  var ask = !!p && waiting && !SPENT, done = !!p && (SPENT || CLOSED !== '');
  show('ask', ask && !done);
  show('done', done);
  show('pair', !!p && !ask && !done);
  if (!p) { return; }
  // No phone release scans yet (F41): the picture is not drawn, the grid becomes one column (the code and the text carry the same address).
  $('qr').hidden = !p.phone_can_scan;
  $('grid').className = 'grid' + (p.phone_can_scan ? '' : ' noqr');
  if (p.phone_can_scan) { $('qr').src = 'data:image/svg+xml;base64,' + btoa(p.svg); }
  $('payload').textContent = p.payload;
  $('addr').textContent = p.address.replace('http://', '');
  $('devname').textContent = p.name;
  show('codebox', !!p.code);
  $('code').textContent = p.code || '';
  // The lead line names only what the phone out today can do: the typed code and the paste (the scan sentence waits for F41).
  if (p.phone_can_type_code && p.code) { $('t-scan').textContent = W.lead_code; } // no code on another port: the paste-only line stays
}

function render(s) {
  PS = s;
  if (s.state === 'paired' || s.state === 'confirmed') { HID = ''; SPENT = true; CLOSED = 'paired'; $('done-h').textContent = T.pair_paired_h; $('done-p').textContent = W.paired_more; }
  else if (s.state === 'aborted') { HID = ''; CLOSED = 'aborted'; $('done-h').textContent = T.pair_title; $('done-p').textContent = T['pair_' + s.reason] || T.pair_unexpected; }
  else if (s.state === 'revealed') { HID = s.handshake_id; }
  else { HID = ''; }
  draw();
}
function poll() { if (quiet() || !VIEW || !VIEW.pair || VIEW.service === 'down') { return; } invoke('pair_state').then(render).catch(function () { HID = ''; draw(); }); }
var MODELS = [];
function gb(n) { return (n / 1073741824).toFixed(1) + ' GB'; }
function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined) { e.textContent = text; } return e; }
function modelRow(o) {
  var row = el('div', 'mrow'), main = el('div', 'main'), nm = el('div', 'nm');
  var heading = o.kind === 'approved' ? (W['size_' + o.name] + (o.label ? ' \u00b7 ' + o.label : '')) : o.name;
  nm.textContent = (o.tier >= 7 && o.label) ? o.label : heading;
  if (o.recommended) { nm.appendChild(el('span', 'badge', W.recommended)); }
  if (!o.tested) { nm.appendChild(el('span', 'badge warn', W.untested_badge)); }
  main.appendChild(nm);
  var sub = gb(o.size_bytes) + ' \u00b7 ' + (o.fits ? W.fits_yes : (o.kind === 'found' ? W.fits_maybe : (o.why_not === 'disk' ? W.disk_short : W.too_small)));
  main.appendChild(el('div', 'sub', sub));
  if (!o.tested) { main.appendChild(el('div', 'sub', W.untested_line)); }
  row.appendChild(main);
  var act;
  if (o.chosen && o.state === 'installed') { act = el('span', 'sub', W.in_use); }
  else if (o.state === 'downloading') { act = el('span', 'sub', W.downloading + ' ' + (o.percent || 0) + '%'); }
  else if (o.state === 'installed' && o.fits) { act = el('button', 'btn sec sm', W.use_model); act.onclick = function () { modelAct('model_choose', o.id); }; }
  else if (o.state === 'absent' && o.fits) { act = el('button', 'btn sec sm', W.download + ' ' + gb(o.size_bytes)); act.onclick = function () { modelAct('model_download', o.id); }; }
  else if (o.state === 'installed') { act = el('span', 'sub', W.installed); }
  if (act) { row.appendChild(act); }
  return row;
}
function modelAct(cmd, id) {
  $('models-out').textContent = '';
  invoke(cmd, { id: id }).then(function () { models(); }).catch(function () { $('models-out').textContent = W.apply_failed; });
}
function drawModels() {
  if (!W) { return; }
  var a = $('model-list'), f = $('found-list');
  a.textContent = ''; f.textContent = '';
  var nf = 0;
  MODELS.forEach(function (o) { if (o.kind === 'found') { f.appendChild(modelRow(o)); nf += 1; } else { a.appendChild(modelRow(o)); } });
  $('found').hidden = nf === 0;
  $('models').hidden = MODELS.length === 0;
}
function models() { if (quiet()) { return; } invoke('model_options').then(function (v) { MODELS = v; drawModels(); }).catch(function () {}); }
function quiet() { return document.hidden === true; } // a window that is hidden asks for nothing: every request leaves a TIME-WAIT socket on the companion port
function view() { if (quiet()) { return; } invoke('home_view').then(function (v) { VIEW = v; draw(); }).catch(function () {}); }

$('start').addEventListener('click', function () {
  SPENT = false; CLOSED = '';
  invoke('open_pairing').then(function () { $('start-out').textContent = ''; poll(); }).catch(function () { $('start-out').textContent = ''; });
});
$('again').addEventListener('click', function () { SPENT = false; CLOSED = ''; draw(); });
$('retry-net').addEventListener('click', view);
$('restart').addEventListener('click', function () {
  var b = $('restart');
  b.disabled = true; b.textContent = W.restarting; $('restart-out').textContent = '';
  var done = function (ok) { b.disabled = false; b.textContent = W.restart; if (!ok) { $('restart-out').textContent = W.restart_failed; } view(); };
  invoke('restart_service').then(function (ok) { done(ok === true); }).catch(function () { done(false); });
});
$('retry-fw').addEventListener('click', function () { invoke('retry_firewall').then(view).catch(view); });
$('copy').addEventListener('click', function () {
  var t = $('payload').textContent;
  var ok = function () { $('copy').textContent = W.copied; setTimeout(function () { $('copy').textContent = W.copy; }, 1500); };
  if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(t).then(ok).catch(function () {}); }
});
$('connect').addEventListener('click', function () {
  var d = $('digits');
  if (!HID) { return; }
  if (!/^[0-9]{6}$/.test(d.value)) { $('hint').textContent = T.pair_code_format; return; }
  var code = d.value;
  d.value = '';
  invoke('pair_confirm', { handshakeId: HID, code: code }).then(function (r) {
    if (r === 'confirmed') { SPENT = true; CLOSED = 'paired'; $('done-h').textContent = T.pair_paired_h; $('done-p').textContent = W.paired_more; }
    else if (r === 'code_format') { $('hint').textContent = T.pair_code_format; return; }
    else { SPENT = true; CLOSED = 'aborted'; $('done-h').textContent = T.pair_title; $('done-p').textContent = T['pair_' + r] || T.pair_failed; }
    $('hint').textContent = '';
    draw();
  });
});
$('notme').addEventListener('click', function () {
  $('digits').value = '';
  invoke('pair_cancel').then(function () { HID = ''; SPENT = false; CLOSED = ''; poll(); });
});

invoke('status_texts').then(function (r) {
  T = lang(r[0]); W = T.home;
  words(); view(); poll();
  models();
  setInterval(view, 3000);
  setInterval(models, 5000);
  setInterval(poll, 2000);
});
