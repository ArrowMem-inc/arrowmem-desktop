// Placeholder UI. Words come from the strings file; the purge box is off by default.
var T = null;
var invoke = window.__TAURI__.core.invoke;
function $(id) { return document.getElementById(id); }
invoke('uninstall_texts').then(function (all) {
  T = (navigator.language || 'en').toLowerCase().indexOf('fr') === 0 ? all.fr : all.en;
  $('confirm').textContent = T.confirm;
  $('purge-label').textContent = T.purge_checkbox;
  $('purge-note').textContent = T.purge_note;
  $('go').textContent = T.button_uninstall;
  $('cancel').textContent = T.button_cancel;
}).catch(function (e) { $('result').textContent = 'error ' + e; });
$('purge').checked = false;
$('purge').addEventListener('change', function () { $('purge-note').hidden = !$('purge').checked; });
$('cancel').addEventListener('click', function () { window.__TAURI__.window.getCurrentWindow().close(); });
$('go').addEventListener('click', function () {
  $('go').disabled = true;
  invoke('uninstall', { purge: $('purge').checked }).then(function (r) {
    var fr = T && T.confirm.indexOf('Cela') === 0;
    $('result').textContent = r.message[fr ? 1 : 0];
  }).catch(function (e) { $('result').textContent = 'error ' + e; $('go').disabled = false; });
});
