// Placeholder UI. null means could not be determined and is shown as unknown, never as no.
var invoke = window.__TAURI__.core.invoke;
var T = null, CMD = null;
function $(id) { return document.getElementById(id); }
function show(v) { return v === null ? T.paired_unknown : (v ? T.paired_yes : T.paired_no); }
function lang(all) { return (navigator.language || 'en').toLowerCase().indexOf('fr') === 0 ? all.fr : all.en; }
function refresh() {
  if (!T) { return; }
  invoke('status_view').then(function (s) {
    $('paired').textContent = T.paired_label + ' ' + show(s.paired);
    // loaded / idle / unknown: an unknown state is never shown as loaded
    var state = s.model_idle === null ? T.model_unknown : (s.model_idle ? T.model_idle : T.model_loaded);
    $('model').textContent = T.model_label + ' ' + state;
    $('model-note').textContent = s.model;
    $('variant').textContent = s.llama_variant === 'vulkan' ? T.engine_vulkan : (s.llama_variant === 'cpu' ? T.engine_cpu : '');
    // shown only after the switch to the CPU build really happened
    $('vulkan-failed').hidden = !s.vulkan_failed;
    $('lan').textContent = T.reachable_label + ' ' + show(s.lan_reachable);
    // specific line only above E4B; the generic line when the tier cannot be told
    $('slowness').hidden = !s.slowness;
    $('slowness').textContent = s.slowness === 'specific' ? T.slowness : (s.slowness === 'generic' ? T.slowness_generic : '');
    $('model-state').textContent = s.model_idle === null ? T.unknown : (s.model_idle ? T.idle : T.loaded);
    $('model-detail').hidden = s.model_idle !== null;
    $('model-first').hidden = s.model_idle !== true;
    $('helper-missing').hidden = !s.helper_missing;
  });
}
invoke('status_texts').then(function (r) {
  T = lang(r[0]); CMD = r[1];
  $('title').textContent = T.status_title;
  $('vulkan-failed').textContent = T.vulkan_failed;
  $('model-detail').textContent = T.unknown_detail;
  $('retry').textContent = T.retry_firewall;
  $('awake-h').textContent = T.keep_awake_heading;
  $('awake-b').textContent = T.keep_awake_body;
  $('model-first').textContent = T.first_answer;
  $('helper-text').textContent = T.helper_missing;
  $('helper-above').textContent = T.above_command;
  $('helper-cmd').textContent = CMD || '';
  refresh();
});
setInterval(refresh, 5000);
$('retry').addEventListener('click', function () {
  invoke('retry_firewall').then(function (r) {
    $('retry-out').textContent = r === 'helper_not_installed' ? T.helper_missing : (r === 'no_firewall' ? T.no_firewall : (r === 'done' ? '' : T.fw_cancelled));
  }).catch(function () {
    $('retry-out').textContent = T.fw_cancelled;
  });
});
