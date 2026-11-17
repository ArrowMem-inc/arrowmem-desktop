.pragma library
// Second check of the helper's one line (the helper already holds these caps; nothing upstream is trusted).
// Anything that does not fit reads unknown. Nothing here writes or stores.

var MAX_ROWS = 64
var MAX_ID = 200
var HOSTS = ["local", "remote"]

function unknownGroups() {
  return [{ host: "local", state: "unknown", rows: [] }, { host: "remote", state: "unknown", rows: [] }]
}

function okId(s) {
  return typeof s === "string" && s.length > 0 && s.length <= MAX_ID && /^[A-Za-z0-9._:\/-]+$/.test(s)
}

function okRow(r) {
  return r && typeof r === "object" && okId(r.id) && (r.loaded === true || r.loaded === false || r.loaded === null) && typeof r.paused === "boolean"
}

// One group of the helper's line, or an unknown group when any part of it is unacceptable.
function group(g, host) {
  var bad = { host: host, state: "unknown", rows: [] }
  if (!g || g.host !== host || g.state !== "ok" || !Array.isArray(g.rows) || g.rows.length > MAX_ROWS) return bad
  var seen = {}
  var rows = []
  for (var i = 0; i < g.rows.length; i++) {
    var r = g.rows[i]
    if (!okRow(r) || seen["k" + r.id]) return bad
    seen["k" + r.id] = true
    rows.push({ id: r.id, loaded: r.loaded, paused: r.paused })
  }
  return { host: host, state: "ok", rows: rows }
}

function parseList(text) {
  var v
  try { v = JSON.parse(String(text || "")) } catch (e) { return unknownGroups() }
  if (!v || !Array.isArray(v.groups) || v.groups.length !== 2) return unknownGroups()
  return [group(v.groups[0], "local"), group(v.groups[1], "remote")]
}

// "paused", "free" or "unknown": only the helper's exact words.
function parseState(text) {
  var v
  try { v = JSON.parse(String(text || "")) } catch (e) { return "unknown" }
  return v && (v.state === "paused" || v.state === "free") ? v.state : "unknown"
}
