.pragma library
// Second check of the helper's one line (the helper already holds these caps; nothing upstream is trusted).
// Anything that does not fit reads unknown. Nothing here writes or stores.

var MAX_ROWS = 64
var MAX_ID = 200
var HOSTS = ["local", "remote"]

function unknownGroups() {
  return [{ host: "local", state: "unknown", rows: [] }, { host: "remote", state: "unknown", rows: [] }]
}

// Categories Cc, Cf, Zl, Zp, Co, Cn and lone surrogates; the same list as BAD in the helper's lib.rs.
var BAD = [[0xAD, 0xAD], [0x600, 0x605], [0x61C, 0x61C], [0x6DD, 0x6DD], [0x70F, 0x70F], [0x890, 0x891], [0x8E2, 0x8E2],
  [0x180E, 0x180E], [0x200B, 0x200F], [0x2028, 0x202E], [0x2060, 0x2064], [0x2066, 0x206F], [0xD800, 0xDFFF], [0xE000, 0xF8FF],
  [0xFDD0, 0xFDEF], [0xFEFF, 0xFEFF], [0xFFF0, 0xFFFB], [0xFFFE, 0xFFFF], [0x110BD, 0x110BD], [0x110CD, 0x110CD],
  [0x13430, 0x1343F], [0x1BCA0, 0x1BCA3], [0x1D173, 0x1D17A], [0x1FFFE, 0x1FFFF], [0x2FFFE, 0x2FFFF],
  [0x3FFFE, 0x3FFFF], [0x40000, 0x10FFFF], [0x00, 0x1F], [0x7F, 0x9F]]

function cleanText(s) {
  for (var i = 0; i < s.length; i++) {
    var c = s.codePointAt(i)
    if (c > 0xFFFF) i++
    for (var j = 0; j < BAD.length; j++) if (c >= BAD[j][0] && c <= BAD[j][1]) return false
  }
  return true
}

function okId(s) {
  return typeof s === "string" && s.length > 0 && s.length <= MAX_ID && cleanText(s)
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
