import QtQuick
import Quickshell.Io
import "Model.js" as Model

// Runs the helper over Process (argv only, no shell) and owns the unknown watchdog.
// Polls only while `active` (the popup is open); closing kills every call and clears the rows.
Item {
  id: root
  visible: false

  property bool active: false
  property int ownerPort: 8789
  property int intervalSec: 5
  property string helperPath: ""

  // Two groups, local then remote: { host, state: "ok" | "unknown", rows: [{ id, loaded, paused }] }.
  property var groups: Model.unknownGroups()
  // The outcome of the last pause or resume, from the helper's reply only: "", "paused", "free", "unknown".
  property string outcome: ""

  readonly property int watchdogMs: 6000

  function refresh() {
    if (!active || listProcess.running) return
    listProcess.stale = false
    listProcess.command = [helperPath, "list", "--owner-port", String(ownerPort)]
    listProcess.running = true
    listWatchdog.restart()
  }

  function pause(id) { act(["pause", "--owner-port", String(ownerPort), "--model", id]) }
  function resume() { act(["resume", "--owner-port", String(ownerPort)]) }

  function act(args) {
    if (!active || actProcess.running) return
    actProcess.stale = false
    actProcess.command = [helperPath].concat(args)
    actProcess.running = true
    actWatchdog.restart()
  }

  function stop() {
    pollTimer.stop()
    listWatchdog.stop()
    actWatchdog.stop()
    listProcess.stale = true
    actProcess.stale = true
    if (listProcess.running) listProcess.signal(15)
    if (actProcess.running) actProcess.signal(15)
  }

  onActiveChanged: {
    if (active) {
      outcome = ""
      refresh()
      pollTimer.start()
    } else {
      stop()
      groups = Model.unknownGroups()
      outcome = ""
    }
  }

  Timer {
    id: pollTimer
    interval: Math.max(3, root.intervalSec) * 1000
    repeat: true
    onTriggered: root.refresh()
  }

  Timer {
    id: listWatchdog
    interval: root.watchdogMs
    onTriggered: {
      listProcess.stale = true
      if (listProcess.running) listProcess.signal(15)
      root.groups = Model.unknownGroups()
    }
  }

  Timer {
    id: actWatchdog
    interval: root.watchdogMs
    onTriggered: {
      actProcess.stale = true
      if (actProcess.running) actProcess.signal(15)
      root.outcome = "unknown"
    }
  }

  Process {
    id: listProcess
    running: false
    property bool stale: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        listWatchdog.stop()
        if (listProcess.stale) return
        root.groups = Model.parseList(text)
      }
    }
  }

  Process {
    id: actProcess
    running: false
    property bool stale: false
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        actWatchdog.stop()
        if (actProcess.stale) return
        root.outcome = Model.parseState(text)
        root.refresh()
      }
    }
  }
}
