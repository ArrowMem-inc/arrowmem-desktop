import QtQuick
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui

// The ArrowBridge bar panel, first cut. Structure only: every size, colour, glyph and string marked FILL
// is awaiting a render and cleared copy. Every Text that shows data sets textFormat: Text.PlainText.
Panel {
  id: root
  moduleName: "arrowmem.bridge"
  ipcTarget: "arrowmem.bridge"

  readonly property color foreground: bar ? bar.foreground : Commons.Color.foreground
  readonly property color dim: Qt.darker(foreground, 1.55)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  Commons.Translations { id: strings; directory: Qt.resolvedUrl("i18n") }

  Service {
    id: service
    active: root.opened
    ownerPort: root.setting("ownerPort", 8789)
    intervalSec: root.setting("refreshIntervalSec", 5)
    helperPath: String(Qt.resolvedUrl("bin/arrowbridge-panel")).replace(/^file:\/\//, "")
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: strings.t("bar.glyph") // FILL
    onPressed: root.toggle()
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(Style.space(320)) // FILL
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, Style.space(600)) // FILL

    content: PanelKeyCatcher {
      implicitHeight: column.implicitHeight
      anchors.fill: parent
      onCloseRequested: root.close()

      Column {
        id: column
        width: parent.width
        spacing: Style.space(12) // FILL

        Repeater {
          model: service.groups

          Column {
            id: grp
            required property var modelData
            width: column.width
            spacing: Style.space(6) // FILL

            Text {
              textFormat: Text.PlainText
              text: strings.t("host." + grp.modelData.host)
              color: root.foreground
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Text {
              visible: grp.modelData.state !== "ok"
              textFormat: Text.PlainText
              text: strings.t("unknown.line") // FILL
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
            }

            Repeater {
              model: grp.modelData.rows

              Row {
                id: line
                required property var modelData
                spacing: Style.space(8) // FILL

                Rectangle {
                  width: Style.space(10) // FILL
                  height: width
                  radius: width / 2
                  anchors.verticalCenter: parent.verticalCenter
                  color: line.modelData.loaded === true ? root.foreground : "transparent"
                  border.width: 1
                  border.color: line.modelData.loaded === null ? root.dim : root.foreground
                }

                Text {
                  textFormat: Text.PlainText
                  text: line.modelData.id
                  elide: Text.ElideRight
                  width: column.width - Style.space(140) // FILL
                  anchors.verticalCenter: parent.verticalCenter
                  color: root.foreground
                  font.family: root.fontFamily
                  font.pixelSize: Style.font.body
                }

                Button {
                  visible: line.modelData.paused || line.modelData.loaded === true
                  text: line.modelData.paused ? strings.t("action.resume") : strings.t("action.pause") // FILL
                  onClicked: line.modelData.paused ? service.resume() : service.pause(line.modelData.id)
                }
              }
            }
          }
        }

        Text {
          visible: service.outcome !== ""
          textFormat: Text.PlainText
          text: strings.t("outcome." + service.outcome) // FILL
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.body
        }

        Row {
          spacing: Style.space(8) // FILL

          Button {
            text: strings.t("action.refresh") // FILL
            onClicked: service.refresh()
          }

          Button {
            text: strings.t("action.resume") // FILL
            onClicked: service.resume()
          }
        }
      }
    }
  }
}
