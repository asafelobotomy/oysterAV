// A scan this page started: a bar that follows the streamed events, what it is doing, a Cancel, and
// afterwards what it found, with a Quarantine for each threat. Shown only for its own `kind`.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

ColumnLayout {
    id: view

    property var host
    /// "scan" (a folder) or "rootkit".
    property string kind
    readonly property bool mine: !!view.host && view.host.scanKind === view.kind
    readonly property var state: view.mine ? view.host.scanState : null
    readonly property var result: view.mine ? view.host.scanOutcome : null

    visible: view.state !== null
    spacing: 6

    RowLayout {
        visible: view.state !== null && !view.state.done
        Layout.fillWidth: true

        QQC2.ProgressBar {
            indeterminate: view.state !== null && Logic.fraction(view.state) < 0
            value: view.state !== null ? Math.max(0, Logic.fraction(view.state)) : 0
            Layout.fillWidth: true
        }
        QQC2.Button {
            objectName: "cancel-" + view.kind
            text: "Cancel"
            icon.name: "process-stop"
            enabled: !!view.host && view.host.workingKey === ""
            onClicked: view.host.cancelScan()
        }
    }
    UqLabel {
        text: view.state !== null ? Logic.scanLine(view.state) : ""
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    UqLabel {
        id: verdict
        objectName: "verdict-" + view.kind
        visible: view.result !== null
        text: view.result !== null ? view.result.message : ""
        font.bold: true
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Binding {
        target: verdict
        property: "color"
        value: view.host ? view.host.errorColor() : "red"
        when: view.result !== null && (view.result.failed || view.result.threats.length > 0)
    }
    Repeater {
        model: view.result !== null ? view.result.threats : []

        ColumnLayout {
            id: threat

            required property var modelData
            readonly property string key: "q:" + threat.modelData.path

            spacing: 2
            Layout.fillWidth: true

            SettingRow {
                label: threat.modelData.threat
                Layout.fillWidth: true

                UqLabel {
                    text: threat.modelData.path
                    opacity: 0.7
                    elide: Text.ElideMiddle
                    Layout.maximumWidth: 360
                }
                QQC2.Button {
                    objectName: "quarantine-" + threat.modelData.path
                    text: "Quarantine"
                    icon.name: "security-medium"
                    enabled: !!view.host && !view.host.busy
                    visible: threat.modelData.pack !== "rkhunter" && threat.modelData.pack !== "chkrootkit"
                    onClicked: view.host.quarantineFinding(threat.modelData)
                }
            }
            Outcome {
                host: view.host
                noteKey: threat.key
                Layout.fillWidth: true
            }
        }
    }
}
