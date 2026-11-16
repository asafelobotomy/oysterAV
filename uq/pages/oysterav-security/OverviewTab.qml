// The Overview tab: is this computer protected, how fresh the signatures are, and any scan running now.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

SettingsTab {
    id: tab

    /// The page (Page.qml): its state and its changes.
    property var host
    readonly property var summary: tab.host ? tab.host.summary : null

    function stateColor() {
        if (tab.summary === null || !tab.summary.ok)
            return tab.host.mutedColor();
        if (tab.summary.state === "ok")
            return tab.host.successColor();
        return tab.summary.state === "threat" ? tab.host.errorColor() : tab.host.warningColor();
    }

    title: "Overview"
    iconName: "security-high"

    SettingsCard {
        title: "Security status"
        iconName: "security-high"
        help: "Read from oysterAV's last scan, its signature files and the quarantine. Looking never starts a scan."
        wide: true
        Layout.fillWidth: true

        Loading {
            loading: tab.summary === null
            problem: tab.summary !== null && !tab.summary.ok ? tab.summary.problem : ""
            what: "the status"
            Layout.fillWidth: true
        }
        SettingRow {
            settingId: "status"
            label: tab.summary !== null && tab.summary.ok ? tab.summary.title : "Status unavailable"
            highlight: tab.host ? tab.host.highlight : ""
            visible: tab.summary !== null
            Layout.fillWidth: true

            Rectangle {
                objectName: "state-dot"
                width: 14
                height: 14
                radius: 7
                color: tab.stateColor()
            }
        }
        Repeater {
            model: tab.summary !== null && tab.summary.ok ? tab.summary.reasons : []

            UqLabel {
                required property var modelData
                text: "• " + modelData
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
        UqLabel {
            visible: tab.summary !== null && tab.summary.ok
            text: tab.summary !== null ? Logic.summaryLine(tab.summary) : ""
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        RowLayout {
            spacing: 8

            QQC2.Button {
                objectName: "update-signatures"
                text: "Update signatures"
                icon.name: "view-refresh"
                enabled: !!tab.host && !tab.host.busy
                onClicked: tab.host.write("update", "update-signatures", [], () => tab.host.loadSummary(), "Signatures updated.")
            }
            QQC2.Button {
                text: "Scan a folder…"
                icon.name: "system-search"
                onClicked: tab.host.showScans()
            }
            QQC2.Button {
                text: "Refresh"
                icon.name: "view-refresh"
                onClicked: tab.host.reloadAll()
            }
        }
        Outcome {
            host: tab.host
            noteKey: "update"
            bar: true
            Layout.fillWidth: true
        }
    }

    SettingsCard {
        title: "A scan is running"
        iconName: "system-search"
        help: "Started in oysterAV, by the timer or here. Cancelling stops it between scanners."
        wide: true
        visible: !!tab.host && tab.host.job.active && !tab.host.streaming
        Layout.fillWidth: true

        QQC2.ProgressBar {
            indeterminate: !!tab.host && tab.host.job.percent <= 0
            value: tab.host ? tab.host.job.percent / 100 : 0
            Layout.fillWidth: true
        }
        UqLabel {
            text: tab.host ? (tab.host.job.pack !== "" ? tab.host.job.pack + ": " : "") + tab.host.job.message : ""
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        QQC2.Button {
            objectName: "cancel-job"
            text: "Cancel the scan"
            icon.name: "process-stop"
            enabled: !!tab.host && !tab.host.busy
            onClicked: tab.host.cancelScan()
        }
        Outcome {
            host: tab.host
            noteKey: "cancel"
            Layout.fillWidth: true
        }
    }
}
