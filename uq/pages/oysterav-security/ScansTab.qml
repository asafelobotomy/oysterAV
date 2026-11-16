// The Scans tab: scan a folder, check for rootkits, and the recent scans. Scans stream their progress.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

SettingsTab {
    id: tab

    property var host
    property string folder: ""
    readonly property string profile: Logic.PROFILES[profileBox.currentIndex >= 0 ? profileBox.currentIndex : 0]
    readonly property var rows: tab.host && tab.host.history ? tab.host.history : null

    function choose(path) {
        tab.folder = path;
        folderField.text = path;
        tab.host.previewFolder(tab.profile, path);
    }

    function autoload() {
        if (tab.visible && tab.host && tab.host.history === null)
            tab.host.loadHistory();
    }

    title: "Scans"
    iconName: "system-search"
    onVisibleChanged: tab.autoload()

    FolderDialog {
        id: folderDialog
        title: "Choose a folder to scan"
        onAccepted: tab.choose(Logic.folderPath(selectedFolder))
    }

    SettingsCard {
        title: "Scan a folder"
        iconName: "folder"
        help: "Runs as you and moves nothing. Quarantine what it finds, or leave it."
        Layout.fillWidth: true

        SettingRow {
            settingId: "scan"
            label: "Scan with"
            highlight: tab.host ? tab.host.highlight : ""
            Layout.fillWidth: true

            UqComboBox {
                id: profileBox
                objectName: "profileBox"
                model: Logic.PROFILES.map(p => Logic.PROFILE_LABELS[p])
                onActivated: tab.host.previewFolder(tab.profile, tab.folder)
            }
        }
        RowLayout {
            Layout.fillWidth: true

            QQC2.TextField {
                id: folderField
                objectName: "folderField"
                placeholderText: "/home/you/Downloads"
                Layout.fillWidth: true
                onEditingFinished: tab.choose(text.trim())
            }
            QQC2.Button {
                text: "Browse…"
                icon.name: "document-open-folder"
                onClicked: folderDialog.open()
            }
        }
        UqLabel {
            objectName: "folder-plan"
            visible: text !== ""
            text: tab.host ? tab.host.folderPlan : ""
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        QQC2.Button {
            objectName: "scan-button"
            text: "Scan"
            icon.name: "system-search"
            enabled: !!tab.host && !tab.host.busy && tab.folder !== "" && Logic.argsProblem("scan-folder", [tab.profile, tab.folder]) === ""
            onClicked: tab.host.scanFolder(tab.profile, tab.folder)
        }
        UqLabel {
            text: "Settings stops a scan after 10 minutes. Scan very large folders from oysterAV itself."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        ScanProgress {
            host: tab.host
            kind: "scan"
            Layout.fillWidth: true
        }
    }

    SettingsCard {
        title: "Check for rootkits"
        iconName: "security-low"
        help: "Rootkit scanners need root. oysterAV asks for your password once, through its own helper."
        Layout.fillWidth: true

        SettingRow {
            settingId: "rootkit"
            label: "Look for hidden malware in the system"
            highlight: tab.host ? tab.host.highlight : ""
            Layout.fillWidth: true

            QQC2.Button {
                objectName: "rootkit-button"
                text: "Check for rootkits…"
                icon.name: "security-low"
                enabled: !!tab.host && !tab.host.busy
                onClicked: tab.host.checkRootkits()
            }
        }
        ScanProgress {
            host: tab.host
            kind: "rootkit"
            Layout.fillWidth: true
        }
    }

    SettingsCard {
        title: "Recent scans"
        iconName: "document-open-recent"
        help: "The last 20, from every way a scan can start."
        wide: true
        Layout.fillWidth: true
        actions: [
            QQC2.Button {
                text: "Refresh"
                icon.name: "view-refresh"
                onClicked: tab.host.loadHistory()
            }
        ]

        Loading {
            loading: tab.rows === null
            problem: tab.rows !== null && !tab.rows.ok ? tab.rows.problem : ""
            what: "the scan history"
            Layout.fillWidth: true
        }
        UqLabel {
            objectName: "history-empty"
            visible: tab.rows !== null && tab.rows.ok && tab.rows.rows.length === 0
            text: "No scans yet."
            opacity: 0.7
        }
        Repeater {
            model: tab.rows !== null && tab.rows.ok ? tab.rows.rows : []

            SettingRow {
                id: row

                required property var modelData
                required property int index

                settingId: row.index === 0 ? "history" : ""
                label: row.modelData.title + " · " + row.modelData.when
                highlight: tab.host ? tab.host.highlight : ""
                Layout.fillWidth: true

                UqLabel {
                    text: row.modelData.outcome
                    font.bold: row.modelData.threat
                    color: row.modelData.threat || row.modelData.problem ? tab.host.errorColor() : tab.host.successColor()
                }
            }
        }
    }
}
