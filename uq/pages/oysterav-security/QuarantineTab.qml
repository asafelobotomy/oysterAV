// The Quarantine tab: what is in the vault, restore or delete each file (the plan sheet shows what
// happens first), and a check of the vault itself.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

SettingsTab {
    id: tab

    property var host
    readonly property var list: tab.host ? tab.host.quarantine : null
    readonly property var vault: tab.host ? tab.host.verify : null

    function autoload() {
        if (!tab.visible || !tab.host)
            return;
        if (tab.host.quarantine === null)
            tab.host.loadQuarantine();
        if (tab.host.verify === null)
            tab.host.loadVerify();
    }

    function after() {
        tab.host.loadQuarantine();
        tab.host.loadVerify();
        tab.host.loadSummary();
    }

    title: "Quarantine"
    iconName: "security-medium"
    onVisibleChanged: tab.autoload()

    SettingsCard {
        title: "Quarantined files"
        iconName: "security-medium"
        help: "Infected files the scanners moved out of the way. Restore puts one back where it was found; delete removes it for good."
        wide: true
        Layout.fillWidth: true
        actions: [
            QQC2.Button {
                text: "Refresh"
                icon.name: "view-refresh"
                onClicked: tab.after()
            }
        ]

        Loading {
            loading: tab.list === null
            problem: tab.list !== null && !tab.list.ok ? tab.list.problem : ""
            what: "the quarantine"
            Layout.fillWidth: true
        }
        UqLabel {
            objectName: "quarantine-empty"
            visible: tab.list !== null && tab.list.ok && tab.list.rows.length === 0
            text: "No quarantined files."
            opacity: 0.7
        }
        Repeater {
            model: tab.list !== null && tab.list.ok ? tab.list.rows : []

            ColumnLayout {
                id: row

                required property var modelData
                required property int index
                readonly property string key: "entry:" + row.modelData.id

                spacing: 2
                Layout.fillWidth: true

                SettingRow {
                    settingId: row.index === 0 ? "quarantine" : ""
                    label: row.modelData.name + " · " + row.modelData.threat
                    highlight: tab.host.highlight
                    Layout.fillWidth: true

                    QQC2.Button {
                        objectName: "restore-" + row.modelData.id
                        text: "Restore"
                        icon.name: "edit-undo"
                        enabled: !tab.host.busy
                        onClicked: tab.host.write(row.key, "quarantine-restore", [row.modelData.id], tab.after, "Restored.")
                    }
                    QQC2.Button {
                        objectName: "delete-" + row.modelData.id
                        text: "Delete"
                        icon.name: "edit-delete"
                        enabled: !tab.host.busy
                        onClicked: tab.host.write(row.key, "quarantine-delete", [row.modelData.id], tab.after, "Deleted.")
                    }
                }
                UqLabel {
                    text: row.modelData.path + " · " + row.modelData.when
                    opacity: 0.7
                    elide: Text.ElideMiddle
                    Layout.fillWidth: true
                }
                Outcome {
                    host: tab.host
                    noteKey: row.key
                    Layout.fillWidth: true
                }
            }
        }
    }

    SettingsCard {
        title: "The vault"
        iconName: "folder-locked"
        help: "Checks that every entry still has its file, and that no file is left without an entry."
        Layout.fillWidth: true

        Loading {
            loading: tab.vault === null
            problem: tab.vault !== null && !tab.vault.ok ? tab.vault.problem : ""
            what: "the vault"
            Layout.fillWidth: true
        }
        UqLabel {
            objectName: "vault-line"
            visible: tab.vault !== null && tab.vault.ok
            text: tab.vault !== null ? tab.vault.text : ""
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        RowLayout {
            QQC2.Button {
                text: "Check again"
                icon.name: "view-refresh"
                onClicked: tab.host.loadVerify()
            }
            QQC2.Button {
                objectName: "reconcile"
                text: "Delete stray files…"
                icon.name: "edit-delete"
                visible: tab.vault !== null && tab.vault.ok && tab.vault.orphans > 0
                enabled: !tab.host.busy
                onClicked: tab.host.write("reconcile", "quarantine-reconcile", [], tab.after, "Deleted the stray files.")
            }
        }
        Outcome {
            host: tab.host
            noteKey: "reconcile"
            Layout.fillWidth: true
        }
    }
}
