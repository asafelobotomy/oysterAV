// The System tab: which scanners are installed, whether oysterAV's polkit helper is ready, and the audit
// log of what ran with elevated rights.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

SettingsTab {
    id: tab

    property var host

    function autoload() {
        if (tab.visible && tab.host && tab.host.doctor === null)
            tab.host.loadSystem();
    }

    title: "System"
    iconName: "utilities-system-monitor"
    onVisibleChanged: tab.autoload()

    SettingsCard {
        title: "Scanners"
        iconName: "utilities-system-monitor"
        help: "The tools oysterAV drives. Missing ones are skipped, and the scan says so."
        wide: true
        Layout.fillWidth: true
        actions: [
            QQC2.Button {
                text: "Refresh"
                icon.name: "view-refresh"
                onClicked: tab.host.loadSystem()
            }
        ]

        Loading {
            loading: !!tab.host && tab.host.doctor === null
            problem: tab.host && tab.host.doctor !== null && !tab.host.doctor.ok ? tab.host.doctor.problem : ""
            what: "the scanners"
            Layout.fillWidth: true
        }
        Repeater {
            model: tab.host && tab.host.doctor !== null && tab.host.doctor.ok ? tab.host.doctor.rows : []

            ColumnLayout {
                id: row

                required property var modelData
                required property int index

                spacing: 2
                Layout.fillWidth: true

                SettingRow {
                    settingId: row.index === 0 ? "system" : ""
                    label: row.modelData.name + " · " + row.modelData.tier
                    highlight: tab.host.highlight
                    Layout.fillWidth: true

                    UqLabel {
                        text: row.modelData.text
                        color: row.modelData.ok ? tab.host.successColor() : (row.modelData.tier === "Needed" ? tab.host.errorColor() : tab.host.warningColor())
                    }
                }
                UqLabel {
                    visible: row.modelData.hint !== ""
                    text: "Install: " + row.modelData.hint
                    opacity: 0.7
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
            }
        }
    }

    SettingsCard {
        title: "oysterAV's helper"
        iconName: "dialog-password"
        help: "Rootkit checks and service changes ask for your password through this helper, never through uQ."
        Layout.fillWidth: true

        Loading {
            loading: !!tab.host && tab.host.helper === null
            problem: tab.host && tab.host.helper !== null && !tab.host.helper.ok ? tab.host.helper.problem : ""
            what: "the helper"
            Layout.fillWidth: true
        }
        UqLabel {
            visible: !!tab.host && tab.host.helper !== null && tab.host.helper.ok
            text: tab.host && tab.host.helper !== null ? tab.host.helper.text : ""
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
    }

    SettingsCard {
        title: "Audit log"
        iconName: "view-list-text"
        help: "What oysterAV did with elevated rights or changed in its settings, newest first."
        wide: true
        Layout.fillWidth: true

        Loading {
            loading: !!tab.host && tab.host.audit === null
            problem: tab.host && tab.host.audit !== null && !tab.host.audit.ok ? tab.host.audit.problem : ""
            what: "the audit log"
            Layout.fillWidth: true
        }
        UqLabel {
            objectName: "audit-empty"
            visible: !!tab.host && tab.host.audit !== null && tab.host.audit.ok && tab.host.audit.rows.length === 0
            text: "Nothing logged yet."
            opacity: 0.7
        }
        Repeater {
            model: tab.host && tab.host.audit !== null && tab.host.audit.ok ? tab.host.audit.rows : []

            SettingRow {
                id: entry

                required property var modelData

                label: entry.modelData.title
                Layout.fillWidth: true

                UqLabel {
                    text: entry.modelData.when
                    color: entry.modelData.failed ? tab.host.errorColor() : tab.host.mutedColor()
                }
            }
        }
    }
}
