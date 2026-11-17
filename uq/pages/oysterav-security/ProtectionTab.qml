// The Protection tab: oysterAV's services (the ClamAV daemon, on-access scanning, signature updates, ...).
// Turning one on or off asks for your password through oysterAV's helper; the plan sheet says so first.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

SettingsTab {
    id: tab

    property var host
    readonly property var list: tab.host ? tab.host.services : null

    function autoload() {
        if (!tab.visible || !tab.host)
            return;
        if (tab.host.services === null)
            tab.host.loadServices();
        if (tab.host.helper === null)
            tab.host.loadSystem();
    }

    title: "Protection"
    iconName: "preferences-system-privacy"
    onVisibleChanged: tab.autoload()

    SettingsCard {
        title: "Real-time protection"
        iconName: "preferences-system-privacy"
        help: "Background services that keep this computer protected between scans."
        wide: true
        Layout.fillWidth: true
        actions: [
            QQC2.Button {
                text: "Refresh"
                icon.name: "view-refresh"
                onClicked: tab.host.loadServices()
            }
        ]

        Loading {
            loading: tab.list === null
            problem: tab.list !== null && !tab.list.ok ? tab.list.problem : ""
            what: "the services"
            Layout.fillWidth: true
        }
        ErrorCard {
            title: "oysterAV's helper isn't ready"
            detail: tab.host && tab.host.helper !== null ? tab.host.helper.text : ""
            visible: !!tab.host && tab.host.helper !== null && tab.host.helper.ok && !(tab.host.helper.installed && tab.host.helper.current)
            Layout.fillWidth: true
        }
        Repeater {
            model: tab.list !== null && tab.list.ok ? tab.list.rows : []

            ColumnLayout {
                id: row

                required property var modelData
                required property int index
                readonly property string key: "service:" + row.modelData.name

                spacing: 2
                Layout.fillWidth: true

                SettingRow {
                    settingId: row.index === 0 ? "protection" : ""
                    label: row.modelData.label
                    highlight: tab.host.highlight
                    enabled: row.modelData.installed && !tab.host.busy
                    Layout.fillWidth: true

                    UqLabel {
                        text: row.modelData.text
                        opacity: 0.7
                    }
                    QQC2.Switch {
                        objectName: "service-" + row.modelData.name
                        checked: row.modelData.running
                        onToggled: {
                            const want = checked;
                            checked = Qt.binding(() => row.modelData.running);
                            tab.host.write(row.key, "service-set", [row.modelData.name, want ? "on" : "off"], () => tab.host.loadServices(), want ? "Turned on." : "Turned off.");
                        }
                    }
                }
                UqLabel {
                    text: row.modelData.help
                    opacity: 0.7
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                Outcome {
                    host: tab.host
                    noteKey: row.key
                    bar: true
                    Layout.fillWidth: true
                }
            }
        }
        UqLabel {
            text: "The folders on-access scanning watches, and whether it blocks infected files, are under Preferences."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
    }
}
