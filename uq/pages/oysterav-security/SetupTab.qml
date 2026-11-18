// The Setup tab: oysterAV's first-time setup (the same steps as its window), run from Settings. Until it has
// been run the other tabs stay hidden, and the Security island in the bar shows a red icon.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

SettingsTab {
    id: tab

    property var host
    readonly property var setup: tab.host ? tab.host.setup : null
    readonly property bool needed: !!tab.host && tab.host.setupNeeded
    readonly property bool usable: !!tab.host && !tab.host.busy

    function autoload() {
        if (tab.visible && tab.host && tab.host.setup === null)
            tab.host.loadSetup();
    }

    /// Runs setup with the command `id`, then reads everything again; the tabs come back once it is complete.
    function run(id) {
        tab.host.write("setup", id, [], () => {
            tab.host.loadSetup();
            tab.host.loadSummary();
        }, result => Logic.setupOutcome(result));
    }

    title: "Setup"
    iconName: tab.needed ? "dialog-warning" : "dialog-ok-apply"
    onVisibleChanged: tab.autoload()
    Component.onCompleted: tab.autoload()

    SettingsCard {
        title: "First-time setup"
        iconName: tab.iconName
        help: "Installs the scanners, sets up the daily scan timer and, if you choose, hardens the computer and turns the firewall on. What needs administrator rights asks for your password through oysterAV's own helper."
        wide: true
        Layout.fillWidth: true

        Loading {
            loading: tab.setup === null
            problem: tab.setup !== null && !tab.setup.ok ? tab.setup.problem : ""
            what: "the setup state"
            Layout.fillWidth: true
        }
        SettingRow {
            settingId: "setup"
            label: tab.needed ? "Security isn't set up yet" : "Security is set up"
            highlight: tab.host ? tab.host.highlight : ""
            visible: tab.host !== undefined && tab.host !== null && tab.host.summary !== null
            Layout.fillWidth: true

            Rectangle {
                objectName: "setup-dot"
                width: 14
                height: 14
                radius: 7
                color: tab.needed ? tab.host.errorColor() : tab.host.successColor()
            }
        }
        UqLabel {
            visible: tab.needed
            text: "The other Security tabs open once setup has run."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Repeater {
            model: tab.setup !== null && tab.setup.ok ? tab.setup.lines : []

            UqLabel {
                required property var modelData
                text: "• " + modelData
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
        RowLayout {
            spacing: 8

            QQC2.Button {
                objectName: "setup-run"
                text: tab.needed ? "Run recommended setup…" : "Run setup again…"
                icon.name: "system-run"
                enabled: tab.usable
                onClicked: tab.run("setup-run")
            }
            QQC2.Button {
                objectName: "setup-run-basic"
                text: "Run basic setup…"
                icon.name: "system-run"
                enabled: tab.usable
                onClicked: tab.run("setup-run-basic")
            }
            QQC2.Button {
                text: "Check again"
                icon.name: "view-refresh"
                enabled: tab.usable
                onClicked: {
                    tab.host.loadSetup();
                    tab.host.loadSummary();
                }
            }
        }
        UqLabel {
            text: "Recommended also applies host hardening and turns the firewall on. Basic installs the scanners and the scan timer and leaves the rest as it is."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Outcome {
            host: tab.host
            noteKey: "setup"
            bar: true
            Layout.fillWidth: true
        }
    }
}
