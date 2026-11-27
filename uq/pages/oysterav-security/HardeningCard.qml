// The System tab's "System hardening" card: the read-only checks from `oyst-cli status hardening`
// (app confinement, Secure Boot, kernel lockdown, CPU flaws, auditd, USBGuard, kernel settings),
// each with what it means and how to fix it. Harden writes oysterAV's one sysctl file through its polkit
// helper (a plan first, one password prompt); Undo removes it.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "reports.js" as Reports

SettingsCard {
    id: card

    property var host
    property var report: null

    function load() {
        if (!card.host || !card.host.ctx)
            return;
        card.host.ctx.command.run("hardening", [], card.host.guard(result => {
            card.report = Reports.parseHardening(result);
        }));
    }

    function harden(action) {
        card.host.write("harden", "harden-set", [action], () => card.load(), action === "apply" ? "Kernel hardening is on." : "Removed. The old settings return at the next reboot.");
    }

    function stateColor(state) {
        if (state === "ok")
            return card.host.successColor();
        return state === "warn" ? card.host.warningColor() : card.host.mutedColor();
    }

    title: "System hardening"
    iconName: "security-high"
    help: "How well the system itself resists an attack that gets past the scanners. Harden sets the weak kernel settings (never looser than now); the rest say how to fix them."
    wide: true
    Layout.fillWidth: true
    onVisibleChanged: if (card.visible && card.report === null) card.load()
    Component.onCompleted: if (card.visible) card.load()
    actions: [
        QQC2.Button {
            objectName: "harden-apply"
            visible: card.report !== null && card.report.ok && card.report.canHarden
            enabled: !!card.host && !card.host.busy
            text: "Harden"
            icon.name: "security-high"
            onClicked: card.harden("apply")
        },
        QQC2.Button {
            objectName: "harden-revert"
            visible: card.report !== null && card.report.ok && card.report.canUndo
            enabled: !!card.host && !card.host.busy
            text: "Undo"
            icon.name: "edit-undo"
            onClicked: card.harden("revert")
        },
        QQC2.Button {
            text: "Refresh"
            icon.name: "view-refresh"
            onClicked: card.load()
        }
    ]

    Loading {
        loading: card.report === null
        problem: card.report !== null && !card.report.ok ? card.report.problem : ""
        what: "the hardening checks"
        Layout.fillWidth: true
    }
    Outcome {
        host: card.host
        noteKey: "harden"
        Layout.fillWidth: true
    }
    UqLabel {
        objectName: "hardening-summary"
        visible: card.report !== null && card.report.ok
        text: card.report !== null ? card.report.summary : ""
        font.bold: true
    }
    Repeater {
        model: card.report !== null && card.report.ok ? card.report.rows : []

        ColumnLayout {
            id: row

            required property var modelData
            required property int index

            spacing: 2
            Layout.fillWidth: true

            SettingRow {
                settingId: row.index === 0 ? "hardening" : ""
                label: row.modelData.title
                highlight: card.host ? card.host.highlight : ""
                Layout.fillWidth: true

                UqLabel {
                    text: row.modelData.text
                    color: card.stateColor(row.modelData.state)
                }
            }
            UqLabel {
                text: row.modelData.detail
                opacity: 0.7
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
            UqLabel {
                visible: row.modelData.fix !== ""
                text: "Fix: " + row.modelData.fix
                opacity: 0.7
                wrapMode: Text.Wrap
                Layout.fillWidth: true
            }
        }
    }
}
