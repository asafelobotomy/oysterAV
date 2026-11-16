// oysterAV's "Security" page in uQ Settings. Everything runs through the commands declared
// in page.toml (oyst-cli as the user); the rootkit check asks for a password through
// oysterAV's own polkit helper. All text goes through UqLabel (plain text only).
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Dialogs
import QtQuick.Layouts
import org.uq.settings

Item {
    id: page

    property var ctx
    /// The [[setting]] id Settings search jumped to.
    property string highlight

    property var summary: null
    property string summaryProblem
    property var quarantine: []
    property string quarantineProblem
    property var schedule: null
    property string scheduleProblem
    /// The outcome of the last scan, update or quarantine action, as one line.
    property string actionMessage
    property bool actionFailed: false
    property string running

    readonly property color mutedColor: (ctx && ctx.theme.colors && ctx.theme.colors.text_muted) || "gray"
    readonly property color errorColor: (ctx && ctx.theme.colors && ctx.theme.colors.error) || "red"
    readonly property color warningColor: (ctx && ctx.theme.colors && ctx.theme.colors.warning) || "orange"
    readonly property color successColor: (ctx && ctx.theme.colors && ctx.theme.colors.success) || "green"

    function stamp(iso) {
        return iso ? String(iso).replace("T", " ").slice(0, 16) : "never";
    }

    function stateTitle() {
        if (page.summaryProblem !== "")
            return "Status unavailable";
        if (!page.summary)
            return "Checking…";
        if (page.summary.state === "ok")
            return "Protected";
        if (page.summary.state === "threat")
            return "Threat found";
        return "Needs attention";
    }

    function stateColor() {
        if (!page.summary || page.summaryProblem !== "")
            return page.mutedColor;
        if (page.summary.state === "ok")
            return page.successColor;
        if (page.summary.state === "threat")
            return page.errorColor;
        return page.warningColor;
    }

    function refreshSummary() {
        page.ctx.command.run("summary", [], r => {
            page.summaryProblem = r.error ? String(r.error) : "";
            page.summary = r.error ? null : r.output;
        });
    }

    function refreshQuarantine() {
        page.ctx.command.run("quarantine-list", [], r => {
            page.quarantineProblem = r.error ? String(r.error) : "";
            page.quarantine = (!r.error && Array.isArray(r.output)) ? r.output : [];
        });
    }

    function refreshSchedule() {
        page.ctx.command.run("schedule-status", [], r => {
            page.scheduleProblem = r.error ? String(r.error) : "";
            page.schedule = r.error ? null : r.output;
            // The controls were changed by hand; show what is saved now.
            var cfg = page.schedule && page.schedule.config;
            enabledSwitch.checked = page.schedule !== null && page.schedule.enabled === true;
            if (cfg) {
                frequencyBox.currentIndex = Math.max(0, frequencyBox.model.indexOf(String(cfg.frequency)));
                timeField.text = String(cfg.time);
            }
        });
    }

    function refresh() {
        if (!page.ctx)
            return;
        refreshSummary();
        refreshQuarantine();
        refreshSchedule();
    }

    // Runs one action command; `describe(output)` turns a success into one line.
    function act(id, args, describe) {
        page.running = id;
        page.ctx.command.run(id, args, r => {
            page.running = "";
            if (r.cancelled) {
                page.refreshSchedule();
                return;
            }
            if (r.error && r.output && typeof r.output === "object" && r.code === 1
                    && Array.isArray(r.output.findings)) {
                // `scan` exits 1 when it found threats: a result, not a failure.
                page.actionFailed = true;
                page.actionMessage = describe(r.output);
            } else if (r.error) {
                page.actionFailed = true;
                page.actionMessage = String(r.error);
            } else {
                page.actionFailed = false;
                page.actionMessage = describe(r.output);
            }
            page.refresh();
        });
    }

    function scanText(out) {
        if (!out || !Array.isArray(out.findings))
            return "Scan finished.";
        var n = out.findings.length;
        var errs = Array.isArray(out.pack_errors) ? out.pack_errors.length : 0;
        var text = n === 0 ? "No threats found." : n + (n === 1 ? " threat found" : " threats found")
            + ": " + out.findings.slice(0, 3).map(f => String(f.path) + " (" + String(f.threat_name) + ")").join(", ")
            + (n > 3 ? ", …" : "") + ". Quarantine them in oysterAV.";
        return errs > 0 ? text + " " + errs + " scanner error(s)." : text;
    }

    function folderPath(url) {
        var s = String(url);
        return s.startsWith("file://") ? decodeURIComponent(s.slice(7)) : "";
    }

    onCtxChanged: refresh()

    FolderDialog {
        id: folderDialog
        title: "Choose a folder to scan"
        onAccepted: {
            var p = page.folderPath(selectedFolder);
            if (p !== "")
                page.act("scan-folder", [p], page.scanText);
        }
    }

    QQC2.ScrollView {
        id: scroll
        anchors.fill: parent
        contentWidth: availableWidth

        ColumnLayout {
            width: scroll.availableWidth
            spacing: 18

            // ---- Status -------------------------------------------------------------------
            ColumnLayout {
                Layout.fillWidth: true
                Layout.margins: 16
                Layout.bottomMargin: 0
                spacing: 6

                UqLabel {
                    text: "Status"
                    font.bold: true
                    font.pixelSize: 15
                    font.underline: page.highlight === "status"
                }
                RowLayout {
                    spacing: 8
                    Rectangle {
                        width: 12
                        height: 12
                        radius: 6
                        color: page.stateColor()
                    }
                    UqLabel {
                        text: page.stateTitle()
                        font.bold: true
                    }
                    UqLabel {
                        visible: page.summary !== null && page.summary.scanning === true
                        text: "(a scan is running)"
                        color: page.mutedColor
                    }
                }
                Repeater {
                    model: page.summary ? page.summary.reasons : []
                    delegate: UqLabel {
                        required property var modelData
                        text: "• " + String(modelData)
                        wrapMode: Text.Wrap
                        Layout.fillWidth: true
                    }
                }
                UqLabel {
                    visible: page.summaryProblem !== ""
                    text: page.summaryProblem
                    color: page.errorColor
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                UqLabel {
                    visible: page.summary !== null
                    text: page.summary ? "Last scan: " + page.stamp(page.summary.last_scan_at)
                        + "    Signatures: " + (page.summary.signature_age_hours === null ? "missing"
                        : Math.round(page.summary.signature_age_hours) + " hours old")
                        + "    Quarantined files: " + Number(page.summary.quarantine_count || 0) : ""
                    color: page.mutedColor
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                RowLayout {
                    spacing: 8
                    QQC2.Button {
                        text: "Refresh"
                        onClicked: page.refresh()
                    }
                    QQC2.Button {
                        text: page.running === "update-signatures" ? "Updating…" : "Update signatures"
                        enabled: page.running === ""
                        onClicked: page.act("update-signatures", [],
                                            out => out && out.ok ? "Signatures updated." : "Signature update finished.")
                    }
                    QQC2.Button {
                        text: page.running === "rootkit-check" ? "Checking…" : "Check for rootkits…"
                        enabled: page.running === ""
                        onClicked: page.act("rootkit-check", [], page.scanText)
                    }
                }
            }

            // ---- Scan a folder ------------------------------------------------------------
            ColumnLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                spacing: 6

                UqLabel {
                    text: "Scan a folder"
                    font.bold: true
                    font.pixelSize: 15
                    font.underline: page.highlight === "scan"
                }
                UqLabel {
                    text: "A quick ClamAV scan as you. Nothing is moved; quarantine what it finds in oysterAV."
                    color: page.mutedColor
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                QQC2.Button {
                    text: page.running === "scan-folder" ? "Scanning…" : "Choose a folder…"
                    enabled: page.running === ""
                    onClicked: folderDialog.open()
                }
                UqLabel {
                    visible: page.actionMessage !== ""
                    text: page.actionMessage
                    color: page.actionFailed ? page.errorColor : page.successColor
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
            }

            // ---- Quarantine ---------------------------------------------------------------
            ColumnLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                spacing: 6

                UqLabel {
                    text: "Quarantine"
                    font.bold: true
                    font.pixelSize: 15
                    font.underline: page.highlight === "quarantine"
                }
                UqLabel {
                    visible: page.quarantineProblem === "" && page.quarantine.length === 0
                    text: "No quarantined files."
                    color: page.mutedColor
                }
                UqLabel {
                    visible: page.quarantineProblem !== ""
                    text: page.quarantineProblem
                    color: page.errorColor
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                Repeater {
                    model: page.quarantine
                    delegate: RowLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        spacing: 8
                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 0
                            UqLabel {
                                text: String(modelData.original_path)
                                elide: Text.ElideMiddle
                                Layout.fillWidth: true
                            }
                            UqLabel {
                                text: "#" + Number(modelData.id) + "  " + String(modelData.threat_name || "unknown")
                                    + "  " + page.stamp(modelData.quarantined_at)
                                color: page.mutedColor
                                elide: Text.ElideRight
                                Layout.fillWidth: true
                            }
                        }
                        QQC2.Button {
                            text: "Restore"
                            enabled: page.running === ""
                            onClicked: page.act("quarantine-restore", [String(Number(modelData.id))],
                                                out => "Restored to " + String(out && out.dest ? out.dest : "its folder") + ".")
                        }
                        QQC2.Button {
                            text: "Delete"
                            enabled: page.running === ""
                            onClicked: page.act("quarantine-delete", [String(Number(modelData.id))],
                                                () => "Deleted.")
                        }
                    }
                }
            }

            // ---- Schedule -----------------------------------------------------------------
            ColumnLayout {
                Layout.fillWidth: true
                Layout.leftMargin: 16
                Layout.rightMargin: 16
                Layout.bottomMargin: 16
                spacing: 6

                readonly property var cfg: page.schedule && page.schedule.config ? page.schedule.config : null

                UqLabel {
                    text: "Scheduled scans"
                    font.bold: true
                    font.pixelSize: 15
                    font.underline: page.highlight === "schedule"
                }
                UqLabel {
                    visible: page.scheduleProblem !== ""
                    text: page.scheduleProblem
                    color: page.errorColor
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                RowLayout {
                    visible: parent.cfg !== null
                    spacing: 8
                    QQC2.Switch {
                        id: enabledSwitch
                        enabled: page.running === ""
                        onToggled: {
                            if (checked)
                                page.act("schedule-enable", [], () => "Scheduled scans are on.");
                            else
                                page.act("schedule-disable", [], () => "Scheduled scans are off.");
                        }
                    }
                    UqLabel {
                        text: "Run a scan on a timer"
                    }
                }
                RowLayout {
                    visible: parent.cfg !== null
                    spacing: 8
                    UqLabel {
                        text: "How often"
                    }
                    QQC2.ComboBox {
                        id: frequencyBox
                        model: ["hourly", "daily", "weekly"]
                        enabled: page.running === ""
                        onActivated: page.act("schedule-frequency", [currentText], () => "Schedule updated.")
                    }
                    UqLabel {
                        text: "at"
                    }
                    QQC2.TextField {
                        id: timeField
                        implicitWidth: 72
                        inputMask: "99:99"
                        validator: RegularExpressionValidator {
                            regularExpression: /^([01][0-9]|2[0-3]):[0-5][0-9]$/
                        }
                    }
                    QQC2.Button {
                        text: "Set time"
                        enabled: page.running === "" && timeField.acceptableInput
                        onClicked: page.act("schedule-time", [timeField.text], () => "Schedule updated.")
                    }
                }
                UqLabel {
                    visible: page.schedule !== null && String(page.schedule.next || "") !== ""
                    text: page.schedule ? "Next run: " + String(page.schedule.next || "") : ""
                    color: page.mutedColor
                }
            }
        }
    }
}
