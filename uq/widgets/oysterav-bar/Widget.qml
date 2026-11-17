// oysterAV's bar shield: a coloured cell for ok / warning / threat from
// `oyst-cli status summary --deep --json` (never starts a scan). It sends a notification when the
// state gets worse (ok -> warning/threat, warning -> threat) and once at start if something is
// already wrong. Every string goes through ctx.UqText as plain text.
import QtQuick

Item {
    id: widget

    property var ctx
    property var summary: null
    property string problem: ""
    property string notified: "ok"

    readonly property string stateName: widget.problem !== "" ? "unknown"
        : (widget.summary ? String(widget.summary.state) : "")

    function rank(name) {
        return name === "threat" ? 2 : (name === "warning" ? 1 : 0);
    }

    function stateColor() {
        if (!widget.ctx)
            return "gray";
        var t = widget.ctx.Theme;
        if (widget.stateName === "ok")
            return t.success;
        if (widget.stateName === "threat")
            return t.error;
        if (widget.stateName === "warning")
            return t.warning;
        return t.textMuted;
    }

    // oysterAV's fixed wording only; the reasons are its own sentences, cleaned before they go out.
    function maybeNotify() {
        var now = widget.stateName;
        if (rank(now) > rank(widget.notified)) {
            var reasons = (widget.summary.reasons || []).map(function (r) {
                return String(r).replace(/[^A-Za-z0-9 ,.'()\/-]/g, " ");
            });
            var body = reasons.join(". ").slice(0, 200);
            widget.ctx.command.run("notify", [
                now === "threat" ? "critical" : "normal",
                now === "threat" ? "Security: threat found" : "Security: needs attention",
                body !== "" && /^[A-Za-z0-9]/.test(body) ? body : "Open Settings, Security for details."
            ], function () {});
        }
        widget.notified = now === "unknown" || now === "" ? widget.notified : now;
    }

    function refresh() {
        widget.ctx.command.run("summary", [], function (result) {
            if (result.error) {
                widget.problem = String(result.error);
                return;
            }
            widget.problem = "";
            widget.summary = result.output;
            widget.maybeNotify();
        });
    }

    Component.onCompleted: refresh()

    Timer {
        interval: 120000
        running: !widget.ctx || !widget.ctx.view || widget.ctx.view.shown
        repeat: true
        onTriggered: widget.refresh()
    }

    // Why the shield has its colour.
    property Component popup: Component {
        Item {
            id: detail

            property var ctx
            readonly property var lines: {
                if (widget.problem !== "")
                    return [widget.problem];
                var s = widget.summary;
                if (!s)
                    return ["Checking…"];
                var out = (s.reasons || []).map(function (r) { return String(r); });
                if (out.length === 0)
                    out.push("Protected: no open findings, signatures current.");
                (s.checks || []).forEach(function (c) {
                    out.push(String(c.id).replace("_", " ") + ": " + String(c.state));
                });
                return out;
            }

            implicitWidth: 260
            implicitHeight: column.implicitHeight + 16

            Column {
                id: column
                anchors.fill: parent
                anchors.margins: 8
                spacing: 4
                Repeater {
                    model: detail.lines
                    delegate: Loader {
                        required property var modelData
                        width: column.width
                        sourceComponent: detail.ctx ? detail.ctx.UqText : null
                        onLoaded: {
                            item.text = modelData;
                            item.width = Qt.binding(function () { return column.width; });
                        }
                    }
                }
            }
        }
    }

    Rectangle {
        anchors.centerIn: parent
        width: 16
        height: 16
        radius: 8
        color: "transparent"
        border.width: 2
        border.color: widget.stateColor()
        Rectangle {
            anchors.centerIn: parent
            width: 8
            height: 8
            radius: 4
            color: widget.stateColor()
        }
    }
    MouseArea {
        anchors.fill: parent
        onClicked: widget.ctx.openPopup()
    }
}
