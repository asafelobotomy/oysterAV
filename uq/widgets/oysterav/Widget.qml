// oysterAV's quick-settings tile: ok / warning / threat and the last scan time, from
// `oyst-cli status summary --json` (never starts a scan). Every string goes through
// ctx.UqText as plain text.
import QtQuick

Item {
    id: widget

    property var ctx
    property var summary: null
    property string problem: ""

    readonly property string stateName: widget.problem !== "" ? "unknown"
        : (widget.summary ? String(widget.summary.state) : "")

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

    function stateLabel() {
        if (widget.problem !== "")
            return "Security: unavailable";
        if (!widget.summary)
            return "Security: checking…";
        if (widget.summary.scanning)
            return "Security: scanning…";
        if (widget.stateName === "ok")
            return "Security: protected";
        if (widget.stateName === "threat")
            return "Security: threat found";
        return "Security: needs attention";
    }

    // "2 h ago", "3 d ago"; the summary's own age keeps clock zones out of it.
    function ago(hours) {
        if (hours === null || hours === undefined)
            return "never";
        if (hours < 1)
            return "just now";
        if (hours < 48)
            return Math.floor(hours) + " h ago";
        return Math.floor(hours / 24) + " d ago";
    }

    function lastScanLabel() {
        if (!widget.summary)
            return "";
        return "Last scan " + widget.ago(widget.summary.last_scan_age_hours);
    }

    function refresh() {
        widget.ctx.command.run("summary", [], function (result) {
            if (result.error) {
                widget.problem = String(result.error);
                return;
            }
            widget.problem = "";
            widget.summary = result.output;
        });
    }

    Component.onCompleted: refresh()

    Timer {
        interval: 60000
        running: true
        repeat: true
        onTriggered: widget.refresh()
    }

    // The detail view under the tile: why the state is what it is.
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
                    out.push("No open findings; signatures are current.");
                out.push("Last scan: " + (s.last_scan_at ? String(s.last_scan_at).replace("T", " ").slice(0, 16) : "never"));
                out.push("Signatures: " + (s.signature_age_hours === null ? "missing"
                    : Math.round(s.signature_age_hours) + " h old"));
                out.push("Quarantined files: " + Number(s.quarantine_count || 0));
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
        anchors.fill: parent
        radius: widget.ctx ? widget.ctx.Theme.radius - 2 : 4
        color: mouse.containsMouse && widget.ctx ? widget.ctx.Theme.overlay : "transparent"
    }
    Rectangle {
        id: dot
        width: 10
        height: 10
        radius: 5
        anchors.left: parent.left
        anchors.leftMargin: 10
        anchors.verticalCenter: parent.verticalCenter
        color: widget.stateColor()
    }
    Loader {
        id: title
        anchors.left: dot.right
        anchors.leftMargin: 8
        anchors.right: when.left
        anchors.rightMargin: 8
        anchors.verticalCenter: parent.verticalCenter
        sourceComponent: widget.ctx ? widget.ctx.UqText : null
        onLoaded: item.text = Qt.binding(function () { return widget.stateLabel(); })
    }
    Loader {
        id: when
        anchors.right: parent.right
        anchors.rightMargin: 10
        anchors.verticalCenter: parent.verticalCenter
        sourceComponent: widget.ctx ? widget.ctx.UqText : null
        onLoaded: {
            item.text = Qt.binding(function () { return widget.lastScanLabel(); });
            item.color = Qt.binding(function () { return widget.ctx.Theme.textMuted; });
        }
    }
    MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: true
        onClicked: widget.ctx.openPopup()
    }
}
