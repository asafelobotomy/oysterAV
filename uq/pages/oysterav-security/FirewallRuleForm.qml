// The form for a new firewall rule, or for changing one. Saving asks for your password once.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "firewall.js" as Fw

ColumnLayout {
    id: box

    /// The Firewall tab (FirewallTab.qml): the form's values, and saving them.
    property var owner

    objectName: "fw-form"
    spacing: 4
    Layout.fillWidth: true

    UqLabel {
        text: box.owner.editing === null ? "New rule" : "Change: " + box.owner.editing.title + " · " + box.owner.editing.detail
        font.bold: true
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    SettingRow {
        label: "Do"
        Layout.fillWidth: true

        UqComboBox {
            objectName: "fw-form-action"
            model: Fw.FW_ACTIONS.map(a => Fw.FW_ACTION_LABELS[a])
            currentIndex: box.owner.form ? Fw.FW_ACTIONS.indexOf(box.owner.form.action) : 0
            onActivated: index => box.owner.setForm("action", Fw.FW_ACTIONS[index])
        }
    }
    SettingRow {
        label: "Port"
        Layout.fillWidth: true

        QQC2.TextField {
            objectName: "fw-form-port"
            text: box.owner.form ? box.owner.form.port : ""
            placeholderText: "8080 or 1714:1764"
            inputMethodHints: Qt.ImhPreferNumbers
            implicitWidth: 160
            onTextEdited: box.owner.setForm("port", text)
            onAccepted: box.owner.saveForm()
        }
        UqComboBox {
            objectName: "fw-form-proto"
            model: Fw.FW_PROTOS.map(p => Fw.FW_PROTO_LABELS[p])
            currentIndex: box.owner.form ? Fw.FW_PROTOS.indexOf(box.owner.form.proto) : 0
            onActivated: index => box.owner.setForm("proto", Fw.FW_PROTOS[index])
        }
    }
    SettingRow {
        label: "From"
        Layout.fillWidth: true

        QQC2.TextField {
            objectName: "fw-form-source"
            text: box.owner.form ? box.owner.form.source : ""
            placeholderText: "Anywhere, or 192.168.1.0/24"
            implicitWidth: 220
            onTextEdited: box.owner.setForm("source", text)
            onAccepted: box.owner.saveForm()
        }
    }
    UqLabel {
        visible: box.owner.formProblem !== ""
        text: box.owner.formProblem
        color: box.owner.host ? box.owner.host.errorColor() : "red"
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    RowLayout {
        Layout.alignment: Qt.AlignRight

        QQC2.Button {
            text: "Cancel"
            enabled: !box.owner.host.busy
            onClicked: box.owner.closeForm()
        }
        QQC2.Button {
            objectName: "fw-form-save"
            text: "Save rule"
            icon.name: "document-save"
            highlighted: true
            enabled: box.owner.usable
            onClicked: box.owner.saveForm()
        }
    }
}
