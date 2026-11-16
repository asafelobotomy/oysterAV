// One preference of oysterAV's config: a switch, a choice or a field, drawn from the schema `config show`
// prints, with oysterAV's own refusal under it. The file is followed, so after a change the row shows what
// was written.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

ColumnLayout {
    id: row

    property var host
    /// {key, label, help, kind, choices, min, value} from Logic.parseConfig.
    property var def
    property string settingId: ""
    readonly property string shown: Logic.prefText(row.def)
    readonly property string noteKey: "pref:" + row.def.key
    readonly property int rev: row.host ? row.host.prefsRev : 0

    /// Writes what the person chose or typed; a number that isn't one is refused here, in words.
    function commit(text) {
        const why = Logic.prefProblem(row.def, text);
        if (why !== "") {
            row.host.setNote(row.noteKey, { message: why, failed: true });
            return false;
        }
        return row.host.setPref(row.def.key, Logic.prefValue(row.def, text));
    }

    // After a write (accepted or refused) the field shows what the file holds, not what was typed.
    onRevChanged: field.text = Qt.binding(() => row.shown)

    spacing: 2

    SettingRow {
        settingId: row.settingId
        label: row.def.label
        highlight: row.host ? row.host.highlight : ""
        enabled: !!row.host && !row.host.busy
        Layout.fillWidth: true

        QQC2.Switch {
            objectName: "switch-" + row.def.key
            visible: row.def.kind === "bool"
            checked: row.def.value === true
            onToggled: {
                const want = checked;
                checked = Qt.binding(() => row.def.value === true);
                row.commit(want);
            }
        }
        UqComboBox {
            id: choice
            objectName: "choice-" + row.def.key
            visible: row.def.kind === "choice"
            model: row.def.choices
            currentIndex: row.def.choices.indexOf(row.shown)
            onActivated: index => row.commit(row.def.choices[index])
        }
        QQC2.TextField {
            id: field
            objectName: "field-" + row.def.key
            visible: row.def.kind !== "bool" && row.def.kind !== "choice"
            text: row.shown
            implicitWidth: row.def.kind === "int" ? 110 : 260
            onEditingFinished: {
                if (field.text === row.shown)
                    return;
                if (!row.commit(field.text))
                    field.text = Qt.binding(() => row.shown);
            }
        }
    }
    UqLabel {
        visible: row.def.help !== ""
        text: row.def.help
        opacity: 0.7
        wrapMode: Text.Wrap
        Layout.fillWidth: true
    }
    Outcome {
        host: row.host
        noteKey: row.noteKey
        Layout.fillWidth: true
    }
}
