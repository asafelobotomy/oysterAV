// The Preferences tab: every setting oysterAV's config file holds that makes sense here, in cards by topic.
// The file is followed (page.toml `watch`), so a change made in oysterAV or by hand shows here.
import QtQuick
import QtQuick.Layouts
import org.uq.settings
import "reports.js" as Reports

SettingsTab {
    id: tab

    property var host
    readonly property var prefs: tab.host ? tab.host.prefs : null

    title: "Preferences"
    iconName: "configure"

    SettingsCard {
        title: "Preferences"
        iconName: "configure"
        help: "oysterAV checks every value before it saves it, and says why when it refuses."
        wide: true
        visible: tab.prefs === null || !tab.prefs.ok
        Layout.fillWidth: true

        Loading {
            loading: tab.prefs === null
            problem: tab.prefs !== null && !tab.prefs.ok ? tab.prefs.problem : ""
            what: "oysterAV's preferences"
            Layout.fillWidth: true
        }
    }
    Repeater {
        model: tab.prefs !== null && tab.prefs.ok ? tab.prefs.groups : []

        SettingsCard {
            id: card

            required property var modelData
            required property int index

            title: card.modelData.title
            iconName: Reports.groupIcon(card.modelData.title)
            wide: true
            Layout.fillWidth: true

            Repeater {
                model: card.modelData.rows

                PrefRow {
                    required property var modelData
                    required property int index

                    host: tab.host
                    def: modelData
                    settingId: card.index === 0 && index === 0 ? "preferences" : ""
                    Layout.fillWidth: true
                }
            }
        }
    }
    SettingsCard {
        title: "Where these are kept"
        iconName: "document-properties"
        visible: tab.prefs !== null && tab.prefs.ok
        wide: true
        Layout.fillWidth: true

        UqLabel {
            text: tab.prefs !== null && tab.prefs.ok ? tab.prefs.path : ""
            wrapMode: Text.WrapAnywhere
            opacity: 0.7
            Layout.fillWidth: true
        }
    }
}
