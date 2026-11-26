// The Schedule tab: scans by a systemd timer, as you. Every change applies the timer at once.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic
import "reports.js" as Reports

SettingsTab {
    id: tab

    property var host
    readonly property var sched: tab.host ? tab.host.schedule : null
    readonly property bool usable: tab.sched !== null && tab.sched.ok && !!tab.host && !tab.host.busy

    function autoload() {
        if (tab.visible && tab.host && tab.host.schedule === null)
            tab.host.loadSchedule();
    }

    /// Writes one schedule setting, then reads the schedule again so the controls show what was saved.
    function set(key, command, value) {
        tab.host.write("schedule:" + key, command, [value], () => tab.host.loadSchedule(), "Saved.");
    }

    title: "Schedule"
    iconName: "appointment-new"
    onVisibleChanged: tab.autoload()

    SettingsCard {
        title: "Scheduled scans"
        iconName: "appointment-new"
        help: "A systemd timer in your account runs oysterAV on this schedule."
        wide: true
        Layout.fillWidth: true

        Loading {
            loading: tab.sched === null
            problem: tab.sched !== null && !tab.sched.ok ? tab.sched.problem : ""
            what: "the schedule"
            Layout.fillWidth: true
        }
        SwitchRow {
            id: enabledRow
            objectName: "schedule-enabled"
            settingId: "schedule"
            label: "Scan on a schedule"
            highlight: tab.host ? tab.host.highlight : ""
            value: tab.sched !== null && tab.sched.ok && tab.sched.enabled
            enabled: tab.usable
            onChosen: isOn => tab.host.write("schedule:enabled", isOn ? "schedule-enable" : "schedule-disable", [], () => tab.host.loadSchedule(), isOn ? "Scheduled scans are on." : "Scheduled scans are off.")
            Layout.fillWidth: true
        }
        UqLabel {
            visible: tab.sched !== null && tab.sched.ok
            text: tab.sched !== null ? Reports.scheduleLine(tab.sched) : ""
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Outcome {
            host: tab.host
            noteKey: "schedule:enabled"
            Layout.fillWidth: true
        }
        SettingRow {
            label: "How often"
            enabled: tab.usable
            Layout.fillWidth: true

            UqComboBox {
                id: frequencyBox
                objectName: "frequencyBox"
                model: Logic.FREQUENCIES
                currentIndex: tab.sched !== null && tab.sched.ok ? Logic.FREQUENCIES.indexOf(tab.sched.frequency) : -1
                onActivated: index => tab.set("frequency", "schedule-frequency", Logic.FREQUENCIES[index])
            }
        }
        UqLabel {
            visible: tab.sched !== null && tab.sched.ok && tab.sched.frequency === "custom"
            text: "This schedule uses a custom timer. Change it in oysterAV."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        SettingRow {
            label: "On"
            visible: tab.sched !== null && tab.sched.ok && tab.sched.frequency === "weekly"
            enabled: tab.usable
            Layout.fillWidth: true

            UqComboBox {
                id: weekdayBox
                objectName: "weekdayBox"
                model: Logic.WEEKDAYS.map(d => Logic.WEEKDAY_LABELS[d])
                currentIndex: tab.sched !== null && tab.sched.ok ? Logic.WEEKDAYS.indexOf(tab.sched.weekday) : -1
                onActivated: index => tab.set("weekday", "schedule-weekday", Logic.WEEKDAYS[index])
            }
        }
        SettingRow {
            label: "At (24-hour, HH:MM)"
            visible: tab.sched !== null && tab.sched.ok && tab.sched.frequency !== "hourly"
            enabled: tab.usable
            Layout.fillWidth: true

            QQC2.TextField {
                id: timeField
                objectName: "timeField"
                text: tab.sched !== null && tab.sched.ok ? tab.sched.time : ""
                implicitWidth: 90
                onEditingFinished: {
                    if (text === tab.sched.time)
                        return;
                    const why = Logic.argsProblem("schedule-time", [text]);
                    if (why !== "") {
                        tab.host.setNote("schedule:time", { message: "Use a 24-hour time like 02:30.", failed: true });
                        text = Qt.binding(() => tab.sched.time);
                        return;
                    }
                    tab.set("time", "schedule-time", text);
                }
            }
        }
        Outcome {
            host: tab.host
            noteKey: "schedule:time"
            Layout.fillWidth: true
        }
        SettingRow {
            label: "What to run"
            enabled: tab.usable
            Layout.fillWidth: true

            UqComboBox {
                id: profileBox
                objectName: "scheduleProfileBox"
                model: Logic.SCHEDULE_PROFILES.map(p => Logic.PROFILE_LABELS[p])
                currentIndex: tab.sched !== null && tab.sched.ok ? Logic.SCHEDULE_PROFILES.indexOf(tab.sched.profile) : -1
                onActivated: index => tab.set("profile", "schedule-profile", Logic.SCHEDULE_PROFILES[index])
            }
        }
        SettingRow {
            label: "Quarantine what it finds"
            enabled: tab.usable
            Layout.fillWidth: true

            UqComboBox {
                id: quarantineBox
                objectName: "scheduleQuarantineBox"
                model: Logic.QUARANTINE_MODES.map(m => Logic.QUARANTINE_LABELS[m])
                currentIndex: tab.sched !== null && tab.sched.ok ? Logic.QUARANTINE_MODES.indexOf(tab.sched.quarantine) : -1
                onActivated: index => tab.set("quarantine", "schedule-quarantine", Logic.QUARANTINE_MODES[index])
            }
        }
        Outcome {
            host: tab.host
            noteKey: "schedule:profile"
            Layout.fillWidth: true
        }
        UqLabel {
            objectName: "linger-warning"
            visible: tab.sched !== null && tab.sched.ok && tab.sched.enabled && tab.sched.lingerOff
            text: "Scans only run while you're logged in. Turn on \"Scans while logged out\" under Protection to run them any time."
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
    }

    SettingsCard {
        title: "Run it now"
        iconName: "media-playback-start"
        help: "Runs one scan with the schedule's profile and folders, once."
        Layout.fillWidth: true

        QQC2.Button {
            objectName: "schedule-run"
            text: "Run the scheduled scan now"
            icon.name: "media-playback-start"
            enabled: !!tab.host && !tab.host.busy
            onClicked: tab.host.write("schedule:run", "schedule-run", [], () => tab.host.reloadAll(), Reports.scheduleRunOutcome)
        }
        Outcome {
            host: tab.host
            noteKey: "schedule:run"
            bar: true
            Layout.fillWidth: true
        }
    }
}
