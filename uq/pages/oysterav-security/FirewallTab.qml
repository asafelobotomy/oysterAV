// The Firewall tab: the firewall on or off, which program runs it, what happens to connections no rule
// matches, and the rules themselves (UFW) or each zone's open ports and services (firewalld). Every change
// asks for your password once, through oysterAV's own helper, and shows its plan first. Nothing here runs
// as root; the read needs no password and follows UFW's files, so a change made in a terminal shows too.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic
import "firewall.js" as Fw

SettingsTab {
    id: tab

    property var host
    readonly property var fw: tab.host ? tab.host.firewall : null
    readonly property bool ready: tab.fw !== null && tab.fw.ok
    readonly property bool ufw: tab.ready && tab.fw.backend === "ufw"
    readonly property bool firewalld: tab.ready && tab.fw.backend === "firewalld"
    /// Rules and default rules can change only while the firewall runs.
    readonly property bool usable: tab.ready && tab.fw.on && !tab.fw.conflict && !tab.host.busy

    /// The rule form: null when closed; {action, port, proto, source} while adding or changing a rule.
    property var form: null
    /// The rule being changed (a row of fw.rules), or null when the form adds one.
    property var editing: null
    property string formProblem: ""
    /// The firewalld zone shown (its name); the default zone until another is picked.
    property string zoneName: ""
    readonly property var zone: {
        if (!tab.firewalld || tab.fw.zones.length === 0)
            return null;
        for (let i = 0; i < tab.fw.zones.length; ++i)
            if (tab.fw.zones[i].name === tab.zoneName)
                return tab.fw.zones[i];
        return tab.fw.zones[0];
    }

    function autoload() {
        if (tab.visible && tab.host)
            tab.host.followFirewall();
    }

    function after() {
        tab.host.loadFirewall();
    }

    function openForm(rule) {
        tab.editing = rule || null;
        tab.form = Fw.fwForm(rule || null);
        tab.formProblem = "";
    }

    function closeForm() {
        tab.form = null;
        tab.editing = null;
        tab.formProblem = "";
    }

    function setForm(key, value) {
        const next = Object.assign({}, tab.form);
        next[key] = value;
        tab.form = next;
        tab.formProblem = "";
    }

    function saveForm() {
        const why = Fw.fwFormProblem(tab.form);
        if (why !== "") {
            tab.formProblem = why;
            return;
        }
        const args = Fw.fwRuleArgs(tab.form);
        const started = tab.editing === null
            ? tab.host.write("fw:form", "fw-rule-add", args, r => { if (Logic.envelope(r).ok) tab.closeForm(); tab.after(); }, "Rule added.")
            : tab.host.write("fw:form", "fw-rule-change", Fw.fwRuleArgs(Fw.fwForm(tab.editing)).concat(args), r => { if (Logic.envelope(r).ok) tab.closeForm(); tab.after(); }, "Rule changed.");
        if (!started && tab.host.noteFor("fw:form") === null)
            tab.formProblem = "Wait for the change that is running to finish.";
    }

    function openInZone(kind, value) {
        const command = kind === "port" ? "fw-zone-port" : "fw-zone-service";
        tab.host.write("fw:zone", command, ["add", tab.zone.name, value], () => tab.after(), value + " is open.");
    }

    title: "Firewall"
    iconName: "network-wired"
    onVisibleChanged: tab.autoload()
    Component.onCompleted: tab.autoload()

    SettingsCard {
        title: "Firewall"
        iconName: "security-high"
        help: "Decides which connections may reach this computer. UFW is what Bindle sets up; firewalld works too."
        Layout.fillWidth: true
        actions: [
            QQC2.Button {
                text: "Refresh"
                icon.name: "view-refresh"
                onClicked: tab.after()
            }
        ]

        Loading {
            loading: tab.fw === null
            problem: tab.fw !== null && !tab.fw.ok ? tab.fw.problem : ""
            what: "the firewall"
            Layout.fillWidth: true
        }
        ErrorCard {
            visible: tab.ready && tab.fw.conflict
            title: "UFW and firewalld are both running"
            detail: "Two firewalls fight over the same rules. Choose one below; the other is stopped."
            Layout.fillWidth: true
        }
        SettingRow {
            settingId: "firewall"
            label: "Firewall"
            highlight: tab.host ? tab.host.highlight : ""
            visible: tab.ready
            enabled: tab.ready && tab.fw.backend !== "none" && !tab.fw.conflict && !tab.host.busy
            Layout.fillWidth: true

            UqLabel {
                objectName: "fw-status"
                text: tab.ready ? tab.fw.statusText : ""
                opacity: 0.7
            }
            QQC2.Switch {
                objectName: "fw-power"
                checked: tab.ready && tab.fw.on
                onToggled: {
                    const want = checked;
                    checked = Qt.binding(() => tab.ready && tab.fw.on);
                    tab.host.write("fw:power", "fw-turn", [want ? "on" : "off"], () => tab.after(), want ? "The firewall is on." : "The firewall is off.");
                }
            }
        }
        UqLabel {
            visible: tab.ready && tab.fw.backend === "none"
            text: tab.ready && tab.fw.handMade
                ? "This computer's firewall rules were set up by hand (nftables). Change them from a terminal."
                : "No firewall program is installed. Install UFW from Bindle's Security group, then come back here."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        SettingRow {
            label: "Firewall program"
            visible: tab.ready && (tab.fw.bothInstalled || tab.fw.conflict)
            enabled: tab.ready && !tab.host.busy
            Layout.fillWidth: true

            UqComboBox {
                objectName: "fw-backend"
                model: ["UFW", "firewalld"]
                currentIndex: tab.ready ? Fw.FW_BACKENDS.indexOf(tab.fw.backend) : -1
                onActivated: index => {
                    const pick = Fw.FW_BACKENDS[index];
                    currentIndex = Qt.binding(() => tab.ready ? Fw.FW_BACKENDS.indexOf(tab.fw.backend) : -1);
                    tab.host.write("fw:power", "fw-use", [pick], () => tab.after(), Fw.FW_NAMES[pick] + " is the firewall now.");
                }
            }
        }
        UqLabel {
            visible: tab.ready && tab.fw.sshInUse
            text: "This computer runs an SSH server, so changes that would shut SSH out (port 22) are refused."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Outcome {
            host: tab.host
            noteKey: "fw:power"
            bar: true
            Layout.fillWidth: true
        }
    }

    SettingsCard {
        title: "Default rules"
        iconName: "view-filter"
        help: "What happens to a connection that none of your rules match."
        visible: tab.ufw
        Layout.fillWidth: true

        Repeater {
            model: Fw.FW_DIRECTIONS

            ColumnLayout {
                id: dir

                required property var modelData
                required property int index
                readonly property string now: tab.ufw ? tab.fw.defaults[dir.modelData.id] : ""

                spacing: 2
                Layout.fillWidth: true

                SettingRow {
                    settingId: dir.index === 0 ? "firewall-defaults" : ""
                    label: dir.modelData.label
                    highlight: tab.host ? tab.host.highlight : ""
                    enabled: tab.usable
                    Layout.fillWidth: true

                    UqComboBox {
                        objectName: "fw-default-" + dir.modelData.id
                        model: Fw.FW_POLICIES.map(p => Fw.FW_POLICY_LABELS[p])
                        currentIndex: Fw.FW_POLICIES.indexOf(dir.now)
                        onActivated: index => {
                            const pick = Fw.FW_POLICIES[index];
                            currentIndex = Qt.binding(() => Fw.FW_POLICIES.indexOf(dir.now));
                            if (pick !== dir.now)
                                tab.host.write("fw:default:" + dir.modelData.id, "fw-policy", [dir.modelData.id, pick], () => tab.after(), dir.modelData.label + ": " + Fw.FW_POLICY_LABELS[pick].toLowerCase() + ".");
                        }
                    }
                }
                UqLabel {
                    text: dir.modelData.help
                    opacity: 0.7
                    wrapMode: Text.Wrap
                    Layout.fillWidth: true
                }
                Outcome {
                    host: tab.host
                    noteKey: "fw:default:" + dir.modelData.id
                    Layout.fillWidth: true
                }
            }
        }
        UqLabel {
            visible: tab.ufw && !tab.fw.on
            text: "Turn the firewall on to change these."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
    }

    SettingsCard {
        title: "Rules"
        iconName: "view-list-details"
        help: "Exceptions to the default rules, checked from the top. Allow lets a port in; Block keeps it out; Limit lets it in but shuts out an address that connects six times in 30 seconds."
        visible: tab.ufw
        wide: true
        Layout.fillWidth: true
        actions: [
            QQC2.Button {
                objectName: "fw-add-rule"
                text: "Add rule…"
                icon.name: "list-add"
                enabled: tab.usable && tab.form === null
                onClicked: tab.openForm(null)
            }
        ]

        FirewallRuleForm {
            owner: tab
            visible: tab.form !== null
            Layout.fillWidth: true
        }
        Outcome {
            host: tab.host
            noteKey: "fw:form"
            bar: true
            Layout.fillWidth: true
        }

        UqLabel {
            objectName: "fw-rules-empty"
            visible: tab.ufw && tab.fw.rules.length === 0 && tab.fw.rulesReadable
            text: "No rules yet: only the default rules apply."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        UqLabel {
            visible: tab.ufw && !tab.fw.rulesReadable
            text: "UFW's rule files can't be read without your password on this computer, so the rules aren't listed. Adding a rule still works."
            opacity: 0.7
            wrapMode: Text.Wrap
            Layout.fillWidth: true
        }
        Repeater {
            model: tab.ufw ? tab.fw.rules : []

            ColumnLayout {
                id: rule

                required property var modelData
                required property int index

                spacing: 2
                Layout.fillWidth: true

                SettingRow {
                    settingId: rule.index === 0 ? "firewall-rules" : ""
                    label: rule.modelData.title
                    highlight: tab.host ? tab.host.highlight : ""
                    Layout.fillWidth: true

                    UqLabel {
                        visible: !rule.modelData.removable
                        text: "Change in a terminal"
                        opacity: 0.6
                    }
                    QQC2.Button {
                        objectName: "fw-edit-" + rule.index
                        text: "Change…"
                        icon.name: "document-edit"
                        visible: rule.modelData.editable
                        enabled: tab.usable && tab.form === null
                        onClicked: tab.openForm(rule.modelData)
                    }
                    QQC2.Button {
                        objectName: "fw-remove-" + rule.index
                        text: "Remove"
                        icon.name: "list-remove"
                        visible: rule.modelData.removable
                        enabled: tab.usable
                        onClicked: tab.host.write(rule.modelData.key, "fw-rule-remove", Fw.fwRuleArgs(Fw.fwForm(rule.modelData)), () => tab.after(), "Rule removed.")
                    }
                }
                UqLabel {
                    text: rule.modelData.detail
                    opacity: 0.7
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                }
                Outcome {
                    host: tab.host
                    noteKey: rule.modelData.key
                    Layout.fillWidth: true
                }
            }
        }
    }

    FirewallZones {
        owner: tab
        Layout.fillWidth: true
    }
}
