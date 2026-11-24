// The Firewall tab: the switch, the default rules, the rule list with its form, and firewalld's zones.
import QtQuick
import QtTest

PageHarness {
    id: root

    TestCase {
        id: tc
        name: "Firewall"
        when: windowShown

        function init() {
            root.reset();
        }

        function overview(extra) {
            return root.ok(Object.assign(root.fixture("firewall.json"), extra || {}));
        }

        function openFirewall() {
            root.tab("Firewall");
            tryVerify(() => root.named("fw-power") !== null);
            tryVerify(() => root.pageLoader.item.firewall !== null);
        }

        function test_followed_only_once_the_tab_opens() {
            compare(root.fakeCtx.calls.filter(c => c[0] === "watch" && c[1] === "firewall").length, 0);
            openFirewall();
            compare(root.fakeCtx.calls.filter(c => c[0] === "watch" && c[1] === "firewall").length, 1);
            verify(root.named("fw-power").checked);
            verify(root.shown("On · UFW 0.36.2") !== null);
            verify(root.shown("Allow 22/tcp") !== null);
            verify(root.shown("Allow 1714–1764/udp") !== null);
            verify(root.shown("Block 3306/tcp") !== null);
            compare(root.named("fw-default-incoming").currentIndex, 1, "block");
            compare(root.named("fw-default-outgoing").currentIndex, 0, "allow");
        }

        function test_a_change_in_a_terminal_shows_here() {
            openFirewall();
            root.fakeCtx.commands.firewall = overview({ rules: [] });
            root.fakeCtx.change("firewall");
            tryVerify(() => root.named("fw-rules-empty") !== null);
        }

        function test_turning_it_off_asks_and_reads_again() {
            openFirewall();
            root.fakeCtx.commands.firewall = overview({ on: false, active: "none" });
            root.flip(root.named("fw-power"));
            tryVerify(() => root.runs("fw-turn").length === 1);
            compare(root.runs("fw-turn")[0][2], ["off"]);
            tryVerify(() => root.shown("The firewall is off.") !== null);
            tryVerify(() => root.named("fw-power").checked === false);
            verify(root.showing("Turn the firewall on to change these.") !== null);
            verify(!root.named("fw-add-rule").enabled);
        }

        function test_declined_changes_nothing() {
            openFirewall();
            root.fakeCtx.confirms = false;
            root.flip(root.named("fw-power"));
            tryVerify(() => root.runs("fw-turn").length === 1);
            wait(50);
            verify(root.named("fw-power").checked, "the switch shows the firewall as it is");
            compare(root.shown("The firewall is off."), null);
        }

        function test_default_rule() {
            openFirewall();
            root.choose(root.named("fw-default-outgoing"), 1);
            tryVerify(() => root.runs("fw-policy").length === 1);
            compare(root.runs("fw-policy")[0][2], ["outgoing", "deny"]);
            compare(root.named("fw-default-outgoing").currentIndex, 0, "shows what is saved until it is read again");
        }

        function test_add_a_rule() {
            openFirewall();
            root.press(root.named("fw-add-rule"));
            tryVerify(() => root.named("fw-form") !== null);
            root.press(root.named("fw-form-save"));
            verify(root.showing("Type a port") !== null, "an empty port is caught here");
            compare(root.runs("fw-rule-add").length, 0);
            const port = root.named("fw-form-port");
            port.text = "8080";
            port.textEdited();
            root.choose(root.named("fw-form-action"), 2);
            const from = root.named("fw-form-source");
            from.text = "192.168.1.0/24";
            from.textEdited();
            root.press(root.named("fw-form-save"));
            tryVerify(() => root.runs("fw-rule-add").length === 1);
            compare(root.runs("fw-rule-add")[0][2], ["limit", "8080", "tcp", "192.168.1.0/24"]);
            tryVerify(() => root.named("fw-form") === null, 5000, "the form closes once the rule is added");
        }

        function test_change_and_remove_a_rule() {
            openFirewall();
            const rows = root.pageLoader.item.firewall.rules;
            const db = rows.findIndex(r => r.port === "3306");
            root.press(root.named("fw-edit-" + db));
            tryVerify(() => root.named("fw-form") !== null);
            compare(root.named("fw-form-source").text, "192.168.1.0/24");
            const from = root.named("fw-form-source");
            from.text = "";
            from.textEdited();
            root.press(root.named("fw-form-save"));
            tryVerify(() => root.runs("fw-rule-change").length === 1);
            compare(root.runs("fw-rule-change")[0][2], ["deny", "3306", "tcp", "192.168.1.0/24", "deny", "3306", "tcp", "anywhere"]);
            tryVerify(() => root.named("fw-form") === null);
            root.press(root.named("fw-remove-0"));
            tryVerify(() => root.runs("fw-rule-remove").length === 1);
            compare(root.runs("fw-rule-remove")[0][2], ["allow", "22", "tcp", "anywhere"]);
            const eth = rows.findIndex(r => r.port === "80");
            compare(root.named("fw-remove-" + eth), null, "a rule the page can't name exactly has no Remove");
        }

        function test_firewalld_zones() {
            root.fakeCtx.commands.firewall = overview({
                backend: "firewalld",
                active: "firewalld",
                installed: { ufw: true, firewalld: true },
                defaults: {},
                rules: [],
                zones: [
                    { name: "public", default: true, active: true, interfaces: ["wlan0"], services: ["ssh"], ports: ["8080/tcp"] },
                    { name: "home", default: false, active: false, interfaces: [], services: [], ports: [] }
                ]
            });
            openFirewall();
            tryVerify(() => root.named("fw-zone") !== null);
            compare(root.named("fw-default-incoming"), null, "default rules are UFW's");
            verify(root.named("fw-backend") !== null, "both installed: a choice of program");
            verify(root.shown("Service ssh") !== null);
            root.press(root.named("fw-close-0"));
            tryVerify(() => root.runs("fw-zone-service").length === 1);
            compare(root.runs("fw-zone-service")[0][2], ["remove", "public", "ssh"]);
            tryVerify(() => !root.pageLoader.item.busy, 5000, "one change at a time");
            root.named("fw-zone-port").text = "9000";
            root.press(root.shown("Open"));
            tryVerify(() => root.runs("fw-zone-port").length === 1);
            compare(root.runs("fw-zone-port")[0][2], ["add", "public", "9000/tcp"]);
            root.choose(root.named("fw-zone"), 1);
            tryVerify(() => root.showing("Nothing is open in this zone.") !== null);
        }
    }

    Component.onCompleted: root.tc = tc
}
