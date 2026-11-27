// The Preferences tab (rows drawn from `config show`, followed live) and the System tab.
import QtQuick
import QtTest

PageHarness {
    id: root

    TestCase {
        id: tc
        name: "PreferencesSystem"
        when: windowShown

        function init() {
            root.reset();
        }

        function openPrefs() {
            root.tab("Preferences");
            tryVerify(() => root.named("switch-quarantine.auto") !== null);
        }

        function test_every_setting_of_the_schema_has_a_row() {
            openPrefs();
            const keys = Object.keys(root.fixture("config.json").values);
            const page = root.pageLoader.item;
            compare(Object.keys(page.prefs.byKey).length, keys.length);
            // a row of each kind is drawn
            verify(root.named("switch-quarantine.auto") !== null);
            verify(root.named("choice-scan.backend") !== null);
            verify(root.named("field-scan.max_files") !== null);
            verify(root.named("field-clamonacc.paths") !== null);
            verify(root.shown("Default scan") !== null);
            verify(root.shown("Quarantine") !== null, "cards are by topic");
        }

        function test_the_values_are_those_in_the_file() {
            openPrefs();
            compare(root.named("field-scan.max_files").text, "10000");
            compare(root.named("field-clamonacc.paths").text, "~/Downloads, ~/Desktop");
            compare(root.named("choice-scan.backend").currentIndex, 0);
            compare(root.named("switch-quarantine.auto").checked, false);
        }

        function test_a_switch_writes_and_the_file_then_shows_it() {
            openPrefs();
            root.fakeCtx.commands["config-set"] = root.ok({ ok: true, key: "quarantine.auto", value: "true" });
            root.fakeCtx.commands.config = root.config({ "quarantine.auto": true });
            root.flip(root.named("switch-quarantine.auto"));
            tryVerify(() => root.runs("config-set").length === 1);
            compare(root.runs("config-set")[0][2], ["quarantine.auto", "true"]);
            tryVerify(() => root.named("switch-quarantine.auto").checked === true);
            verify(root.shown("Saved.") !== null);
        }

        function test_a_choice_writes_its_text() {
            openPrefs();
            root.choose(root.named("choice-scan.backend"), 2);
            tryVerify(() => root.runs("config-set").length === 1);
            compare(root.runs("config-set")[0][2], ["scan.backend", "clamscan"]);
        }

        function test_a_number_is_checked_here_first_and_then_by_oysterAV() {
            openPrefs();
            root.type(root.named("field-scan.max_files"), "abc");
            tryVerify(() => root.shown("Files per archive must be a whole number.") !== null);
            compare(root.runs("config-set").length, 0, "nothing was sent");
            compare(root.named("field-scan.max_files").text, "10000", "the field shows what is saved");
            root.type(root.named("field-scan.max_files"), "0");
            tryVerify(() => root.shown("Files per archive must be at least 1.") !== null);
            compare(root.runs("config-set").length, 0);
            root.fakeCtx.commands["config-set"] = { code: 2, error: "exit code 2", output: { ok: false, key: "scan.max_files", error: "scan.max_files must be <= 1000000" } };
            root.type(root.named("field-scan.max_files"), "99999999");
            tryVerify(() => root.shown("scan.max_files must be <= 1000000") !== null);
            tryVerify(() => root.named("field-scan.max_files").text === "10000", 2000, "the field shows what is saved again");
        }

        function test_a_list_is_sent_comma_separated() {
            openPrefs();
            root.type(root.named("field-clamonacc.paths"), " ~/Downloads , /srv/share ,");
            tryVerify(() => root.runs("config-set").length === 1);
            compare(root.runs("config-set")[0][2], ["clamonacc.paths", "~/Downloads,/srv/share"]);
        }

        function test_a_change_made_elsewhere_shows_up() {
            openPrefs();
            root.fakeCtx.commands.config = root.config({ "scan.max_files": 777 });
            root.fakeCtx.change("config");
            tryVerify(() => root.named("field-scan.max_files").text === "777");
        }

        function test_a_failed_read_says_so() {
            root.fakeCtx.commands.config = { code: 2, error: "exit code 2: invalid config.toml", output: null };
            root.open();
            root.tab("Preferences");
            tryVerify(() => root.shown("Couldn't read oysterAV's preferences") !== null);
            verify(root.showing("invalid config.toml") !== null);
        }

        function test_system_shows_scanners_the_helper_and_the_audit_log() {
            root.tab("System");
            tryVerify(() => root.shown("clamav · Needed") !== null);
            verify(root.shown("Missing") !== null);
            verify(root.showing("Install: sudo apt install clamav") !== null);
            tryVerify(() => root.showing("oysterAV's helper isn't installed") !== null);
            tryVerify(() => root.shown("config.set: scan.max_files") !== null);
            compare(root.runs("doctor").length, 1);
            compare(root.runs("audit").length, 1);
        }

        function test_system_shows_the_hardening_checks_with_fixes() {
            root.tab("System");
            tryVerify(() => root.named("hardening-summary") !== null && root.named("hardening-summary").visible);
            compare(root.named("hardening-summary").text, "15 of 22 checks pass, 3 need attention.");
            verify(root.shown("App confinement (AppArmor or SELinux)") !== null);
            verify(root.shown("Kernel pointers hidden") !== null);
            verify(root.showing("Fix: kernel.kptr_restrict = 1") !== null);
            compare(root.runs("hardening").length, 1);
        }

        function test_harden_writes_the_sysctl_file_and_reads_again() {
            root.tab("System");
            tryVerify(() => root.named("harden-apply") !== null && root.named("harden-apply").visible);
            verify(root.named("harden-revert") === null || !root.named("harden-revert").visible, "nothing to undo yet");
            root.press(root.named("harden-apply"));
            tryVerify(() => root.runs("harden-set").length === 1);
            compare(root.runs("harden-set")[0][2], ["apply"]);
            tryVerify(() => root.runs("hardening").length === 2);
            tryVerify(() => root.showing("Kernel hardening is on.") !== null);
        }

        function test_a_failed_hardening_read_says_so() {
            root.fakeCtx.commands.hardening = { code: 2, error: "exit code 2", output: null };
            root.tab("System");
            tryVerify(() => root.showing("the hardening checks") !== null);
        }

        function test_an_empty_audit_log_says_so() {
            root.fakeCtx.commands.audit = root.ok([]);
            root.tab("System");
            tryVerify(() => root.named("audit-empty") !== null);
        }

        function test_scanner_text_is_plain() {
            root.fakeCtx.commands.doctor = root.ok([{ name: "<b>x</b>", tier: "required", installed: false, install_hint: "<a href='http://evil'>go</a>" }]);
            root.tab("System");
            tryVerify(() => root.shown("<b>x</b> · Needed") !== null);
            verify(root.showing("<a href=") !== null, "shown as text, not as a link");
        }
    }

    Component.onCompleted: root.tc = tc
}
