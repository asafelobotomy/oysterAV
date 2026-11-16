// The Schedule and Protection tabs.
import QtQuick
import QtTest

PageHarness {
    id: root

    TestCase {
        id: tc
        name: "ScheduleProtection"
        when: windowShown

        function init() {
            root.reset();
        }

        function schedule(extra) {
            const doc = root.fixture("schedule.json");
            return root.ok(Object.assign(doc, extra || {}));
        }

        function openSchedule() {
            root.tab("Schedule");
            tryVerify(() => root.named("schedule-enabled") !== null);
        }

        function test_schedule_is_read_when_the_tab_opens() {
            compare(root.runs("schedule-status").length, 0);
            openSchedule();
            tryVerify(() => root.runs("schedule-status").length === 1);
            tryVerify(() => root.showing("Scheduled scans are off.") !== null);
            compare(root.named("frequencyBox").currentIndex, 1, "daily");
            compare(root.named("timeField").text, "02:00");
            compare(root.named("weekdayBox"), null, "weekday is for a weekly schedule only");
        }

        function test_turning_it_on_applies_the_timer_and_reads_again() {
            openSchedule();
            tryVerify(() => root.pageLoader.item.schedule !== null);
            root.fakeCtx.commands["schedule-status"] = schedule({ enabled: true, next: "Tue 2026-11-17 02:00:00 UTC", linger: { available: true, linger: true } });
            root.flip(root.named("schedule-enabled").toggle);
            tryVerify(() => root.runs("schedule-enable").length === 1);
            tryVerify(() => root.showing("Next scan: Tue 2026-11-17 02:00:00 UTC.") !== null);
            verify(root.shown("Scheduled scans are on.") !== null);
        }

        function test_turning_it_off_asks_first() {
            root.fakeCtx.commands["schedule-status"] = schedule({ enabled: true });
            openSchedule();
            tryVerify(() => root.named("schedule-enabled").value === true);
            root.fakeCtx.confirms = false;
            root.flip(root.named("schedule-enabled").toggle);
            tryVerify(() => root.runs("schedule-disable").length === 1);
            wait(50);
            compare(root.runs("schedule-status").length, 1, "declining changes nothing");
        }

        function test_how_often_what_and_quarantine() {
            openSchedule();
            tryVerify(() => root.pageLoader.item.schedule !== null);
            // what oysterAV will say once the change is saved
            root.fakeCtx.commands["schedule-status"] = schedule({ config: Object.assign(root.fixture("schedule.json").config, { frequency: "weekly", weekday: "fri" }) });
            root.choose(root.named("frequencyBox"), 2);
            tryVerify(() => root.runs("schedule-frequency").length === 1);
            compare(root.runs("schedule-frequency")[0][2], ["weekly"]);
            tryVerify(() => root.named("weekdayBox") !== null);
            compare(root.named("weekdayBox").currentIndex, 4, "Friday");
            tryVerify(() => !root.pageLoader.item.busy);
            root.choose(root.named("weekdayBox"), 0);
            tryVerify(() => root.runs("schedule-weekday").length === 1);
            compare(root.runs("schedule-weekday")[0][2], ["mon"]);
            tryVerify(() => !root.pageLoader.item.busy);
            root.choose(root.named("scheduleProfileBox"), 1);
            tryVerify(() => root.runs("schedule-profile").length === 1);
            compare(root.runs("schedule-profile")[0][2], ["full"]);
            tryVerify(() => !root.pageLoader.item.busy);
            root.choose(root.named("scheduleQuarantineBox"), 2);
            tryVerify(() => root.runs("schedule-quarantine").length === 1);
            compare(root.runs("schedule-quarantine")[0][2], ["off"]);
        }

        function test_a_bad_time_is_refused_in_words_and_runs_nothing() {
            openSchedule();
            tryVerify(() => root.pageLoader.item.schedule !== null);
            root.type(root.named("timeField"), "25:99");
            tryVerify(() => root.shown("Use a 24-hour time like 02:30.") !== null);
            compare(root.runs("schedule-time").length, 0);
            compare(root.named("timeField").text, "02:00", "the field shows what is saved");
            root.type(root.named("timeField"), "03:15");
            tryVerify(() => root.runs("schedule-time").length === 1);
            compare(root.runs("schedule-time")[0][2], ["03:15"]);
        }

        function test_a_custom_schedule_is_said_to_be_custom() {
            root.fakeCtx.commands["schedule-status"] = schedule({ config: Object.assign(root.fixture("schedule.json").config, { frequency: "custom" }) });
            openSchedule();
            tryVerify(() => root.showing("This schedule uses a custom timer") !== null);
            compare(root.named("frequencyBox").currentIndex, -1);
        }

        function test_scans_only_while_logged_in_is_warned_about() {
            root.fakeCtx.commands["schedule-status"] = schedule({ enabled: true, linger: { available: true, linger: false } });
            openSchedule();
            tryVerify(() => root.named("linger-warning") !== null);
        }

        function test_run_now_asks_and_shows_what_it_found() {
            openSchedule();
            root.fakeCtx.confirms = false;
            root.press(root.named("schedule-run"));
            tryVerify(() => root.runs("schedule-run").length === 1);
            wait(50);
            verify(root.shown("The scan finished. No threats found.") === null);
            root.fakeCtx.confirms = true;
            root.fakeCtx.commands["schedule-run"] = { code: 1, error: "exit code 1", output: { exit_code: 1, scan: { findings: [{ path: "/x", threat_name: "T" }] } } };
            root.press(root.named("schedule-run"));
            tryVerify(() => root.shown("The scan found 1 threat. See Scans.") !== null);
        }

        function test_protection_lists_the_services_and_their_state() {
            root.tab("Protection");
            tryVerify(() => root.named("service-clamd") !== null);
            verify(root.shown("ClamAV daemon") !== null);
            compare(root.named("service-clamd").checked, false);
            verify(root.shown("Not installed") !== null, "on-access scanning isn't installed here");
            // oysterAV's helper isn't installed in the recorded state: say so on this tab
            tryVerify(() => root.shown("oysterAV's helper isn't ready") !== null);
        }

        function test_a_service_switch_asks_and_snaps_back_until_it_is_really_on() {
            root.tab("Protection");
            tryVerify(() => root.named("service-clamd") !== null);
            root.fakeCtx.confirms = false;
            root.flip(root.named("service-clamd"));
            tryVerify(() => root.runs("service-set").length === 1);
            compare(root.runs("service-set")[0][2], ["clamd", "on"]);
            compare(root.named("service-clamd").checked, false, "declined: still off");
            tryVerify(() => !root.pageLoader.item.busy);
            root.fakeCtx.confirms = true;
            const on = root.fixture("services.json");
            on.services.clamd.running = true;
            root.fakeCtx.commands.services = root.ok(on);
            root.flip(root.named("service-clamd"));
            tryVerify(() => root.runs("service-set").length === 2);
            tryVerify(() => root.named("service-clamd").checked === true);
            verify(root.shown("Turned on.") !== null);
        }

        function test_a_refused_service_change_shows_why() {
            root.tab("Protection");
            tryVerify(() => root.named("service-clamd") !== null);
            root.fakeCtx.commands["service-set"] = { code: 2, error: "exit code 2", output: { ok: false, error: "authorization was dismissed" } };
            root.flip(root.named("service-clamd"));
            tryVerify(() => root.shown("authorization was dismissed") !== null);
            compare(root.named("service-clamd").checked, false);
        }
    }

    Component.onCompleted: root.tc = tc
}
