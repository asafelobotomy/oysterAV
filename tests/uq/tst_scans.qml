// The Scans tab: a folder scan with streamed progress, the plan line, quarantining a finding, the rootkit check and history.
import QtQuick
import QtTest

PageHarness {
    id: root

    TestCase {
        id: tc
        name: "Scans"
        when: windowShown

        function init() {
            root.reset();
            root.tab("Scans");
            tryVerify(() => root.named("folderField") !== null);
        }

        function choose(path) {
            root.type(root.named("folderField"), path);
            tryVerify(() => root.runs("preview-scan").length > 0);
        }

        function test_history_is_read_when_the_tab_opens() {
            tryVerify(() => root.shown("Quick (ClamAV) · 2026-11-16 09:30") !== null);
            verify(root.shown("1 threat found") !== null);
            compare(root.runs("history").length, 1);
        }

        function test_an_empty_history_says_so() {
            root.fakeCtx.commands.history = root.ok([]);
            root.pageLoader.item.loadHistory();
            tryVerify(() => root.named("history-empty") !== null);
        }

        function test_choosing_a_folder_counts_its_files() {
            choose("/home/user/Downloads");
            tryVerify(() => root.named("folder-plan") !== null);
            compare(root.named("folder-plan").text, "1 files, 1 scanner(s)");
            compare(root.runs("preview-scan")[0][2], ["quick", "/home/user/Downloads"]);
            root.choose(root.named("profileBox"), 1);
            tryVerify(() => root.runs("preview-scan").length === 2);
            compare(root.runs("preview-scan")[1][2], ["full", "/home/user/Downloads"]);
        }

        function test_a_missing_folder_is_refused_by_the_plan() {
            root.fakeCtx.commands["preview-scan"] = root.ok({ summary: "x", changes: [], would_refuse: true, reason: "Not found: /nope" });
            choose("/nope");
            tryVerify(() => root.named("folder-plan") !== null && root.named("folder-plan").text === "Not found: /nope");
        }

        function test_a_bad_path_is_refused_before_anything_runs() {
            root.type(root.named("folderField"), "relative/path");
            tryVerify(() => root.named("folder-plan") !== null);
            compare(root.named("folder-plan").text, "That value isn't allowed here.");
            compare(root.runs("preview-scan").length, 0);
            verify(!root.named("scan-button").enabled);
        }

        function test_scan_streams_progress_then_offers_the_threat() {
            choose("/home/user/Downloads");
            root.press(root.named("scan-button"));
            tryVerify(() => root.streams("scan-folder").length === 1);
            compare(root.streams("scan-folder")[0][2], ["quick", "/home/user/Downloads"]);
            tryVerify(() => root.named("verdict-scan") !== null);
            compare(root.named("verdict-scan").text, "1 threat found.");
            verify(root.shown("Win.Test.EICAR_HDB-1") !== null);
            verify(root.showing("Finished.") !== null);
            tryVerify(() => root.runs("summary").length >= 2 && root.runs("history").length >= 2, 2000, "the results are read again");
        }

        function test_progress_events_move_the_bar() {
            const page = root.pageLoader.item;
            page.scanKind = "scan";
            page.scanState = { kind: "scan", label: "Scanning /x", percent: 60, stage: "clamav", done: false, result: null };
            tryVerify(() => root.showing("Scanning /x: clamav 60%") !== null);
            verify(root.named("cancel-scan") !== null, "a Cancel while it runs");
        }

        function test_a_clean_scan_says_so() {
            root.fakeCtx.events["scan-folder"] = root.cleanEvents();
            root.fakeCtx.commands["scan-folder"] = { code: 0, output: null };
            choose("/home/user/Downloads");
            root.press(root.named("scan-button"));
            tryVerify(() => root.named("verdict-scan") !== null);
            compare(root.named("verdict-scan").text, "No threats found.");
            compare(root.allNamed("quarantine-").length, 0);
        }

        function test_a_scanner_that_is_missing_is_not_a_clean_scan() {
            root.fakeCtx.events["scan-folder"] = [{ event: "result", findings: [], pack_errors: [{ pack: "clamav", error: "required pack missing: sudo apt install clamav" }], clean: false, state: "completed" }];
            root.fakeCtx.commands["scan-folder"] = { code: 5, error: "exit code 5", output: null };
            choose("/home/user/Downloads");
            root.press(root.named("scan-button"));
            tryVerify(() => root.named("verdict-scan") !== null);
            verify(root.named("verdict-scan").text.indexOf("clamav: required pack missing") >= 0);
        }

        function test_a_scan_already_running_is_said_in_words() {
            root.fakeCtx.events["scan-folder"] = [];
            root.fakeCtx.commands["scan-folder"] = { code: 3, error: "exit code 3", output: null };
            choose("/home/user/Downloads");
            root.press(root.named("scan-button"));
            tryVerify(() => root.named("verdict-scan") !== null);
            compare(root.named("verdict-scan").text, "Another scan is already running.");
        }

        function test_quarantining_a_finding_asks_with_a_plan_and_removes_it_from_the_list() {
            choose("/home/user/Downloads");
            root.press(root.named("scan-button"));
            tryVerify(() => root.named("quarantine-/home/user/Downloads/bad.exe") !== null);
            root.fakeCtx.confirms = false;
            root.press(root.named("quarantine-/home/user/Downloads/bad.exe"));
            tryVerify(() => root.runs("quarantine-add").length === 1);
            wait(50);
            verify(root.named("quarantine-/home/user/Downloads/bad.exe") !== null, "declining changes nothing");
            root.fakeCtx.confirms = true;
            root.press(root.named("quarantine-/home/user/Downloads/bad.exe"));
            tryVerify(() => root.runs("quarantine-add").length === 2);
            compare(root.runs("quarantine-add")[1][2], ["Win.Test.EICAR_HDB-1", "/home/user/Downloads/bad.exe"]);
            tryVerify(() => root.named("quarantine-/home/user/Downloads/bad.exe") === null);
            tryVerify(() => root.runs("quarantine-list").length >= 1, 2000, "the quarantine is read again");
        }

        function test_the_rootkit_check_asks_first_and_declining_runs_nothing() {
            root.fakeCtx.confirms = false;
            root.press(root.named("rootkit-button"));
            tryVerify(() => root.streams("rootkit-check").length === 1);
            wait(50);
            compare(root.named("verdict-rootkit"), null);
            verify(!root.pageLoader.item.streaming, "a declined sheet leaves the page idle");
            root.fakeCtx.confirms = true;
            root.press(root.named("rootkit-button"));
            tryVerify(() => root.named("verdict-rootkit") !== null);
            compare(root.named("verdict-rootkit").text, "No threats found.");
        }

        function test_only_one_thing_runs_at_a_time() {
            const page = root.pageLoader.item;
            page.streaming = true;
            verify(!root.named("rootkit-button").enabled);
            choose("/home/user/Downloads");
            verify(!root.named("scan-button").enabled);
            page.streaming = false;
        }
    }

    Component.onCompleted: root.tc = tc
}
