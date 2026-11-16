// The Overview tab, the banners and the states a read can be in.
import QtQuick
import QtTest

PageHarness {
    id: root

    TestCase {
        id: tc
        name: "Overview"
        when: windowShown

        function init() {
            root.reset();
        }

        function test_shows_the_threat_and_why() {
            const page = root.pageLoader.item;
            tryVerify(() => root.shown("Threat found") !== null);
            verify(root.showing("• 1 unresolved finding in the last scan") !== null);
            verify(root.showing("Last scan 2026-11-16 09:30. Signatures: missing. 1 file in quarantine.") !== null);
            compare(page.summary.state, "threat");
            // the first reads of an opened page: status, the job, and the followed config only
            compare(root.runs("summary").length, 1);
            compare(root.runs("job").length, 1);
            verify(root.fakeCtx.calls.some(c => c[0] === "watch" && c[1] === "config"));
            compare(root.runs("quarantine-list").length, 0, "tabs that aren't open aren't read");
            compare(root.runs("doctor").length, 0);
        }

        function test_a_protected_computer() {
            root.fakeCtx.commands.summary = root.protectedSummary();
            root.open();
            tryVerify(() => root.shown("Protected") !== null);
            compare(root.showing("• "), null, "no reasons to list");
            verify(root.showing("Signatures: 5 hours old") !== null);
        }

        function test_a_failed_read_says_so_and_keeps_the_page() {
            root.fakeCtx.commands.summary = { code: 127, error: "exit code 127: oyst-cli: command not found", output: null };
            root.open();
            tryVerify(() => root.shown("Couldn't read oysterAV's status") !== null);
            verify(root.showing("command not found") !== null);
            verify(root.shown("Status unavailable") !== null);
            verify(root.named("tab-Scans") !== null, "the tabs are still there");
        }

        function test_loading_shows_a_bar_not_a_word() {
            root.open();
            // answers come later (as in Settings): until then the status says nothing, and a bar moves
            const bars = [];
            root.walk(root.pageLoader.item, it => {
                if (it.visible && it.indeterminate === true)
                    bars.push(it);
            });
            verify(bars.length > 0, "an indeterminate bar while the status is read");
            verify(root.shown("Checking…") === null, "no bare Checking…");
            tryVerify(() => root.shown("Threat found") !== null);
            let left = 0;
            root.walk(root.pageLoader.item, it => {
                if (it.visible && it.indeterminate === true)
                    left++;
            });
            compare(left, 0, "the bar is gone once the status is in");
        }

        function test_update_signatures() {
            tryVerify(() => root.named("update-signatures") !== null);
            root.press(root.named("update-signatures"));
            tryVerify(() => root.runs("update-signatures").length === 1);
            tryVerify(() => root.shown("Signatures updated.") !== null);
            tryVerify(() => root.runs("summary").length === 2, 2000, "the status is read again");
        }

        function test_a_failed_signature_update_shows_oysterAVs_words() {
            root.fakeCtx.commands["update-signatures"] = { code: 2, error: "exit code 2", output: { ok: false, message: "freshclam is not installed" } };
            tryVerify(() => root.named("update-signatures") !== null);
            root.press(root.named("update-signatures"));
            tryVerify(() => root.shown("freshclam is not installed") !== null);
        }

        function test_a_scan_running_elsewhere_shows_progress_and_can_be_cancelled() {
            root.fakeCtx.commands.job = root.ok({ active: true, job_id: "j", pack: "clamav", message: "Scanning ~/Downloads", percent: 42, started_at: "2026-11-16T10:00:00", state: "running" });
            root.pageLoader.item.loadJob();
            tryVerify(() => root.shown("A scan is running") !== null);
            verify(root.showing("clamav: Scanning ~/Downloads") !== null);
            root.press(root.named("cancel-job"));
            tryVerify(() => root.runs("scan-cancel").length === 1);
            // the scan ended meanwhile: its result is news
            root.fakeCtx.commands.job = root.ok({ active: false, job_id: null, pack: "", message: "", percent: 0 });
            const before = root.runs("summary").length;
            root.pageLoader.item.loadJob();
            tryVerify(() => root.runs("summary").length > before);
            verify(root.shown("A scan is running") === null);
        }

        function test_open_oysterav() {
            const open = root.shown("Open oysterAV");
            verify(open !== null);
            open.clicked();
            tryVerify(() => root.fakeCtx.calls.some(c => c[0] === "openApp" && c[1] === "io.github.asafelobotomy.OysterAV.desktop"));
        }
    }

    Component.onCompleted: root.tc = tc
}
