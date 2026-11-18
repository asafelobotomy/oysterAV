// The Setup tab, and the other tabs staying away until first-time setup has been run.
import QtQuick
import QtTest

PageHarness {
    id: root

    TestCase {
        id: tc
        name: "Setup"
        when: windowShown

        function init() {
            root.reset();
        }

        function test_a_set_up_computer_keeps_every_tab() {
            tryVerify(() => root.named("tab-Setup") !== null);
            verify(root.named("tab-Overview") !== null);
            verify(root.named("tab-Scans") !== null);
        }

        function test_before_setup_only_the_setup_tab_is_there() {
            root.fakeCtx.commands.summary = root.summary({ setup_completed: false });
            root.fakeCtx.commands["setup-status"] = root.ok({ completed: false, needs_attention: true, missing_required: ["clamav"], missing_signatures: false, helper_missing: true, install_mismatch: false, skipped_steps: [] });
            root.open();
            tryVerify(() => root.pageLoader.item.setupNeeded);
            tryVerify(() => root.shown("Security isn't set up yet") !== null);
            tryVerify(() => root.showing("• First-time setup hasn't been run.") !== null);
            verify(root.showing("• Scanners to install: clamav") !== null);
            compare(root.named("tab-Scans"), null, "the other tabs wait");
            compare(root.named("tab-Quarantine"), null);
        }

        function test_running_setup_asks_first_then_opens_the_tabs() {
            root.fakeCtx.commands.summary = root.summary({ setup_completed: false });
            root.open();
            tryVerify(() => root.pageLoader.item.setupNeeded);
            tryVerify(() => root.named("setup-run") !== null);
            // what the run did: the status read afterwards says setup has been completed
            root.fakeCtx.commands.summary = root.summary({ setup_completed: true });
            root.press(root.named("setup-run"));
            tryVerify(() => root.runs("setup-run").length === 1);
            tryVerify(() => root.shown("Setup is complete.") !== null);
            tryVerify(() => root.runs("summary").length >= 2, 2000, "the status is read again");
            tryVerify(() => !root.pageLoader.item.setupNeeded);
        }

        function test_a_declined_confirmation_runs_nothing() {
            root.fakeCtx.commands.summary = root.summary({ setup_completed: false });
            root.open();
            tryVerify(() => root.named("setup-run-basic") !== null);
            root.fakeCtx.confirms = false;
            root.press(root.named("setup-run-basic"));
            wait(100);
            compare(root.pageLoader.item.noteFor("setup"), null);
            verify(root.pageLoader.item.setupNeeded);
        }

        function test_a_failed_step_is_named_and_setup_stays_open() {
            root.fakeCtx.commands.summary = root.summary({ setup_completed: false });
            root.fakeCtx.commands["setup-run"] = root.ok({ ok: false, completed: false, steps: [{ step: "packs", ok: false, message: "pacman failed" }] });
            root.open();
            tryVerify(() => root.named("setup-run") !== null);
            root.press(root.named("setup-run"));
            tryVerify(() => root.showing("Setup isn't finished") !== null);
            verify(root.showing("packs (pacman failed)") !== null);
            verify(root.pageLoader.item.setupNeeded);
        }

        function test_an_older_oyst_cli_that_does_not_say_never_locks_the_page() {
            const old = root.fixture("summary.json");
            delete old.setup_completed;
            root.fakeCtx.commands.summary = root.ok(old);
            root.open();
            tryVerify(() => root.pageLoader.item.summary !== null);
            verify(!root.pageLoader.item.setupNeeded);
            verify(root.named("tab-Scans") !== null);
        }
    }

    Component.onCompleted: root.tc = tc
}
