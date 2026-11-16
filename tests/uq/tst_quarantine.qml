// The Quarantine tab: the list, restore and delete behind their confirmation, and the vault check.
import QtQuick
import QtTest

PageHarness {
    id: root

    TestCase {
        id: tc
        name: "Quarantine"
        when: windowShown

        function init() {
            root.reset();
            root.tab("Quarantine");
            tryVerify(() => root.named("restore-1") !== null);
        }

        function test_lists_the_vault_when_the_tab_opens() {
            verify(root.shown("bad.exe · Win.Test.EICAR_HDB-1") !== null);
            verify(root.showing("/home/user/Downloads/bad.exe · 2026-11-16 09:30") !== null);
            tryVerify(() => root.named("vault-line") !== null);
            compare(root.named("vault-line").text, "The vault is consistent.");
            compare(root.runs("quarantine-list").length, 1);
            compare(root.runs("quarantine-verify").length, 1);
            compare(root.named("reconcile"), null, "nothing stray to delete");
        }

        function test_an_empty_vault_says_so() {
            root.fakeCtx.commands["quarantine-list"] = root.ok([]);
            root.press(root.shown("Refresh"));
            tryVerify(() => root.named("quarantine-empty") !== null);
        }

        function test_restore_asks_and_then_reads_again() {
            root.fakeCtx.confirms = false;
            root.press(root.named("restore-1"));
            tryVerify(() => root.runs("quarantine-restore").length === 1);
            wait(50);
            compare(root.runs("quarantine-list").length, 1, "declining reads nothing again");
            verify(root.shown("Restored.") === null);
            root.fakeCtx.confirms = true;
            root.press(root.named("restore-1"));
            tryVerify(() => root.shown("Restored.") !== null);
            compare(root.runs("quarantine-restore")[1][2], ["1"]);
            tryVerify(() => root.runs("quarantine-list").length === 2);
            tryVerify(() => root.runs("summary").length >= 2);
        }

        function test_delete_says_what_oysterAV_refused() {
            root.fakeCtx.commands["quarantine-delete"] = { code: 2, error: "exit code 2", output: { ok: false, entry_id: 1, error: "vault file missing for entry 1" } };
            root.press(root.named("delete-1"));
            tryVerify(() => root.shown("vault file missing for entry 1") !== null);
            verify(root.named("delete-1") !== null, "the row is still there");
        }

        function test_delete_for_good() {
            root.press(root.named("delete-1"));
            tryVerify(() => root.shown("Deleted.") !== null);
            compare(root.runs("quarantine-delete")[0][2], ["1"]);
        }

        function test_stray_files_can_be_deleted_after_a_plan() {
            root.fakeCtx.commands["quarantine-verify"] = { code: 1, error: "exit code 1", output: { invalid_entries: [], orphans: ["/x/a.bin"], orphan_count: 1, ok: false } };
            root.press(root.shown("Check again"));
            tryVerify(() => root.named("reconcile") !== null);
            compare(root.named("vault-line").text, "1 stray file belongs to no entry.");
            root.press(root.named("reconcile"));
            tryVerify(() => root.shown("Deleted the stray files.") !== null);
            compare(root.runs("quarantine-reconcile").length, 1);
        }

        function test_a_failed_read_keeps_the_tab() {
            root.fakeCtx.commands["quarantine-list"] = { code: 2, error: "exit code 2: vault must be mode 0700", output: null };
            root.press(root.shown("Refresh"));
            tryVerify(() => root.shown("Couldn't read the quarantine") !== null);
            verify(root.showing("vault must be mode 0700") !== null);
        }
    }

    Component.onCompleted: root.tc = tc
}
