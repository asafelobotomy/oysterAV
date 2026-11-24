// What the page tests share: the Security page in a Loader, a fake ctx (FakeContext.qml) with an answer for every
// command (from fixtures/, which are what the real `oyst-cli` commands print), and helpers that find items by their
// text or objectName and act on them the way a person does: a switch flips (its `toggled` signal), a box is chosen
// (`activated`), a button is pressed (`clicked`), a field is typed in (`editingFinished`). The fake ctx logs every
// request in `fake.calls`. A test file is `PageHarness { id: root; TestCase { id: tc; ... } Component.onCompleted: root.tc = tc }`.
import QtQuick
import QtTest

Item {
    id: root
    width: 800
    height: 600

    /// The TestCase of the file that uses this harness (its verify and tryVerify).
    property var tc
    default property alias tests: holder.data
    readonly property alias fakeCtx: fake
    readonly property alias pageLoader: loader
    Item {
        id: holder
    }

    readonly property url pageUrl: Qt.resolvedUrl("../../uq/pages/oysterav-security/Page.qml")

    function fixture(name) {
        const x = new XMLHttpRequest();
        x.open("GET", Qt.resolvedUrl("fixtures/" + name), false);
        x.send();
        return JSON.parse(x.responseText);
    }

    function ok(output) {
        return { code: 0, output: output };
    }

    /// A summary of a protected computer, or with `extra` merged over the recorded one (a threat).
    function summary(extra) {
        return ok(Object.assign(fixture("summary.json"), extra || {}));
    }

    function protectedSummary() {
        return summary({ state: "ok", reasons: [], open_findings: 0, signature_age_hours: 5.4, signatures_stale: false });
    }

    /// `config show`; `changes` maps a key to its new value (the file then holds it).
    function config(changes) {
        const doc = fixture("config.json");
        for (const k in (changes || {}))
            doc.values[k] = changes[k];
        return ok(doc);
    }

    /// The events `scan` prints, then the exit code and result `ctx.command.stream` ends with.
    function threatEvents() {
        return [
            { event: "progress", stage: "Starting", percent: 0 },
            { event: "progress", stage: "clamav", percent: 0 },
            { event: "progress", stage: "clamav", percent: 60 },
            { event: "result", job_id: "j9", profile: "quick", paths: ["/home/user/Downloads"], findings: [{ pack: "clamav", path: "/home/user/Downloads/bad.exe", threat_name: "Win.Test.EICAR_HDB-1", severity: "high", quarantined: false, resolved: false }], pack_errors: [], clean: false, state: "completed" }
        ];
    }

    function cleanEvents() {
        return [
            { event: "progress", stage: "clamav", percent: 50 },
            { event: "result", job_id: "j8", profile: "quick", paths: ["/home/user/Downloads"], findings: [], pack_errors: [], clean: true, state: "completed" }
        ];
    }

    function answers() {
        return {
            summary: summary(),
            "setup-status": ok(Object.assign(fixture("setup-status.json"), { completed: true, needs_attention: false, missing_required: [], missing_signatures: false, helper_missing: false })),
            "setup-run": ok({ ok: true, completed: true, steps: [] }),
            "setup-run-basic": ok({ ok: true, completed: true, steps: [] }),
            job: ok(fixture("job.json")),
            history: ok(fixture("history.json")),
            "quarantine-list": ok(fixture("quarantine.json")),
            "quarantine-verify": { code: 0, output: fixture("quarantine-verify.json") },
            "schedule-status": ok(fixture("schedule.json")),
            services: ok(fixture("services.json")),
            signatures: ok(fixture("signatures.json")),
            doctor: ok(fixture("doctor.json")),
            helper: ok(fixture("helper.json")),
            audit: ok(fixture("audit.json")),
            config: config(),
            "preview-scan": ok(fixture("preview-scan.json")),
            "update-signatures": ok({ ok: true, message: "signatures are current" }),
            "scan-folder": { code: 1, error: "exit code 1", output: null },
            "rootkit-check": { code: 0, output: null },
            "scan-cancel": ok({ ok: true }),
            "quarantine-add": ok({ id: 2, sha256: "x" }),
            "quarantine-restore": ok({ ok: true, entry_id: 1, dest: "/home/user/Downloads/bad.exe" }),
            "quarantine-delete": ok({ ok: true, entry_id: 1 }),
            "quarantine-reconcile": ok({ ok: true, orphans: [], deleted: [] }),
            "schedule-enable": ok({ ok: true }),
            "schedule-disable": ok({ ok: true }),
            "schedule-frequency": ok({ ok: true, config: {} }),
            "schedule-time": ok({ ok: true, config: {} }),
            "schedule-weekday": ok({ ok: true, config: {} }),
            "schedule-profile": ok({ ok: true, config: {} }),
            "schedule-quarantine": ok({ ok: true, config: {} }),
            "schedule-run": ok({ exit_code: 0, scan: { findings: [] } }),
            "service-set": ok({ ok: true }),
            "config-set": ok({ ok: true, key: "k", value: "v" }),
            firewall: ok(fixture("firewall.json")),
            "fw-turn": ok({ ok: true, message: "The firewall is off." }),
            "fw-use": ok({ ok: true, message: "firewalld is the firewall now." }),
            "fw-policy": ok({ ok: true, message: "Outgoing connections: deny." }),
            "fw-rule-add": ok({ ok: true, message: "Rule added." }),
            "fw-rule-remove": ok({ ok: true, message: "Rule removed." }),
            "fw-rule-change": ok({ ok: true, message: "Rule changed." }),
            "fw-zone-port": ok({ ok: true, message: "8080/tcp is open in public." }),
            "fw-zone-service": ok({ ok: true, message: "ssh is closed in public." })
        };
    }

    FakeContext {
        id: fake
        commands: root.answers()
        confirmed: ["quarantine-add", "quarantine-restore", "quarantine-delete", "quarantine-reconcile", "service-set", "rootkit-check", "schedule-disable", "schedule-run", "setup-run", "setup-run-basic", "fw-turn", "fw-use", "fw-policy", "fw-rule-add", "fw-rule-remove", "fw-rule-change", "fw-zone-port", "fw-zone-service"]
        events: ({
            "scan-folder": root.threatEvents(),
            "rootkit-check": root.cleanEvents()
        })
    }

    Loader {
        id: loader
        anchors.fill: parent
    }

    function walk(item, visit) {
        visit(item);
        for (let i = 0; i < item.children.length; ++i)
            walk(item.children[i], visit);
    }

    /// The first visible item whose `text` (or `label`, `title`) is exactly `text`.
    function shown(text) {
        let hit = null;
        walk(loader.item, it => {
            if (!hit && it.visible && (it.text === text || it.label === text || it.title === text))
                hit = it;
        });
        return hit;
    }

    /// The first visible item whose `text` contains `part`.
    function showing(part) {
        let hit = null;
        walk(loader.item, it => {
            if (!hit && it.visible && typeof it.text === "string" && it.text.indexOf(part) >= 0)
                hit = it;
        });
        return hit;
    }

    function named(name) {
        let hit = null;
        walk(loader.item, it => {
            if (!hit && it.objectName === name && it.visible)
                hit = it;
        });
        return hit;
    }

    /// Every item with that objectName, shown or not.
    function allNamed(prefix) {
        const all = [];
        walk(loader.item, it => {
            if (typeof it.objectName === "string" && it.objectName.indexOf(prefix) === 0 && it.visible)
                all.push(it);
        });
        return all;
    }

    function everyText() {
        const all = [];
        walk(loader.item, it => {
            for (const k of ["text", "label", "title"])
                if (typeof it[k] === "string" && it[k] !== "")
                    all.push(it[k]);
        });
        return all;
    }

    function tab(title) {
        const button = root.named("tab-" + title);
        root.tc.verify(button !== null, "a tab called " + title);
        button.clicked();
    }

    function flip(sw) {
        sw.checked = !sw.checked;
        sw.toggled();
    }

    function choose(box, index) {
        box.currentIndex = index;
        box.activated(index);
    }

    function press(button) {
        root.tc.verify(button !== null, "a button to press");
        root.tc.verify(button.enabled, "the button is enabled");
        button.clicked();
    }

    function type(field, text) {
        field.text = text;
        field.editingFinished();
    }

    function runs(id) {
        return fake.calls.filter(c => c[0] === "run" && c[1] === id);
    }

    function streams(id) {
        return fake.calls.filter(c => c[0] === "stream" && c[1] === id);
    }

    function open() {
        loader.source = "";
        loader.source = root.pageUrl;
        root.tc.verify(loader.status === Loader.Ready, "the page loads");
        loader.item.ctx = fake.ctx;
    }

    /// Start every test from a freshly opened page whose first reads have been answered.
    function reset() {
        fake.calls = [];
        fake.watches = ({});
        fake.confirms = true;
        fake.commands = root.answers();
        fake.events = ({
            "scan-folder": root.threatEvents(),
            "rootkit-check": root.cleanEvents()
        });
        root.open();
        root.tc.tryVerify(() => loader.item.summary !== null && loader.item.prefs !== null);
    }
}
