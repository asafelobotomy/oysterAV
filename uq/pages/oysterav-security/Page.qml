// oysterAV's "Security" page in uQ Settings, laid out like Settings' own pages (uq_api = 3): seven tabs of
// cards. Everything runs through the commands declared in page.toml (oyst-cli as the user); what needs
// root (the rootkit check, a service on or off) asks for a password through oysterAV's own polkit helper.
// All text goes through org.uq.settings components (plain text). Parsing and the rules for what may be
// sent live in logic.js; the tabs are the *Tab.qml files beside this one.
import QtQuick
import QtQuick.Controls as QQC2
import QtQuick.Layouts
import org.uq.settings
import "logic.js" as Logic

SettingsPage {
    id: page

    property var ctx
    property var theme
    /// The [[setting]] row Settings search jumped to; the rows flash, and their tab opens.
    property string highlight

    // What oyst-cli last printed, parsed (Logic.parse*). null until the read has answered.
    property var summary: null
    property var setup: null
    property var job: ({ active: false, percent: 0, pack: "", message: "", jobId: "" })
    property var history: null
    property var quarantine: null
    property var verify: null
    property var schedule: null
    property var services: null
    property var signatures: null
    property var doctor: null
    property var helper: null
    property var audit: null
    property var prefs: null
    /// Counts the times the preferences were read again after a write: a field then shows what is saved.
    property int prefsRev: 0

    /// What each write said, by row key: {message, failed}. Shown under the row.
    property var notes: ({})
    /// The key of the write that is running ("" = none). One write at a time.
    property string workingKey: ""
    readonly property bool busy: page.workingKey !== "" || page.streaming

    /// A scan this page started: its kind ("scan" or "rootkit"), its streamed state and what it found.
    property string scanKind: ""
    property var scanState: null
    property var scanOutcome: null
    property bool streaming: false
    /// The plan line shown under the folder choice ("1,204 files, 1 scanner(s)").
    property string folderPlan: ""
    property bool alive: true
    property var openedWith: null
    property string openProblem: ""

    pageId: "oysterav-security"

    function colorOf(name, fallback) {
        const c = page.ctx && page.ctx.theme ? page.ctx.theme.colors : null;
        return (c && c[name]) || fallback;
    }

    function errorColor() {
        return page.colorOf("error", "red");
    }

    function mutedColor() {
        return page.colorOf("text_muted", "gray");
    }

    function successColor() {
        return page.colorOf("success", "green");
    }

    function warningColor() {
        return page.colorOf("warning", "orange");
    }

    function noteFor(key) {
        return page.notes[key] || null;
    }

    function setNote(key, note) {
        page.notes = Logic.withNote(page.notes, key, note);
    }

    /// Wraps a callback so an answer that arrives after the page is gone is ignored.
    function guard(callback) {
        return result => {
            if (page.alive)
                callback(result);
        };
    }

    /// Reads `command` and keeps what Logic's `parse` makes of it in the property `name`.
    function load(name, command, parse) {
        if (!page.ctx)
            return;
        page.ctx.command.run(command, [], page.guard(result => {
            page[name] = parse(result);
        }));
    }

    /// First-time setup hasn't been run: the other tabs stay hidden until it has.
    readonly property bool setupNeeded: page.summary !== null && page.summary.ok && !page.summary.setupDone

    // The tab shown can be one that has just gone: land on Setup while it is needed, Overview once it is done.
    onSetupNeededChanged: page.show(page.setupNeeded ? setupTab : overview)

    function loadSetup() {
        page.load("setup", "setup-status", Logic.parseSetup);
    }

    function loadSummary() {
        page.load("summary", "summary", Logic.parseSummary);
    }

    function loadHistory() {
        page.load("history", "history", Logic.parseHistory);
    }

    function loadQuarantine() {
        page.load("quarantine", "quarantine-list", Logic.parseQuarantine);
    }

    function loadVerify() {
        page.load("verify", "quarantine-verify", Logic.parseVerify);
    }

    function loadSchedule() {
        page.load("schedule", "schedule-status", Logic.parseSchedule);
    }

    function loadServices() {
        page.load("services", "services", Logic.parseServices);
    }

    function loadSystem() {
        page.load("doctor", "doctor", Logic.parseDoctor);
        page.load("helper", "helper", Logic.parseHelper);
        page.load("audit", "audit", Logic.parseAudit);
    }

    function loadSignatures() {
        page.load("signatures", "signatures", r => Logic.envelope(r));
    }

    /// Everything a finished scan or a change may have moved.
    function reloadAll() {
        page.loadSummary();
        page.loadHistory();
        page.loadQuarantine();
    }

    /// Runs one write (a command that changes something) for the row `key`, then `done(result)` unless the
    /// person cancelled. A cancel changes nothing and shows nothing. `doing` words a success (text, or a function of the result).
    function write(key, command, args, done, doing) {
        if (page.busy || !page.ctx)
            return false;
        const why = Logic.argsProblem(command, args);
        if (why !== "") {
            page.setNote(key, { message: why, failed: true });
            return false;
        }
        page.setNote(key, null);
        page.workingKey = key;
        page.ctx.command.run(command, args, page.guard(result => {
            page.workingKey = "";
            if (Logic.isCancelled(result))
                return;
            page.setNote(key, typeof doing === "function" ? doing(result) : Logic.outcome(result, doing));
            if (done)
                done(result);
        }));
        return true;
    }

    /// Starts a scan that streams its progress. `kind` says which card shows it.
    function startScan(kind, label, command, args) {
        if (page.busy || !page.ctx)
            return;
        const why = Logic.argsProblem(command, args);
        if (why !== "") {
            page.scanKind = kind;
            page.scanState = null;
            page.scanOutcome = { message: why, failed: true, threats: [] };
            return;
        }
        page.scanKind = kind;
        page.scanOutcome = null;
        page.scanState = Logic.startScan(kind, label);
        page.streaming = true;
        page.ctx.command.stream(command, args, page.guard(ev => {
            page.scanState = Logic.reduceScan(page.scanState, ev);
        }), page.guard(done => {
            page.streaming = false;
            const outcome = Logic.scanOutcome(page.scanState, done);
            if (outcome === null) {
                // Declined at the confirmation sheet: nothing ran.
                page.scanState = null;
                page.scanKind = "";
                return;
            }
            page.scanOutcome = outcome;
            page.reloadAll();
        }));
    }

    function scanFolder(profile, folder) {
        page.startScan("scan", "Scanning " + folder, "scan-folder", Logic.scanArgs(profile, folder));
    }

    function checkRootkits() {
        page.startScan("rootkit", "Rootkit check", "rootkit-check", []);
    }

    function cancelScan() {
        page.write("cancel", "scan-cancel", [], () => page.loadJob(), "Asked the scan to stop. It stops between scanners.");
    }

    /// Moves a finding to the quarantine vault; the plan sheet shows what moves first.
    function quarantineFinding(finding) {
        page.write("q:" + finding.path, "quarantine-add", [finding.threat, finding.path], () => {
            if (page.scanOutcome)
                page.scanOutcome = Object.assign({}, page.scanOutcome, {
                    threats: page.scanOutcome.threats.filter(t => t.path !== finding.path)
                });
            page.loadQuarantine();
            page.loadSummary();
        }, "Moved to quarantine.");
    }

    /// Counts what a scan of `folder` would look at (the `--dry-run` plan), for the line under the choice.
    function previewFolder(profile, folder) {
        page.folderPlan = "";
        if (folder === "" || !page.ctx)
            return;
        const why = Logic.argsProblem("preview-scan", Logic.scanArgs(profile, folder));
        if (why !== "") {
            page.folderPlan = why;
            return;
        }
        page.ctx.command.run("preview-scan", Logic.scanArgs(profile, folder), page.guard(result => {
            page.folderPlan = Logic.planLine(result);
        }));
    }

    function loadJob() {
        if (!page.ctx)
            return;
        page.ctx.command.run("job", [], page.guard(result => {
            const was = page.job.active;
            page.job = Logic.parseJob(result);
            // A scan that ended somewhere else (oysterAV, the timer): what it found is news here too.
            if (was && !page.job.active && !page.streaming)
                page.reloadAll();
        }));
    }

    function change(key, command, args, doing, done) {
        page.write(key, command, args, result => {
            if (done)
                done(result);
        }, doing);
    }

    function pref(key) {
        return page.prefs && page.prefs.ok ? (page.prefs.byKey[key] || null) : null;
    }

    /// Writes one preference; oysterAV checks the value and says why it refused. The file is followed, so
    /// the row shows what was written once it is.
    function setPref(key, value) {
        return page.write("pref:" + key, "config-set", [key, value], () => page.ctx.command.run("config", [], page.guard(r => {
            page.prefs = Logic.parseConfig(r);
            page.prefsRev++;
        })), "Saved.");
    }

    function showScans() {
        page.show(scans);
    }

    function openApp() {
        page.openProblem = "";
        page.ctx.openApp(Logic.APP_ID, page.guard(result => {
            if (result && result.error !== undefined)
                page.openProblem = "Couldn't open oysterAV.";
        }));
    }

    onCtxChanged: {
        if (page.ctx && page.ctx !== page.openedWith) {
            page.openedWith = page.ctx;
            page.loadSummary();
            page.loadSetup();
            page.loadJob();
            page.ctx.command.watch("config", page.guard(r => {
                page.prefs = Logic.parseConfig(r);
            }));
        }
    }
    Component.onDestruction: page.alive = false

    // A scan started from anywhere shows its progress here, and ends by itself.
    Timer {
        interval: 3000
        repeat: true
        running: page.ctx !== null && page.ctx !== undefined && page.visible && !page.streaming
        onTriggered: page.loadJob()
    }

    headerItems: [
        QQC2.Button {
            text: "Open oysterAV"
            icon.name: "security-high"
            onClicked: page.openApp()
        }
    ]

    banners: [
        ErrorCard {
            visible: page.summary !== null && !page.summary.ok
            title: "Couldn't read oysterAV's status"
            detail: page.summary ? page.summary.problem : ""
            Layout.fillWidth: true
        },
        ErrorCard {
            visible: page.openProblem !== ""
            title: page.openProblem
            detail: "Start oysterAV from your app launcher."
            Layout.fillWidth: true
        }
    ]

    OverviewTab {
        id: overview
        host: page
        available: !page.setupNeeded
    }

    SetupTab {
        id: setupTab
        host: page
    }

    ScansTab {
        id: scans
        host: page
        available: !page.setupNeeded
    }

    QuarantineTab {
        host: page
        available: !page.setupNeeded
    }

    ScheduleTab {
        host: page
        available: !page.setupNeeded
    }

    ProtectionTab {
        host: page
        available: !page.setupNeeded
    }

    PreferencesTab {
        host: page
        available: !page.setupNeeded
    }

    SystemTab {
        host: page
        available: !page.setupNeeded
    }
}
