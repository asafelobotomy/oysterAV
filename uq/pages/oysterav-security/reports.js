.pragma library
.import "logic.js" as Logic

// What oysterAV reports about the past and the machine: scan history, the quarantine, the
// schedule, its services, the system check (scanners, helper, audit) and preferences. No Qt
// calls, so Node can test it (tests/uq/logic.test.mjs). Shared helpers and the command
// patterns are in logic.js.

var MAX_ROWS = Logic.MAX_ROWS;
var PROFILE_LABELS = Logic.PROFILE_LABELS;
var FREQUENCIES = Logic.FREQUENCIES;
var WEEKDAYS = Logic.WEEKDAYS;
var SCHEDULE_PROFILES = Logic.SCHEDULE_PROFILES;
var QUARANTINE_MODES = Logic.QUARANTINE_MODES;
var SERVICES = Logic.SERVICES;
var clip = Logic.clip;
var isObject = Logic.isObject;
var plural = Logic.plural;
var envelope = Logic.envelope;
var stamp = Logic.stamp;
var findings = Logic.findings;

// ---- History ----------------------------------------------------------------------------------------------

function parseHistory(result) {
    var env = envelope(result);
    if (!env.ok || !Array.isArray(env.output))
        return { ok: false, problem: env.ok ? "oysterAV printed no history." : env.error, rows: [] };
    var rows = env.output.slice(0, MAX_ROWS).filter(isObject).map(function (r) {
        var n = Number(r.open_findings_count !== undefined ? r.open_findings_count : r.findings_count) || 0;
        var paths = Array.isArray(r.paths) ? r.paths.map(clip).join(", ") : "";
        var label = PROFILE_LABELS[r.profile] || clip(r.profile || "Scan");
        return {
            id: clip(r.job_id || ""),
            when: stamp(r.started_at),
            title: label,
            detail: paths,
            outcome: n > 0 ? plural(n, "threat", "threats") + " found" : (r.state === "cancelled" ? "Cancelled" : (r.clean === false ? "Finished with errors" : "Clean")),
            threat: n > 0,
            problem: n === 0 && (r.clean === false || r.state === "failed")
        };
    });
    return { ok: true, problem: "", rows: rows };
}

// ---- Quarantine --------------------------------------------------------------------------------------------

function baseName(path) {
    var parts = String(path).split("/");
    return parts[parts.length - 1] || String(path);
}

function parseQuarantine(result) {
    var env = envelope(result);
    if (!env.ok || !Array.isArray(env.output))
        return { ok: false, problem: env.ok ? "oysterAV printed no list." : env.error, rows: [] };
    var rows = env.output.slice(0, MAX_ROWS).filter(isObject).map(function (e) {
        return {
            id: String(Math.floor(Number(e.id) || 0)),
            name: clip(baseName(e.original_path || "")),
            path: clip(e.original_path || ""),
            threat: clip(e.threat_name || "unknown threat"),
            when: stamp(e.quarantined_at)
        };
    }).filter(function (r) { return r.id !== "0"; });
    return { ok: true, problem: "", rows: rows };
}

/// `quarantine verify --json`: a line saying whether the vault is consistent.
function parseVerify(result) {
    // `verify` prints {ok: false, ...} when the vault is not consistent: that is its answer, not a refusal.
    var out = result && isObject(result.output) ? result.output : null;
    if (out === null || !Array.isArray(out.invalid_entries)) {
        var env = envelope(result);
        return { ok: false, problem: env.ok ? "No answer." : env.error, orphans: 0, invalid: 0, clean: false, text: "" };
    }
    var o = Number(out.orphan_count) || 0;
    var bad = out.invalid_entries.length;
    var text = o === 0 && bad === 0 ? "The vault is consistent." : (bad > 0 ? plural(bad, "entry", "entries") + (bad === 1 ? " no longer matches its file. " : " no longer match their files. ") : "") + (o > 0 ? plural(o, "stray file", "stray files") + (o === 1 ? " belongs to no entry." : " belong to no entry.") : "");
    return { ok: true, problem: "", orphans: o, invalid: bad, clean: o === 0 && bad === 0, text: text.trim() };
}

// ---- Schedule -----------------------------------------------------------------------------------------------

function parseSchedule(result) {
    var env = envelope(result);
    if (!env.ok || !isObject(env.output) || !isObject(env.output.config))
        return { ok: false, problem: env.ok ? "oysterAV printed no schedule." : env.error };
    var d = env.output;
    var c = d.config;
    var linger = isObject(d.linger) ? d.linger : {};
    return {
        ok: true,
        problem: "",
        enabled: d.enabled === true,
        installed: d.installed === true,
        frequency: FREQUENCIES.indexOf(c.frequency) >= 0 ? c.frequency : "custom",
        time: clip(c.time || "02:00"),
        weekday: WEEKDAYS.indexOf(c.weekday) >= 0 ? c.weekday : "mon",
        profile: SCHEDULE_PROFILES.indexOf(c.profile) >= 0 ? c.profile : "quick",
        quarantine: QUARANTINE_MODES.indexOf(c.quarantine) >= 0 ? c.quarantine : "auto",
        next: clip(d.next || ""),
        lingerOff: linger.available === true && linger.linger === false,
        calendarError: clip(d.calendar_error || "")
    };
}

function scheduleLine(s) {
    if (!s.ok)
        return "";
    if (!s.enabled)
        return "Scheduled scans are off.";
    return s.next !== "" ? "Next scan: " + s.next + "." : "Scheduled scans are on.";
}

/// What `schedule run --json` said: it exits 1 when the scan found threats, with the scan inside.
function scheduleRunOutcome(result) {
    var env = envelope(result);
    if (env.cancelled)
        return null;
    var out = result && isObject(result.output) ? result.output : null;
    if (out && isObject(out.scan)) {
        var open = findings(out.scan).filter(function (f) { return !f.quarantined && !f.resolved; });
        return { message: open.length === 0 ? "The scan finished. No threats found." : "The scan found " + plural(open.length, "threat", "threats") + ". See Scans.", failed: open.length > 0 };
    }
    return env.ok ? { message: "The scan finished.", failed: false } : { message: env.error, failed: true };
}

// ---- Services -----------------------------------------------------------------------------------------------

/// `services status --json` as one row per service, in SERVICES order.
function parseServices(result) {
    var env = envelope(result);
    if (!env.ok || !isObject(env.output) || !isObject(env.output.services))
        return { ok: false, problem: env.ok ? "oysterAV printed no services." : env.error, rows: [] };
    var table = env.output.services;
    var rows = SERVICES.filter(function (s) { return isObject(table[s.name]); }).map(function (s) {
        var d = table[s.name];
        var installed = !(isObject(d.details) && d.details.installed === false);
        return {
            name: s.name,
            label: s.label,
            help: s.help,
            running: d.running === true,
            enabled: d.enabled === true,
            installed: installed,
            text: !installed ? "Not installed" : (d.running === true ? "Running" : "Off") + (d.enabled === true ? ", starts at boot" : "")
        };
    });
    return { ok: true, problem: "", rows: rows };
}

// ---- System: scanners, helper, audit ---------------------------------------------------------------------

function parseDoctor(result) {
    var env = envelope(result);
    if (!Array.isArray(env.output))
        return { ok: false, problem: env.ok ? "oysterAV printed no scanner list." : env.error, rows: [] };
    var rows = env.output.slice(0, MAX_ROWS).filter(isObject).map(function (p) {
        var installed = p.installed === true;
        var tier = p.tier === "required" ? "Needed" : (p.tier === "recommended" ? "Recommended" : "Optional");
        var version = installed && p.version ? clip(p.version) : "";
        return {
            name: clip(p.name || ""),
            tier: tier,
            installed: installed,
            ok: installed && p.version_ok !== false,
            text: installed ? (p.version_ok === false ? "Too old" + (version ? " (" + version + ")" : "") : "Installed" + (version ? " " + version : "")) : "Missing",
            hint: !installed ? clip(p.install_hint || "") : ""
        };
    });
    return { ok: true, problem: "", rows: rows };
}

function parseHelper(result) {
    var env = envelope(result);
    if (!env.ok || !isObject(env.output))
        return { ok: false, problem: env.ok ? "No answer." : env.error, installed: false, current: false, text: "" };
    var d = env.output;
    var installed = d.installed === true;
    var current = d.policy_current === true;
    var text = !installed ? "oysterAV's helper isn't installed, so rootkit checks and service changes can't ask for your password." : (current ? "The helper is installed and up to date." : "The helper is installed but out of date. Reinstall it from oysterAV.");
    return { ok: true, problem: "", installed: installed, current: current, text: text };
}

function parseAudit(result) {
    var env = envelope(result);
    if (!env.ok || !Array.isArray(env.output))
        return { ok: false, problem: env.ok ? "oysterAV printed no audit log." : env.error, rows: [] };
    var rows = env.output.slice(0, MAX_ROWS).filter(isObject).map(function (r) {
        return { when: stamp(r.ts), title: clip((r.kind || "") + ": " + (r.action || "")), failed: r.success === false || r.success === 0 };
    });
    return { ok: true, problem: "", rows: rows };
}

var HARDENING_STATES = { ok: "On", warn: "Weak", info: "Off", unknown: "Can't tell" };

/// `oyst-cli status hardening --json`: one row per check (title, state word, why, how to fix).
function parseHardening(result) {
    var env = envelope(result);
    if (!env.ok || !isObject(env.output) || !Array.isArray(env.output.checks))
        return { ok: false, problem: env.ok ? "oysterAV printed no hardening checks." : env.error, rows: [], summary: "" };
    var rows = env.output.checks.slice(0, MAX_ROWS).filter(isObject).map(function (c) {
        var state = HARDENING_STATES[c.state] ? c.state : "unknown";
        return { title: clip(c.title || ""), group: clip(c.group || ""), state: state, text: HARDENING_STATES[state], detail: clip(c.detail || ""), fix: clip(c.fix || "") };
    });
    var counts = isObject(env.output.counts) ? env.output.counts : {};
    var weak = Number(counts.warn) || 0;
    var summary = (Number(counts.ok) || 0) + " of " + rows.length + " checks pass" + (weak > 0 ? ", " + plural(weak, "needs", "need") + " attention" : "") + ".";
    var fixes = Array.isArray(env.output.sysctl_fixes) ? env.output.sysctl_fixes.length : 0;
    return { ok: true, problem: "", rows: rows, summary: summary, canHarden: fixes > 0, canUndo: env.output.hardened_by_oysterav === true };
}

// ---- Preferences --------------------------------------------------------------------------------------------------

/// `config show --json`: the preference groups, each with its rows (key, label, kind, choices, value).
function parseConfig(result) {
    var env = envelope(result);
    if (!env.ok || !isObject(env.output) || !Array.isArray(env.output.schema) || !isObject(env.output.values))
        return { ok: false, problem: env.ok ? "oysterAV printed no preferences." : env.error, groups: [], byKey: ({}) };
    var values = env.output.values;
    var order = [];
    var groups = {};
    var byKey = {};
    env.output.schema.slice(0, 100).filter(isObject).forEach(function (s) {
        if (typeof s.key !== "string" || values[s.key] === undefined)
            return;
        var row = {
            key: s.key,
            group: clip(s.group || "Other"),
            label: clip(s.label || s.key),
            help: clip(s.help || ""),
            kind: ["bool", "choice", "int", "text", "list"].indexOf(s.kind) >= 0 ? s.kind : "text",
            choices: Array.isArray(s.choices) ? s.choices.map(String) : [],
            min: typeof s.min === "number" ? s.min : undefined,
            value: values[s.key]
        };
        byKey[row.key] = row;
        if (!groups[row.group]) {
            groups[row.group] = [];
            order.push(row.group);
        }
        groups[row.group].push(row);
    });
    return { ok: true, problem: "", path: clip(env.output.path || ""), groups: order.map(function (g) { return { title: g, rows: groups[g] }; }), byKey: byKey };
}

var GROUP_ICONS = { Scanning: "system-search", Quarantine: "security-medium", Protection: "security-high", Updates: "system-software-update", "System scans": "utilities-system-monitor", "Security news": "internet-news-reader", App: "preferences-system" };

function groupIcon(title) {
    return GROUP_ICONS[title] || "configure";
}

/// The text a row shows for its value: a list is comma-separated, a choice is its text.
function prefText(row) {
    if (!row || row.value === null || row.value === undefined)
        return "";
    if (Array.isArray(row.value))
        return row.value.join(", ");
    return String(row.value);
}

/// The value `config set` takes for what the person typed or chose; "" for an empty list.
function prefValue(row, text) {
    if (row.kind === "bool")
        return text === true || text === "true" ? "true" : "false";
    if (row.kind === "list")
        return String(text).split(",").map(function (p) { return p.trim(); }).filter(function (p) { return p !== ""; }).join(",");
    return String(text).trim();
}

/// A sentence for a number the field wouldn't take, "" when it is fine (oysterAV checks the rest).
function prefProblem(row, text) {
    if (row.kind !== "int")
        return "";
    var t = String(text).trim();
    if (!/^[0-9]{1,9}$/.test(t))
        return row.label + " must be a whole number.";
    if (typeof row.min === "number" && Number(t) < row.min)
        return row.label + " must be at least " + row.min + ".";
    return "";
}
