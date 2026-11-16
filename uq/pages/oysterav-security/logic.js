.pragma library
// What the Security page knows that isn't layout: reading what `oyst-cli` prints, wording what
// it says, and checking what the page may send. No Qt calls, so Node can test it
// (tests/uq/logic.test.mjs). Text from scanners (file names, threat names) is only ever shown as
// plain text and cut to length.

var MAX_ROWS = 200;
var MAX_TEXT = 300;
var WORKING = "Working…";
var APP_ID = "io.github.asafelobotomy.OysterAV.desktop";

var PROFILES = ["quick", "full"];
var PROFILE_LABELS = { quick: "Quick (ClamAV)", full: "Full (ClamAV and maldet)", integrity: "Rootkit check", suite: "Everything" };
var FREQUENCIES = ["hourly", "daily", "weekly"];
var WEEKDAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
var WEEKDAY_LABELS = { mon: "Monday", tue: "Tuesday", wed: "Wednesday", thu: "Thursday", fri: "Friday", sat: "Saturday", sun: "Sunday" };
var SCHEDULE_PROFILES = ["quick", "full", "integrity", "suite"];
var QUARANTINE_MODES = ["auto", "on", "off"];
var QUARANTINE_LABELS = { auto: "As in preferences", on: "Always", off: "Never" };

// What each service is for, in the order the Protection tab lists them.
var SERVICES = [
    { name: "clamd", label: "ClamAV daemon", help: "Keeps the signatures loaded, so scans start at once." },
    { name: "clamonacc", label: "On-access scanning", help: "Scans a file when it is opened, in the folders set under Preferences." },
    { name: "freshclam-timer", label: "Signature updates", help: "Fetches new virus signatures in the background." },
    { name: "maldet-monitor", label: "Linux Malware Detect monitor", help: "Watches for new files with maldet." },
    { name: "fail2ban", label: "Fail2ban", help: "Blocks addresses that keep failing to log in." },
    { name: "schedule-linger", label: "Scans while logged out", help: "Lets scheduled scans run when you aren't signed in." }
];

// The patterns of page.toml, so a bad value is refused here with a sentence instead of by uQ with a
// code. tests/uq/logic.test.mjs checks they are the same.
var FOLDER = "^/[^\\x00-\\x1f\\x7f]*$";
var ENTRY = "^[1-9][0-9]{0,8}$";
var THREAT = "^[A-Za-z0-9][A-Za-z0-9._:/+() -]{0,199}$";
var SERVICE = "^(clamd|clamonacc|freshclam-timer|fail2ban|maldet-monitor|schedule-linger)$";
var PATTERNS = {
    "scan-folder": ["^(quick|full)$", FOLDER],
    "preview-scan": ["^(quick|full)$", FOLDER],
    "quarantine-add": [THREAT, FOLDER],
    "preview-quarantine-add": [THREAT, FOLDER],
    "quarantine-restore": [ENTRY],
    "quarantine-delete": [ENTRY],
    "preview-restore": [ENTRY],
    "preview-delete": [ENTRY],
    "service-set": [SERVICE, "^(on|off)$"],
    "preview-service": [SERVICE, "^(on|off)$"],
    "schedule-frequency": ["^(hourly|daily|weekly)$"],
    "schedule-time": ["^([01][0-9]|2[0-3]):[0-5][0-9]$"],
    "schedule-weekday": ["^(mon|tue|wed|thu|fri|sat|sun)$"],
    "schedule-profile": ["^(quick|full|integrity|suite)$"],
    "schedule-quarantine": ["^(auto|on|off)$"],
    "config-set": ["^(scan|clamav|quarantine|clamonacc|maldet_monitor|runtime|fangfrisch|rkhunter|lynis|ui)\\.[a-z_]{1,40}$", "^[^\\x00-\\x1f\\x7f]{0,600}$"]
};

function clip(value) {
    var text = String(value === undefined || value === null ? "" : value);
    return text.length > MAX_TEXT ? text.slice(0, MAX_TEXT - 1) + "…" : text;
}

function isObject(v) {
    return v !== null && typeof v === "object" && !Array.isArray(v);
}

function plural(n, one, many) {
    return n + " " + (n === 1 ? one : many);
}

function isCancelled(result) {
    return !!result && result.cancelled === true;
}

/// Why `args` can't be sent to `command` ("" when they can), by the patterns of page.toml.
function argsProblem(command, args) {
    var patterns = PATTERNS[command];
    if (!patterns)
        return args.length === 0 ? "" : "That doesn't take arguments.";
    if (args.length !== patterns.length)
        return "That needs " + patterns.length + " value(s).";
    for (var i = 0; i < patterns.length; ++i) {
        var text = String(args[i]);
        if (text.charAt(0) === "-" || text.indexOf("\0") >= 0 || !new RegExp(patterns[i]).test(text))
            return "That value isn't allowed here.";
    }
    return "";
}

/// What a command answered, whatever its exit code: {ok, cancelled, error, output}. oyst-cli prints
/// {ok: false, error} for a refusal, so its words are kept; `scan` exits 1 with a full result when it
/// finds threats, which is not a failure of the command.
function envelope(result) {
    if (!isObject(result))
        return { ok: false, cancelled: false, error: "No answer.", output: null };
    if (result.cancelled === true)
        return { ok: false, cancelled: true, error: "Cancelled", output: null };
    var out = result.output === undefined ? null : result.output;
    if (isObject(out) && out.ok === false)
        return { ok: false, cancelled: false, error: clip(out.error || out.message || result.error || "oysterAV refused."), output: out };
    if (result.error)
        return { ok: false, cancelled: false, error: clip(result.error), output: out };
    return { ok: true, cancelled: false, error: "", output: out };
}

function outcome(result, doing) {
    var env = envelope(result);
    if (env.cancelled)
        return null;
    if (env.ok)
        return { message: doing || "Done.", failed: false };
    return { message: env.error, failed: true };
}

function withNote(notes, key, note) {
    var next = Object.assign({}, notes);
    if (note === null)
        delete next[key];
    else
        next[key] = note;
    return next;
}

// ---- Dates and sizes ---------------------------------------------------------------------------

function two(n) {
    return n < 10 ? "0" + n : String(n);
}

/// "2026-11-16 14:41" from an ISO time, "never" when there is none.
function stamp(iso) {
    if (!iso)
        return "never";
    var text = String(iso).replace("T", " ");
    return text.slice(0, 16);
}

function ageText(hours) {
    if (hours === null || hours === undefined || isNaN(Number(hours)))
        return "unknown";
    var h = Number(hours);
    if (h < 1)
        return "less than an hour old";
    if (h < 48)
        return plural(Math.round(h), "hour", "hours") + " old";
    return plural(Math.round(h / 24), "day", "days") + " old";
}

function bytesText(n) {
    if (typeof n !== "number" || n < 0)
        return "";
    var units = ["B", "KB", "MB", "GB", "TB"];
    var v = n;
    var i = 0;
    while (v >= 1000 && i < units.length - 1) {
        v /= 1000;
        i++;
    }
    return (i === 0 || v >= 10 ? Math.round(v) : Math.round(v * 10) / 10) + " " + units[i];
}

// ---- Status --------------------------------------------------------------------------------------

/// `status summary --json`: {ok, problem, state: ok|warning|threat, title, reasons, scanning, lastScan, sigText, sigStale, quarantined, open}.
function parseSummary(result) {
    var env = envelope(result);
    if (!env.ok || !isObject(env.output))
        return { ok: false, problem: env.ok ? "oysterAV printed no status." : env.error, state: "", title: "Status unavailable", reasons: [], scanning: false, lastScan: "never", sigText: "", sigStale: false, quarantined: 0, open: 0 };
    var d = env.output;
    var state = d.state === "ok" || d.state === "threat" ? d.state : "warning";
    var reasons = Array.isArray(d.reasons) ? d.reasons.slice(0, 20).map(clip) : [];
    return {
        ok: true,
        problem: "",
        state: state,
        title: state === "ok" ? "Protected" : (state === "threat" ? "Threat found" : "Needs attention"),
        reasons: reasons,
        scanning: d.scanning === true,
        lastScan: stamp(d.last_scan_at),
        sigText: d.signature_age_hours === null || d.signature_age_hours === undefined ? "missing" : ageText(d.signature_age_hours),
        sigStale: d.signatures_stale === true,
        quarantined: Number(d.quarantine_count) || 0,
        open: Number(d.open_findings) || 0
    };
}

function summaryLine(s) {
    if (!s.ok)
        return "";
    return "Last scan " + s.lastScan + ". Signatures: " + s.sigText + ". " + plural(s.quarantined, "file", "files") + " in quarantine.";
}

/// `job status --json`: a scan running now, from anywhere (oysterAV, the timer, this page).
function parseJob(result) {
    var env = envelope(result);
    var d = env.ok && isObject(env.output) ? env.output : {};
    return {
        active: d.active === true,
        percent: Math.max(0, Math.min(100, Number(d.percent) || 0)),
        pack: clip(d.pack || ""),
        message: clip(d.message || ""),
        jobId: clip(d.job_id || "")
    };
}

// ---- Scans: streamed progress ----------------------------------------------------------------------

/// The state of a scan the page started; `kind` is "scan" or "rootkit".
function startScan(kind, label) {
    return { kind: kind, label: label, percent: -1, stage: "Starting", done: false, result: null };
}

/// Fold one line of the scan's output into the state: {event: progress, stage, percent} or {event: result, ...}.
function reduceScan(state, ev) {
    if (!isObject(ev))
        return state;
    var next = Object.assign({}, state);
    if (ev.event === "progress") {
        next.percent = typeof ev.percent === "number" ? Math.max(0, Math.min(100, ev.percent)) : state.percent;
        next.stage = ev.stage ? clip(ev.stage) : state.stage;
    } else if (ev.event === "result") {
        next.result = ev;
        next.percent = 100;
        next.done = true;
    }
    return next;
}

/// 0..1, or -1 when the scan hasn't said how far it is (an indeterminate bar).
function fraction(state) {
    if (!state || state.percent < 0 || (state.percent === 0 && !state.done))
        return -1;
    return state.percent / 100;
}

function scanLine(state) {
    if (!state)
        return "";
    if (state.done)
        return "Finished.";
    var pct = state.percent > 0 ? " " + Math.round(state.percent) + "%" : "";
    return state.stage === "Starting" ? "Starting " + state.label + "…" : state.label + ": " + state.stage + pct;
}

function findings(result) {
    var list = result && Array.isArray(result.findings) ? result.findings : [];
    return list.slice(0, MAX_ROWS).filter(isObject).map(function (f) {
        return { pack: clip(f.pack || ""), path: clip(f.path || ""), threat: clip(f.threat_name || "unknown"), quarantined: f.quarantined === true, resolved: f.resolved === true };
    });
}

/// What a finished scan says: {message, failed, threats: [{path, threat, ...}]}. `done` is the stream's
/// own result (code, error); the scan's JSON is what tells clean from infected.
function scanOutcome(state, done) {
    var env = envelope(done);
    if (env.cancelled)
        return null;
    var result = state && state.result;
    if (!result) {
        var code = done && typeof done.code === "number" ? done.code : 0;
        var why = code === 3 ? "Another scan is already running." : (env.error || "The scan ended without a result.");
        return { message: why, failed: true, threats: [] };
    }
    var threats = findings(result).filter(function (f) { return !f.quarantined && !f.resolved; });
    var errs = Array.isArray(result.pack_errors) ? result.pack_errors.map(function (e) { return clip((e.pack || "scanner") + ": " + (e.error || "failed")); }) : [];
    if (result.state === "cancelled")
        return { message: "The scan was cancelled.", failed: false, threats: [] };
    var text = threats.length === 0 ? "No threats found." : plural(threats.length, "threat", "threats") + " found.";
    if (errs.length > 0)
        text += " " + errs.slice(0, 3).join("; ") + (errs.length > 3 ? "; …" : "") + ".";
    return { message: text, failed: errs.length > 0 && threats.length === 0, threats: threats };
}

function scanArgs(profile, folder) {
    return [profile, folder];
}

function folderPath(url) {
    var s = String(url);
    return s.indexOf("file://") === 0 ? decodeURIComponent(s.slice(7)) : "";
}

// ---- Plans (the `--dry-run --json` document) ---------------------------------------------------------

/// A line for under a folder choice: "1,204 files, 1 scanner(s)" or why the scan would be refused.
function planLine(result) {
    var env = envelope(result);
    if (!env.ok || !isObject(env.output))
        return env.ok ? "" : env.error;
    var d = env.output;
    if (d.would_refuse === true)
        return clip(d.reason || "oysterAV would refuse this.");
    return clip(d.summary || "");
}

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
