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
// The firewall's values (oyst-cli firewall ...). A port is one number or a range "1714:1764"; a source is
// "anywhere" or an address or network.
var FW_STATE = "^(on|off)$";
var FW_BACKEND = "^(ufw|firewalld)$";
var FW_DIRECTION = "^(incoming|outgoing|routed)$";
var FW_POLICY = "^(allow|deny|reject)$";
var FW_ACTION = "^(allow|deny|limit)$";
var FW_PORT = "^[0-9]{1,5}(:[0-9]{1,5})?$";
var FW_PROTO = "^(tcp|udp)$";
var FW_SOURCE = "^(anywhere|[0-9A-Fa-f.:]{2,39}(/[0-9]{1,3})?)$";
var FW_OP = "^(add|remove)$";
var FW_ZONE = "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$";
var FW_PORT_SPEC = "^[0-9]{1,5}/(tcp|udp)$";
var FW_RULE = [FW_ACTION, FW_PORT, FW_PROTO, FW_SOURCE];
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
    "fw-turn": [FW_STATE],
    "preview-fw-turn": [FW_STATE],
    "fw-use": [FW_BACKEND],
    "preview-fw-use": [FW_BACKEND],
    "fw-policy": [FW_DIRECTION, FW_POLICY],
    "preview-fw-policy": [FW_DIRECTION, FW_POLICY],
    "fw-rule-add": FW_RULE,
    "preview-fw-rule-add": FW_RULE,
    "fw-rule-remove": FW_RULE,
    "preview-fw-rule-remove": FW_RULE,
    "fw-rule-change": FW_RULE.concat(FW_RULE),
    "preview-fw-rule-change": FW_RULE.concat(FW_RULE),
    "fw-zone-port": [FW_OP, FW_ZONE, FW_PORT_SPEC],
    "preview-fw-zone-port": [FW_OP, FW_ZONE, FW_PORT_SPEC],
    "fw-zone-service": [FW_OP, FW_ZONE, FW_ZONE],
    "preview-fw-zone-service": [FW_OP, FW_ZONE, FW_ZONE],
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
        return { ok: false, problem: env.ok ? "oysterAV printed no status." : env.error, state: "", title: "Status unavailable", reasons: [], scanning: false, lastScan: "never", sigText: "", sigStale: false, quarantined: 0, open: 0, setupDone: true };
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
        open: Number(d.open_findings) || 0,
        // Only an explicit false gates the page: an older oyst-cli that doesn't say is taken as set up.
        setupDone: d.setup_completed !== false
    };
}

/// `setup status --json`: {ok, problem, completed, needsAttention, lines}; lines say what is still open, in plain words.
function parseSetup(result) {
    var env = envelope(result);
    if (!env.ok || !isObject(env.output))
        return { ok: false, problem: env.ok ? "oysterAV printed no setup state." : env.error, completed: false, needsAttention: true, lines: [] };
    var d = env.output;
    var lines = [];
    var req = Array.isArray(d.missing_required) ? d.missing_required.slice(0, 20).map(clip) : [];
    if (req.length > 0)
        lines.push("Scanners to install: " + req.join(", "));
    if (d.missing_signatures === true)
        lines.push("Virus signatures aren't downloaded yet.");
    if (d.helper_missing === true)
        lines.push("oysterAV's password helper isn't installed or is out of date.");
    if (d.install_mismatch === true)
        lines.push("Setup was run for a different install of oysterAV.");
    if (d.completed !== true)
        lines.unshift("First-time setup hasn't been run.");
    return { ok: true, problem: "", completed: d.completed === true, needsAttention: d.needs_attention !== false, lines: lines };
}

/// What a finished setup run says: steps that failed are named, since oysterAV leaves setup open then.
function setupOutcome(result) {
    var env = envelope(result);
    if (env.cancelled)
        return null;
    var out = isObject(env.output) ? env.output : {};
    if (!env.ok && !Array.isArray(out.steps))
        return { message: env.error, failed: true };
    var steps = Array.isArray(out.steps) ? out.steps : [];
    var bad = steps.filter(function (s) { return isObject(s) && s.ok === false && s.skipped !== true; }).slice(0, 6).map(function (s) { return clip(s.step || "a step") + (s.message ? " (" + clip(s.message) + ")" : ""); });
    if (out.completed === true)
        return { message: "Setup is complete.", failed: false };
    return { message: bad.length > 0 ? "Setup isn't finished: " + bad.join("; ") + "." : "Setup isn't finished.", failed: true };
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
