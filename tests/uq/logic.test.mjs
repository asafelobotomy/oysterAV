// Node tests for the Security page: logic.js, page.toml and what the QML may send.
//   node --test 'tests/uq/*.test.mjs'
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { loadLogic } from "./load-logic.mjs";
import { parseToml } from "./toml-lite.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pageDir = join(here, "../../uq/pages/oysterav-security");
const logic = loadLogic(join(pageDir, "logic.js"));
const manifest = parseToml(readFileSync(join(pageDir, "page.toml"), "utf8"));
const qmlFiles = readdirSync(pageDir).filter((f) => f.endsWith(".qml")).sort();
const qmlOf = (f) => readFileSync(join(pageDir, f), "utf8");
const allQml = qmlFiles.map(qmlOf).join("\n");
const fixture = (name) => JSON.parse(readFileSync(join(here, "fixtures", name), "utf8"));
// logic.js runs in its own context; its arrays and objects have another prototype, so compare plain copies
const plain = (v) => JSON.parse(JSON.stringify(v));
const ok = (output) => ({ code: 0, output });
const command = (id) => manifest.command.find((c) => c.id === id);

// ---- page.toml ----------------------------------------------------------------------------------------------

test("manifest: uq_api 3, unique ids, and the file the page names exists", () => {
  assert.equal(manifest.uq_api, 3);
  assert.equal(manifest.id, "oysterav-security");
  assert.ok(qmlFiles.includes(manifest.qml));
  const ids = manifest.command.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  const settings = manifest.setting.map((s) => s.id);
  assert.equal(new Set(settings).size, settings.length);
});

test("manifest: every command is used by the page, and every preview is a read that takes the same arguments", () => {
  for (const c of manifest.command) {
    assert.ok(allQml.includes(`"${c.id}"`) || c.id.startsWith("preview-"), `${c.id} is used in QML`);
    if (c.id.startsWith("preview-")) continue;
    assert.ok(c.argv[0] === "/usr/bin/oyst-cli", c.id);
  }
  const previewed = manifest.command.filter((c) => c.preview);
  assert.ok(previewed.length >= 6);
  for (const c of previewed) {
    const p = command(c.preview);
    assert.ok(p, `${c.id}: preview ${c.preview} exists`);
    assert.ok(c.confirm, `${c.id} has a confirm to show the plan under`);
    assert.deepEqual(plain(p.args ?? []), plain(c.args ?? []), `${c.id}: the preview takes the same arguments`);
    assert.ok(!p.confirm && !p.preview, `${p.id} asks nothing`);
    assert.equal(p.output, "json");
    assert.ok(p.argv.includes("--dry-run"), `${p.id} is a --dry-run`);
    assert.ok(!c.argv.includes("--dry-run"), c.id);
  }
});

test("manifest: what changes something asks first, with a plan where there is one", () => {
  const writes = ["quarantine-add", "quarantine-restore", "quarantine-delete", "quarantine-reconcile", "service-set", "rootkit-check", "schedule-disable", "schedule-run"];
  for (const id of writes) assert.ok(command(id).confirm, `${id} asks first`);
  for (const id of ["quarantine-add", "quarantine-restore", "quarantine-delete", "quarantine-reconcile", "service-set", "rootkit-check"]) {
    assert.ok(command(id).preview, `${id} shows a plan`);
  }
  // nothing forces: no flag that overrides oysterAV's own refusals
  for (const c of manifest.command) for (const flag of ["--force", "--delete-all", "delete-all"]) assert.ok(!c.argv.includes(flag), `${c.id} ${flag}`);
  // a scan from this page only looks: it never moves a file by itself (--quarantine is the schedule's own option)
  for (const c of manifest.command.filter((x) => x.argv[1] === "scan")) assert.ok(!c.argv.includes("--quarantine"), c.id);
});

test("manifest: scans stream, and every other command prints one JSON document", () => {
  for (const id of ["scan-folder", "rootkit-check"]) {
    assert.equal(command(id).output, "ndjson");
    assert.ok(command(id).argv.includes("--ndjson"));
  }
  for (const c of manifest.command) if (c.output !== "ndjson") assert.ok(c.argv.includes("--json"), c.id);
});

test("patterns_match_manifest: logic.js and page.toml carry the same argument patterns", () => {
  const fromManifest = {};
  for (const c of manifest.command) if (c.args) fromManifest[c.id] = c.args.map((a) => a.pattern);
  for (const c of manifest.command) for (const a of c.args ?? []) assert.ok(a.pattern.startsWith("^") && a.pattern.endsWith("$"), `${c.id}.${a.name} is anchored`);
  assert.deepEqual(plain(logic.PATTERNS), fromManifest);
});

test("watch: the config file is followed", () => {
  assert.deepEqual(plain(command("config").watch.files), ["~/.config/oysterav/config.toml"]);
});

test("qml: every [[setting]] row is reachable, and no file is over 400 lines", () => {
  for (const s of manifest.setting) assert.ok(allQml.includes(`settingId: "${s.id}"`) || allQml.includes(`"${s.id}" : ""`) || allQml.includes(`? "${s.id}"`), `${s.id}`);
  for (const f of qmlFiles) assert.ok(qmlOf(f).split("\n").length <= 400, `${f} is over 400 lines`);
  assert.ok(readFileSync(join(pageDir, "logic.js"), "utf8").split("\n").length <= 700);
});

test("qml: text is shown through UqLabel only, and buttons use fixed text", () => {
  const banned = /(^|[^A-Za-z0-9_.])(Text|Label|TextEdit|TextInput)\s*\{/m;
  for (const f of qmlFiles) assert.ok(!banned.test(qmlOf(f)), `${f} shows text with a stock item`);
  assert.ok(!/Qt\.createQmlObject/.test(allQml));
  assert.ok(!/import org\.kde\.kirigami/.test(allQml));
});

// ---- Arguments -------------------------------------------------------------------------------------------------------

test("argsProblem: accepts what the page sends and refuses options and junk", () => {
  assert.equal(logic.argsProblem("scan-folder", ["quick", "/home/me/Downloads"]), "");
  assert.equal(logic.argsProblem("scan-folder", ["full", "/home/me/a folder"]), "");
  assert.notEqual(logic.argsProblem("scan-folder", ["integrity", "/home"]), "");
  assert.notEqual(logic.argsProblem("scan-folder", ["quick", "relative"]), "");
  assert.notEqual(logic.argsProblem("scan-folder", ["quick", "/tmp/a\nb"]), "");
  assert.notEqual(logic.argsProblem("scan-folder", ["quick"]), "");
  assert.notEqual(logic.argsProblem("quarantine-restore", ["-1"]), "");
  assert.notEqual(logic.argsProblem("quarantine-restore", ["0"]), "");
  assert.equal(logic.argsProblem("quarantine-restore", ["12"]), "");
  assert.equal(logic.argsProblem("quarantine-add", ["Win.Test.EICAR_HDB-1".replace("_", "."), "/home/me/x.exe"]), "");
  assert.notEqual(logic.argsProblem("quarantine-add", ["--confirm", "/x"]), "");
  assert.equal(logic.argsProblem("service-set", ["clamd", "on"]), "");
  assert.notEqual(logic.argsProblem("service-set", ["sshd", "on"]), "");
  assert.notEqual(logic.argsProblem("service-set", ["clamd", "restart"]), "");
  assert.equal(logic.argsProblem("schedule-time", ["02:30"]), "");
  assert.notEqual(logic.argsProblem("schedule-time", ["24:00"]), "");
  assert.notEqual(logic.argsProblem("schedule-time", ["2:30"]), "");
  assert.equal(logic.argsProblem("config-set", ["scan.max_files", ""]), "");
  assert.notEqual(logic.argsProblem("config-set", ["schedule.enabled", "true"]), "", "schedule keys go through the schedule commands");
  assert.notEqual(logic.argsProblem("config-set", ["setup.completed", "true"]), "");
  assert.equal(logic.argsProblem("summary", []), "");
  assert.notEqual(logic.argsProblem("summary", ["x"]), "");
});

test("config-set: every key the schema lists is accepted by the manifest's key pattern", () => {
  const keys = Object.keys(fixture("config.json").values);
  const pattern = new RegExp(command("config-set").args[0].pattern);
  for (const k of keys) assert.ok(pattern.test(k), k);
});

// ---- envelope --------------------------------------------------------------------------------------------------------

test("envelope: a refusal keeps oysterAV's words; a cancel is not an error", () => {
  assert.equal(logic.envelope(ok({ ok: true })).ok, true);
  assert.deepEqual(plain(logic.envelope({ code: 2, error: "exit code 2", output: { ok: false, key: "k", error: "scan.max_files must be >= 1" } })), { ok: false, cancelled: false, error: "scan.max_files must be >= 1", output: { ok: false, key: "k", error: "scan.max_files must be >= 1" } });
  assert.equal(logic.envelope({ error: "Cancelled", cancelled: true }).cancelled, true);
  assert.equal(logic.envelope(null).ok, false);
  assert.equal(logic.envelope({ error: "timed out" }).error, "timed out");
  assert.equal(logic.outcome({ error: "Cancelled", cancelled: true }), null);
  assert.deepEqual(plain(logic.outcome(ok({ ok: true }), "Saved.")), { message: "Saved.", failed: false });
  assert.equal(logic.outcome({ code: 4, error: "exit code 4" }).failed, true);
});

test("withNote adds and removes without touching the old notes", () => {
  const a = {};
  const b = logic.withNote(a, "k", { message: "x" });
  assert.deepEqual(plain(a), {});
  assert.deepEqual(plain(b), { k: { message: "x" } });
  assert.deepEqual(plain(logic.withNote(b, "k", null)), {});
});

// ---- parsers ---------------------------------------------------------------------------------------------------------

test("parseSummary: protected, needs attention, threat, and a failure", () => {
  const threat = plain(logic.parseSummary(ok(fixture("summary.json"))));
  assert.equal(threat.state, "threat");
  assert.equal(threat.title, "Threat found");
  assert.equal(threat.quarantined, 1);
  assert.equal(threat.open, 1);
  assert.equal(threat.sigText, "missing");
  assert.equal(threat.sigStale, true);
  assert.equal(threat.lastScan, "2026-11-16 09:30");
  assert.equal(threat.reasons.length, 2);
  const good = plain(logic.parseSummary(ok({ ...fixture("summary.json"), state: "ok", reasons: [], signature_age_hours: 5.4, signatures_stale: false })));
  assert.equal(good.title, "Protected");
  assert.equal(good.sigText, "5 hours old");
  assert.equal(logic.parseSummary(ok({ state: "odd" })).title, "Needs attention");
  const bad = logic.parseSummary({ error: "exit code 127: oyst-cli: not found" });
  assert.equal(bad.ok, false);
  assert.equal(bad.title, "Status unavailable");
  assert.equal(logic.parseSummary(ok("text")).ok, false);
  assert.match(logic.summaryLine(good), /Last scan .*Signatures: 5 hours old\. 1 file in quarantine\./);
});

test("parseJob: a scan running now", () => {
  const idle = plain(logic.parseJob(ok(fixture("job.json"))));
  assert.equal(idle.active, false);
  const busy = plain(logic.parseJob(ok({ ...fixture("job.json"), active: true, percent: 42.5, pack: "clamav", message: "Scanning", job_id: "j" })));
  assert.deepEqual(busy, { active: true, percent: 42.5, pack: "clamav", message: "Scanning", jobId: "j" });
  assert.equal(logic.parseJob({ error: "x" }).active, false);
  assert.equal(logic.parseJob(ok({ active: true, percent: 900 })).percent, 100);
});

test("scan streaming: progress events move the bar, the result ends it", () => {
  let s = logic.startScan("scan", "Scanning /home/me");
  assert.equal(logic.fraction(s), -1, "no percentage yet: an indeterminate bar");
  assert.equal(logic.scanLine(s), "Starting Scanning /home/me…");
  s = logic.reduceScan(s, { event: "progress", stage: "clamav", percent: 0 });
  assert.equal(logic.fraction(s), -1, "0% from the first scanner is still unknown");
  s = logic.reduceScan(s, { event: "progress", stage: "clamav", percent: 50 });
  assert.equal(logic.fraction(s), 0.5);
  assert.equal(logic.scanLine(s), "Scanning /home/me: clamav 50%");
  assert.equal(logic.reduceScan(s, "junk"), s);
  assert.equal(logic.reduceScan(s, { event: "other" }).percent, 50);
  const clean = logic.reduceScan(s, { event: "result", job_id: "j", findings: [], pack_errors: [], clean: true, state: "completed" });
  assert.equal(clean.done, true);
  assert.equal(logic.fraction(clean), 1);
  assert.equal(logic.scanLine(clean), "Finished.");
  assert.deepEqual(plain(logic.scanOutcome(clean, { code: 0, output: null })), { message: "No threats found.", failed: false, threats: [] });
});

test("scanOutcome: threats, scanner errors, a busy scan, a cancel and a decline", () => {
  const found = logic.reduceScan(logic.startScan("scan", "x"), { event: "result", findings: [{ pack: "clamav", path: "/home/me/bad.exe", threat_name: "Win.Test.EICAR", quarantined: false }, { pack: "clamav", path: "/home/me/old", threat_name: "Old", quarantined: true }], pack_errors: [], clean: false, state: "completed" });
  const o = plain(logic.scanOutcome(found, { code: 1, error: "exit code 1", output: null }));
  assert.equal(o.message, "1 threat found.");
  assert.equal(o.threats.length, 1, "an already quarantined finding isn't offered again");
  assert.equal(o.threats[0].path, "/home/me/bad.exe");
  const missing = logic.reduceScan(logic.startScan("scan", "x"), { event: "result", findings: [], pack_errors: [{ pack: "clamav", error: "required pack missing: sudo apt install clamav" }], clean: false, state: "completed" });
  const m = plain(logic.scanOutcome(missing, { code: 5, error: "exit code 5" }));
  assert.equal(m.failed, true);
  assert.match(m.message, /clamav: required pack missing/);
  const busy = plain(logic.scanOutcome(logic.startScan("scan", "x"), { code: 3, error: "exit code 3" }));
  assert.deepEqual(busy, { message: "Another scan is already running.", failed: true, threats: [] });
  assert.equal(logic.scanOutcome(logic.startScan("scan", "x"), { error: "Cancelled", cancelled: true }), null);
  const cancelled = logic.reduceScan(logic.startScan("scan", "x"), { event: "result", findings: [], pack_errors: [], state: "cancelled" });
  assert.equal(logic.scanOutcome(cancelled, { code: 0 }).message, "The scan was cancelled.");
  assert.equal(logic.scanOutcome(logic.startScan("scan", "x"), { error: "timed out" }).message, "timed out");
});

test("planLine: the count, or why the scan would be refused", () => {
  assert.equal(logic.planLine(ok(fixture("preview-scan.json"))), "1 files, 1 scanner(s)");
  assert.equal(logic.planLine(ok({ summary: "x", would_refuse: true, reason: "Not found: /nope" })), "Not found: /nope");
  assert.equal(logic.planLine({ error: "timed out" }), "timed out");
});

test("parseHistory", () => {
  const h = plain(logic.parseHistory(ok(fixture("history.json"))));
  assert.equal(h.ok, true);
  assert.equal(h.rows.length, 1);
  assert.deepEqual(h.rows[0], { id: "job-1", when: "2026-11-16 09:30", title: "Quick (ClamAV)", detail: "/home/user/Downloads", outcome: "1 threat found", threat: true, problem: false });
  const clean = plain(logic.parseHistory(ok([{ job_id: "a", profile: "full", paths: [], started_at: "2026-01-01T00:00:00", clean: true, findings_count: 0, open_findings_count: 0, state: "completed" }, { job_id: "b", profile: "quick", clean: false, findings_count: 0, state: "completed" }])));
  assert.equal(clean.rows[0].outcome, "Clean");
  assert.equal(clean.rows[1].outcome, "Finished with errors");
  assert.equal(logic.parseHistory(ok([])).rows.length, 0);
  assert.equal(logic.parseHistory(ok({})).ok, false);
});

test("parseQuarantine and parseVerify", () => {
  const q = plain(logic.parseQuarantine(ok(fixture("quarantine.json"))));
  assert.deepEqual(q.rows, [{ id: "1", name: "bad.exe", path: "/home/user/Downloads/bad.exe", threat: "Win.Test.EICAR_HDB-1", when: "2026-11-16 09:30" }]);
  assert.equal(logic.parseQuarantine(ok([{ id: 0, original_path: "/x" }])).rows.length, 0, "an entry without a usable id can't be named, so it isn't offered");
  assert.equal(logic.parseQuarantine({ error: "boom" }).ok, false);
  const v = plain(logic.parseVerify(ok(fixture("quarantine-verify.json"))));
  assert.equal(v.clean, true);
  assert.equal(v.text, "The vault is consistent.");
  const dirty = plain(logic.parseVerify(ok({ invalid_entries: [{}], orphans: ["a", "b"], orphan_count: 2, ok: false })));
  assert.equal(dirty.orphans, 2);
  assert.equal(dirty.text, "1 entry no longer matches its file. 2 stray files belong to no entry.");
  assert.equal(logic.parseVerify({ code: 1, error: "exit code 1", output: { invalid_entries: [], orphan_count: 1, ok: false } }).orphans, 1);
});

test("parseSchedule and scheduleLine", () => {
  const off = plain(logic.parseSchedule(ok(fixture("schedule.json"))));
  assert.equal(off.ok, true);
  assert.equal(off.enabled, false);
  assert.equal(off.frequency, "daily");
  assert.equal(off.time, "02:00");
  assert.equal(logic.scheduleLine(off), "Scheduled scans are off.");
  const on = plain(logic.parseSchedule(ok({ ...fixture("schedule.json"), enabled: true, next: "Tue 2026-11-17 02:00:00 UTC", linger: { available: true, linger: false } })));
  assert.equal(logic.scheduleLine(on), "Next scan: Tue 2026-11-17 02:00:00 UTC.");
  assert.equal(on.lingerOff, true);
  const custom = plain(logic.parseSchedule(ok({ ...fixture("schedule.json"), config: { ...fixture("schedule.json").config, frequency: "custom" } })));
  assert.equal(custom.frequency, "custom");
  assert.equal(logic.parseSchedule(ok({})).ok, false);
});

test("scheduleRunOutcome: exit 1 with the scan inside is a result", () => {
  assert.equal(logic.scheduleRunOutcome({ error: "Cancelled", cancelled: true }), null);
  const threat = plain(logic.scheduleRunOutcome({ code: 1, error: "exit code 1", output: { exit_code: 1, scan: { findings: [{ path: "/x", threat_name: "T" }] } } }));
  assert.deepEqual(threat, { message: "The scan found 1 threat. See Scans.", failed: true });
  assert.equal(logic.scheduleRunOutcome(ok({ exit_code: 0, scan: { findings: [] } })).failed, false);
  assert.equal(logic.scheduleRunOutcome({ code: 2, error: "exit code 2: bad" }).failed, true);
});

test("parseServices: one row per service, in the page's order", () => {
  const s = plain(logic.parseServices(ok(fixture("services.json"))));
  assert.equal(s.ok, true);
  assert.deepEqual(s.rows.map((r) => r.name), ["clamd", "clamonacc", "freshclam-timer", "maldet-monitor", "fail2ban", "schedule-linger"]);
  assert.equal(s.rows[0].running, false);
  assert.equal(s.rows[0].text, "Off");
  assert.equal(s.rows[1].installed, false, "clamonacc says it isn't installed");
  assert.equal(s.rows[1].text, "Not installed");
  assert.equal(logic.parseServices(ok({})).ok, false);
});

test("parseDoctor, parseHelper and parseAudit", () => {
  const d = plain(logic.parseDoctor(ok(fixture("doctor.json"))));
  assert.equal(d.ok, true);
  assert.ok(d.rows.length >= 5);
  assert.equal(d.rows[0].name, "clamav");
  assert.equal(d.rows[0].tier, "Needed");
  assert.equal(d.rows[0].text, "Missing");
  assert.match(d.rows[0].hint, /apt install/);
  const have = plain(logic.parseDoctor(ok([{ name: "clamav", tier: "required", installed: true, version: "1.4.2", version_ok: true, install_hint: "x" }, { name: "old", tier: "optional", installed: true, version: "0.1", version_ok: false }])));
  assert.equal(have.rows[0].text, "Installed 1.4.2");
  assert.equal(have.rows[0].hint, "");
  assert.equal(have.rows[1].text, "Too old (0.1)");
  assert.equal(have.rows[1].ok, false);
  assert.match(logic.parseHelper(ok(fixture("helper.json"))).text, /isn't installed/);
  assert.match(logic.parseHelper(ok({ installed: true, policy_current: true })).text, /up to date/);
  assert.match(logic.parseHelper(ok({ installed: true, policy_current: false })).text, /out of date/);
  const a = plain(logic.parseAudit(ok(fixture("audit.json"))));
  assert.equal(a.rows[0].title, "config.set: scan.max_files");
  assert.equal(a.rows[0].failed, false);
});

test("parseConfig groups the schema, and prefValue/prefText/prefProblem go both ways", () => {
  const c = logic.parseConfig(ok(fixture("config.json")));
  assert.equal(c.ok, true);
  assert.deepEqual(plain(c.groups.map((g) => g.title)), ["Scanning", "Quarantine", "Protection", "Updates", "System scans", "Security news", "App"]);
  const rows = plain(c.groups.flatMap((g) => g.rows));
  assert.equal(rows.length, Object.keys(fixture("config.json").values).length);
  for (const g of c.groups) assert.notEqual(logic.groupIcon(g.title), "configure", g.title);
  const files = c.byKey["scan.max_files"];
  assert.equal(files.kind, "int");
  assert.equal(files.min, 1);
  assert.equal(logic.prefText(files), "10000");
  assert.equal(logic.prefProblem(files, "0"), "Files per archive must be at least 1.");
  assert.equal(logic.prefProblem(files, "x"), "Files per archive must be a whole number.");
  assert.equal(logic.prefProblem(files, "500"), "");
  assert.equal(logic.prefProblem(c.byKey["scan.profile"], "anything"), "");
  const list = c.byKey["clamonacc.paths"];
  assert.equal(logic.prefText(list), "~/Downloads, ~/Desktop");
  assert.equal(logic.prefValue(list, " ~/a ,, /b "), "~/a,/b");
  assert.equal(logic.prefValue(list, ""), "");
  assert.equal(logic.prefValue(c.byKey["quarantine.auto"], true), "true");
  assert.equal(logic.prefValue(c.byKey["quarantine.auto"], false), "false");
  assert.equal(logic.prefValue(c.byKey["scan.profile"], "full"), "full");
  assert.deepEqual(plain(c.byKey["scan.backend"].choices), ["auto", "clamd", "clamscan"]);
  assert.equal(logic.parseConfig({ error: "x" }).ok, false);
  assert.equal(logic.parseConfig(ok({ values: {}, schema: [{ key: "a.b" }] })).groups.length, 0, "a schema key with no value is skipped");
});

test("helpers: stamp, age, bytes, plural, clip, folderPath", () => {
  assert.equal(logic.stamp(null), "never");
  assert.equal(logic.stamp("2026-11-16T14:41:46.470256"), "2026-11-16 14:41");
  assert.equal(logic.ageText(0.2), "less than an hour old");
  assert.equal(logic.ageText(30), "30 hours old");
  assert.equal(logic.ageText(100), "4 days old");
  assert.equal(logic.ageText(null), "unknown");
  assert.equal(logic.bytesText(999), "999 B");
  assert.equal(logic.bytesText(1500), "1.5 KB");
  assert.equal(logic.bytesText(125829120), "126 MB");
  assert.equal(logic.plural(1, "file", "files"), "1 file");
  assert.equal(logic.plural(0, "file", "files"), "0 files");
  assert.equal(logic.clip("x".repeat(400)).length, 300);
  assert.equal(logic.folderPath("file:///home/me/My%20Folder"), "/home/me/My Folder");
  assert.equal(logic.folderPath("https://evil"), "");
});

// ---- First-time setup -------------------------------------------------------------------------------------------------

test("setup: summary gates only on an explicit false", () => {
  assert.equal(logic.parseSummary(ok({ state: "ok", setup_completed: false })).setupDone, false);
  assert.equal(logic.parseSummary(ok({ state: "ok", setup_completed: true })).setupDone, true);
  assert.equal(logic.parseSummary(ok({ state: "ok" })).setupDone, true, "an older oyst-cli doesn't lock the page");
  assert.equal(logic.parseSummary({ code: 127, error: "not found", output: null }).setupDone, true);
});

test("setup: parseSetup words what is still open", () => {
  const s = logic.parseSetup(ok(fixture("setup-status.json")));
  assert.equal(s.ok, true);
  assert.equal(s.completed, false);
  assert.equal(s.needsAttention, true);
  assert.deepEqual(plain(s.lines), ["First-time setup hasn't been run.", "Scanners to install: clamav, freshclam", "oysterAV's password helper isn't installed or is out of date."]);
  assert.equal(logic.parseSetup({ code: 1, error: "boom", output: null }).ok, false);
});

test("setup: outcome names failed steps and says when it is done", () => {
  assert.equal(logic.setupOutcome({ cancelled: true }), null);
  assert.deepEqual(plain(logic.setupOutcome(ok({ ok: true, completed: true, steps: [] }))), { message: "Setup is complete.", failed: false });
  const bad = logic.setupOutcome({ code: 2, error: "exit code 2", output: { ok: false, completed: false, steps: [{ step: "packs", ok: false, message: "pacman failed" }, { step: "schedule", skipped: true }] } });
  assert.equal(bad.failed, true);
  assert.equal(bad.message, "Setup isn't finished: packs (pacman failed).");
});

test("manifest: setup runs ask first and show a plan, and the basic form leaves host changes alone", () => {
  for (const id of ["setup-run", "setup-run-basic"]) {
    assert.ok(command(id).confirm, id);
    assert.ok(command(id).argv.includes("--confirm"), id);
  }
  assert.equal(command("setup-run").preview, "preview-setup");
  assert.equal(command("setup-run-basic").preview, "preview-setup-basic");
  for (const flag of ["--skip-harden", "--no-enable-firewall"]) {
    assert.ok(command("setup-run-basic").argv.includes(flag));
    assert.ok(command("preview-setup-basic").argv.includes(flag));
  }
  assert.ok(!command("setup-run").argv.includes("--skip-harden"));
  assert.deepEqual(plain(command("setup-status").argv.slice(1)), ["setup", "status", "--json"]);
});
