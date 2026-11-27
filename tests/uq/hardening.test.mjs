// The System tab's hardening card: reports.js parseHardening against `oyst-cli status hardening`.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { loadLogic } from "./load-logic.mjs";
import { parseToml } from "./toml-lite.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pageDir = join(here, "../../uq/pages/oysterav-security");
const core = loadLogic(join(pageDir, "logic.js"));
const reports = loadLogic(join(pageDir, "reports.js"), { Logic: core });
const fixture = (name) => JSON.parse(readFileSync(join(here, "fixtures", name), "utf8"));
const plain = (v) => JSON.parse(JSON.stringify(v));
const ok = (output) => ({ code: 0, output });

test("parseHardening turns each check into a row with a state word and a fix", () => {
  const h = plain(reports.parseHardening(ok(fixture("hardening.json"))));
  assert.equal(h.ok, true);
  assert.equal(h.summary, "15 of 22 checks pass, 3 need attention.");
  const mac = h.rows.find((r) => r.title.startsWith("App confinement"));
  assert.equal(mac.state, "warn");
  assert.equal(mac.text, "Weak");
  assert.match(mac.fix, /apparmor/);
  const kptr = h.rows.find((r) => r.title === "Kernel pointers hidden");
  assert.equal(kptr.fix, "kernel.kptr_restrict = 1");
  assert.equal(h.rows.find((r) => r.title === "Secure Boot").text, "Off");
  assert.equal(h.canHarden, true);
  assert.equal(h.canUndo, false);
});

test("parseHardening: odd states and bad output", () => {
  const odd = plain(reports.parseHardening(ok({ checks: [{ title: "x", state: "<b>" }], counts: { ok: 0 } })));
  assert.equal(odd.rows[0].state, "unknown");
  assert.equal(odd.rows[0].text, "Can't tell");
  assert.equal(odd.summary, "0 of 1 checks pass.");
  assert.equal(reports.parseHardening(ok({})).ok, false);
  assert.equal(reports.parseHardening({ code: 2, error: "boom", output: null }).ok, false);
});

test("page.toml: hardening read as the user, Harden behind a preview", () => {
  const manifest = parseToml(readFileSync(join(pageDir, "page.toml"), "utf8"));
  const cmd = manifest.command.find((c) => c.id === "hardening");
  assert.deepEqual(cmd.argv, ["/usr/bin/oyst-cli", "status", "hardening", "--json"]);
  const set = manifest.command.find((c) => c.id === "harden-set");
  assert.equal(set.preview, "preview-harden");
  assert.deepEqual(set.args.map((a) => a.pattern), ["^(apply|revert)$"]);
  assert.ok(manifest.command.length <= 64, "uQ allows 64 commands per page");
});
