// Node tests for the Firewall tab's helpers (firewall.js) and its commands in page.toml.
//   node --test 'tests/uq/*.test.mjs'
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { loadLogic } from "./load-logic.mjs";
import { parseToml } from "./toml-lite.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pageDir = join(here, "../../uq/pages/oysterav-security");
const Logic = loadLogic(join(pageDir, "logic.js"));
const fw = loadLogic(join(pageDir, "firewall.js"), { Logic });
const manifest = parseToml(readFileSync(join(pageDir, "page.toml"), "utf8"));
const fixture = (name) => JSON.parse(readFileSync(join(here, "fixtures", name), "utf8"));
const plain = (v) => JSON.parse(JSON.stringify(v));
const ok = (output) => ({ code: 0, output });
const command = (id) => manifest.command.find((c) => c.id === id);

test("firewall: the overview of a UFW computer reads as the cards show it", () => {
  const f = fw.parseFirewall(ok(fixture("firewall.json")));
  assert.equal(f.ok, true);
  assert.equal(f.backend, "ufw");
  assert.equal(f.statusText, "On · UFW 0.36.2");
  assert.deepEqual(plain(f.defaults), { incoming: "deny", outgoing: "allow", routed: "deny" });
  const titles = f.rules.map((r) => r.title);
  assert.ok(titles.includes("Allow 22/tcp"));
  assert.ok(titles.includes("Allow 1714–1764/udp"));
  const db = f.rules.find((r) => r.port === "3306");
  assert.equal(db.title, "Block 3306/tcp");
  assert.equal(db.detail, "Incoming · from 192.168.1.0/24");
  assert.equal(db.editable, true);
  const eth = f.rules.find((r) => r.port === "80");
  assert.equal(eth.removable, false, "a rule bound to one network card is changed in a terminal");
});

test("firewall: off, missing, both running, and a failed read", () => {
  const base = fixture("firewall.json");
  assert.equal(fw.parseFirewall(ok({ ...base, on: false, active: "none" })).statusText, "Off · UFW");
  assert.equal(fw.parseFirewall(ok({ ...base, backend: "none", active: "none" })).statusText, "Not installed");
  assert.equal(fw.parseFirewall(ok({ ...base, backend: "none", active: "nft-direct" })).handMade, true);
  const both = fw.parseFirewall(ok({ ...base, conflict: true, installed: { ufw: true, firewalld: true } }));
  assert.equal(both.conflict, true);
  assert.equal(both.bothInstalled, true);
  const bad = fw.parseFirewall({ code: 1, error: "exit code 1: boom" });
  assert.equal(bad.ok, false);
  assert.match(bad.problem, /boom/);
  assert.equal(fw.parseFirewall(ok({ nonsense: 1 })).ok, false);
  // Unknown policies and long junk don't reach the page as they are.
  const odd = fw.parseFirewall(ok({ ...base, defaults: { incoming: "<b>x</b>" }, version: "x".repeat(500) }));
  assert.equal(odd.defaults.incoming, "");
  assert.ok(odd.statusText.length < 40);
});

test("firewall: zones keep the default first and say which are in use", () => {
  const zones = [
    { name: "public", default: true, active: true, interfaces: ["wlan0"], services: ["ssh"], ports: ["8080/tcp"] },
    { name: "home", default: false, active: false, interfaces: [], services: [], ports: [] }
  ];
  const f = fw.parseFirewall(ok({ ...fixture("firewall.json"), backend: "firewalld", active: "firewalld", zones }));
  assert.deepEqual(f.zones.map((z) => z.label), ["public (default, in use)", "home"]);
  assert.deepEqual(plain(f.zones[0].services), ["ssh"]);
});

test("firewall: the rule form becomes the four values oyst-cli takes, and says what is wrong", () => {
  const blank = fw.fwForm(null);
  assert.deepEqual(plain(blank), { action: "allow", port: "", proto: "tcp", source: "" });
  assert.match(fw.fwFormProblem(blank), /Type a port/);
  const good = { action: "limit", port: " 22 ", proto: "tcp", source: "" };
  assert.equal(fw.fwFormProblem(good), "");
  assert.deepEqual(plain(fw.fwRuleArgs(good)), ["limit", "22", "tcp", "anywhere"]);
  assert.equal(Logic.argsProblem("fw-rule-add", fw.fwRuleArgs(good)), "");
  for (const port of ["0", "70000", "90:80", "22/tcp", "-1", "80,443"])
    assert.notEqual(fw.fwFormProblem({ ...good, port }), "", port);
  for (const source of ["192.168.1.0/24", "10.0.0.5", "fe80::1", "Anywhere"])
    assert.equal(fw.fwFormProblem({ ...good, source }), "", source);
  for (const source of ["my-laptop", "--from", "10.0.0.1 to any"])
    assert.notEqual(fw.fwFormProblem({ ...good, source }), "", source);
  // Changing a rule starts from it, and sends the old four values then the new four.
  const row = fw.parseFirewall(ok(fixture("firewall.json"))).rules.find((r) => r.port === "3306");
  const form = fw.fwForm(row);
  assert.deepEqual(plain(form), { action: "deny", port: "3306", proto: "tcp", source: "192.168.1.0/24" });
  const args = fw.fwRuleArgs(fw.fwForm(row)).concat(fw.fwRuleArgs({ ...form, source: "" }));
  assert.equal(Logic.argsProblem("fw-rule-change", args), "");
  assert.equal(fw.fwPortSpec(" 8080", "udp"), "8080/udp");
  assert.equal(Logic.argsProblem("fw-zone-port", ["add", "public", fw.fwPortSpec("8080", "udp")]), "");
});

test("firewall: every change asks first, shows a plan, and takes the same values as its plan", () => {
  for (const id of ["fw-turn", "fw-use", "fw-policy", "fw-rule-add", "fw-rule-remove", "fw-rule-change", "fw-zone-port", "fw-zone-service"]) {
    const c = command(id);
    assert.ok(c.confirm, `${id} asks first`);
    assert.equal(c.preview, `preview-${id}`);
    assert.deepEqual(plain(command(c.preview).args), plain(c.args));
    assert.ok(c.argv.includes("--confirm") && !c.argv.some((a) => /force/.test(a)), `${id} never forces`);
  }
  const read = command("firewall");
  assert.deepEqual(plain(read.watch.files), ["/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/ufw.conf", "/etc/default/ufw"]);
  assert.equal(read.confirm, undefined);
});
