.pragma library
.import "logic.js" as Logic

// The Firewall tab's plain-text helpers: `oyst-cli firewall overview --json` parsed into what the cards show, the
// rule form, and the values each firewall command takes. The argument patterns themselves live in logic.js
// (PATTERNS, FW_*), beside every other command's.

var FW_NAMES = { ufw: "UFW", firewalld: "firewalld" };
var FW_BACKENDS = ["ufw", "firewalld"];
var FW_POLICIES = ["allow", "deny", "reject"];
var FW_POLICY_LABELS = { allow: "Allow", deny: "Block", reject: "Refuse" };
var FW_DIRECTIONS = [
    { id: "incoming", label: "Incoming connections", help: "From other computers to this one. Block is the safe choice; your rules below make the exceptions." },
    { id: "outgoing", label: "Outgoing connections", help: "From this computer's apps to the internet and your network." },
    { id: "routed", label: "Forwarded connections", help: "Passing through this computer to another one, as for virtual machines and containers." }
];
var FW_ACTIONS = ["allow", "deny", "limit"];
var FW_ACTION_LABELS = { allow: "Allow", deny: "Block", limit: "Limit", reject: "Refuse" };
var FW_PROTOS = ["tcp", "udp"];
var FW_PROTO_LABELS = { tcp: "TCP", udp: "UDP" };

function _word(v, max) {
    return String(v === undefined || v === null ? "" : v).replace(/[\x00-\x1f\x7f]/g, "").slice(0, max || 64);
}

/// "22/tcp", "1714–1764/udp", "any protocol" for a rule with neither.
function fwPortText(port, proto) {
    var p = _word(port, 24).replace(":", "–");
    var pr = _word(proto, 8);
    if (p === "" || p === "any")
        return pr === "" || pr === "any" ? "Everything" : pr.toUpperCase();
    return pr === "" || pr === "any" ? p + " (TCP and UDP)" : p + "/" + pr;
}

/// One rule row of `firewall overview` as the Rules card shows it.
function fwRule(r, i) {
    var action = _word(r.action, 8);
    var outbound = r.direction === "out";
    var source = _word(r.source, 48) || "anywhere";
    var bits = [outbound ? "Outgoing" : "Incoming", source === "anywhere" ? "from anywhere" : "from " + source];
    if (r.ipv6_only === true)
        bits.push("IPv6 only");
    return {
        key: "fw-rule:" + i,
        action: action,
        port: _word(r.port, 24),
        proto: _word(r.proto, 8),
        source: source,
        outbound: outbound,
        title: (FW_ACTION_LABELS[action] || action) + " " + fwPortText(r.port, r.proto),
        detail: bits.join(" · "),
        removable: r.removable === true,
        editable: r.editable === true
    };
}

function fwZone(z) {
    var list = function (v) {
        return Array.isArray(v) ? v.slice(0, Logic.MAX_ROWS).map(function (x) { return _word(x, 64); }) : [];
    };
    var name = _word(z.name, 64);
    var tags = [];
    if (z["default"] === true)
        tags.push("default");
    if (z.active === true)
        tags.push("in use");
    return {
        name: name,
        label: tags.length ? name + " (" + tags.join(", ") + ")" : name,
        isDefault: z["default"] === true,
        active: z.active === true,
        interfaces: list(z.interfaces),
        sources: list(z.sources),
        services: list(z.services),
        ports: list(z.ports)
    };
}

/// `oyst-cli firewall overview --json`: {ok, problem, backend, on, conflict, ..., rules, zones, statusText}.
function parseFirewall(result) {
    var env = Logic.envelope(result);
    var o = env.output;
    if (!env.ok || !Logic.isObject(o) || typeof o.backend !== "string")
        return { ok: false, problem: env.ok ? "oysterAV printed no firewall state." : env.error, rules: [], zones: [] };
    var backend = FW_NAMES[o.backend] ? o.backend : "none";
    var installed = Logic.isObject(o.installed) ? o.installed : {};
    var defaults = Logic.isObject(o.defaults) ? o.defaults : {};
    var on = o.on === true;
    var name = FW_NAMES[backend] || "";
    var version = _word(o.version, 16);
    var status;
    if (o.conflict === true)
        status = "UFW and firewalld are both running";
    else if (backend === "none")
        status = o.active === "nft-direct" ? "Rules set up by hand (nftables)" : "Not installed";
    else
        status = (on ? "On" : "Off") + " · " + name + (on && version !== "" ? " " + version : "");
    return {
        ok: true,
        problem: "",
        backend: backend,
        name: name,
        on: on,
        conflict: o.conflict === true,
        handMade: o.active === "nft-direct",
        installed: { ufw: installed.ufw === true, firewalld: installed.firewalld === true },
        bothInstalled: installed.ufw === true && installed.firewalld === true,
        sshInUse: o.ssh_in_use === true,
        defaults: {
            incoming: FW_POLICIES.indexOf(defaults.incoming) >= 0 ? defaults.incoming : "",
            outgoing: FW_POLICIES.indexOf(defaults.outgoing) >= 0 ? defaults.outgoing : "",
            routed: FW_POLICIES.indexOf(defaults.routed) >= 0 ? defaults.routed : ""
        },
        rulesReadable: o.rules_readable !== false,
        rules: Array.isArray(o.rules) ? o.rules.slice(0, Logic.MAX_ROWS).filter(Logic.isObject).map(fwRule) : [],
        zones: Array.isArray(o.zones) ? o.zones.slice(0, 64).filter(Logic.isObject).map(fwZone) : [],
        statusText: status
    };
}

/// A blank rule form, or one filled from `rule` (to change it).
function fwForm(rule) {
    if (!rule)
        return { action: "allow", port: "", proto: "tcp", source: "" };
    return { action: rule.action, port: rule.port, proto: rule.proto === "udp" ? "udp" : "tcp", source: rule.source === "anywhere" ? "" : rule.source };
}

/// The four values oyst-cli takes for a rule: action, port, protocol, source ("anywhere" when blank).
function fwRuleArgs(form) {
    var source = String(form.source || "").trim();
    return [form.action, String(form.port || "").trim(), form.proto, source === "" || source.toLowerCase() === "anywhere" ? "anywhere" : source];
}

/// A sentence for a rule form oyst-cli would refuse ("" when it looks fine; oysterAV checks the rest).
function fwFormProblem(form) {
    var a = fwRuleArgs(form);
    if (a[1] === "")
        return "Type a port, like 8080, or a range like 1714:1764.";
    if (!new RegExp(Logic.FW_PORT).test(a[1]))
        return "A port is a number from 1 to 65535, or a range like 1714:1764.";
    var parts = a[1].split(":").map(Number);
    if (parts.some(function (n) { return n < 1 || n > 65535; }) || (parts.length === 2 && parts[0] >= parts[1]))
        return "A port is a number from 1 to 65535, or a range from low to high.";
    if (!new RegExp(Logic.FW_SOURCE).test(a[3]))
        return "From is blank for anywhere, or an address like 192.168.1.20 or a network like 192.168.1.0/24.";
    return "";
}

/// The values for opening a port in a firewalld zone: "8080/tcp".
function fwPortSpec(port, proto) {
    return String(port || "").trim() + "/" + proto;
}
