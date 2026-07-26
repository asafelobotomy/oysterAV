"""Shared adversarial corpora for security-property tests.

Fail2Ban-style golden cases: input payload + expected outcome kind.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ExpectKind = Literal[
    "ok_argv",
    "value_error",
    "validation_error",
    "auth_error",
    "not_found",
    "usage_exit_2",
    "ok_result",
]


@dataclass(frozen=True)
class Expect:
    """Expected class of outcome for a corpus case."""

    kind: ExpectKind
    substr: str | None = None  # optional message / argv fragment


@dataclass(frozen=True)
class Case:
    """Named adversarial input with an expected outcome."""

    id: str
    surface: str
    payload: object
    expect: Expect


SHELL_METACHAR_TOKENS = (
    ";",
    "|",
    "&",
    "$",
    "`",
    "&&",
    "||",
    "$(id)",
    "`id`",
    "\n",
    "\r",
)

SHELL_METACHAR_SUFFIXES = (
    ";id",
    "|cat",
    "&true",
    "$(id)",
    "`id`",
    "\nid",
)

PATH_TRAVERSAL = (
    "../etc/passwd",
    "/etc/passwd",
    "/tmp/../etc/shadow",
    "foo/../../bar",
)

BAD_SHA256 = (
    "",
    "0" * 63,
    "0" * 65,
    "g" * 64,
    "not-a-hash",
)

OVERSIZE_NAME = "x" * 200

# --- RPC handle() cases (auth / params / methods) ---

RPC_AUTH_CASES: tuple[Case, ...] = tuple(
    Case(
        id=f"rpc-auth-{i}",
        surface="rpc",
        payload=auth,
        expect=Expect("auth_error"),
    )
    for i, auth in enumerate(
        (None, "", " truncated", 12345, ["list"], {"obj": True}),
    )
)

RPC_PARAMS_CASES: tuple[Case, ...] = tuple(
    Case(
        id=f"rpc-params-{i}",
        surface="rpc",
        payload=params,
        expect=Expect("validation_error", substr="params"),
    )
    for i, params in enumerate(([], ["x"], "string", 42, True))
)

RPC_METHOD_CASES: tuple[Case, ...] = (
    Case("rpc-method-empty", "rpc", "", Expect("not_found")),
    Case("rpc-method-unknown", "rpc", "not.a.method", Expect("not_found")),
    Case("rpc-method-traversal", "rpc", "../evil", Expect("not_found")),
    Case("rpc-method-shell", "rpc", "job.start;rm", Expect("not_found")),
    Case("rpc-method-oversize", "rpc", OVERSIZE_NAME, Expect("not_found")),
    Case(
        "rpc-method-non-str",
        "rpc",
        123,
        Expect("validation_error", substr="method"),
    ),
)

# Backward-compatible raw tuples (still used by a few tests / imports)
RPC_BAD_AUTH = tuple(c.payload for c in RPC_AUTH_CASES)
RPC_BAD_PARAMS = tuple(c.payload for c in RPC_PARAMS_CASES)
RPC_UNKNOWN_METHODS = tuple(c.payload for c in RPC_METHOD_CASES if isinstance(c.payload, str))

# --- Helper systemctl / fail2ban / maldet / rkhunter ---

SYSTEMCTL_REJECT_CASES: tuple[Case, ...] = (
    Case("sysctl-empty", "helper_systemctl", [], Expect("value_error")),
    Case("sysctl-restart-only", "helper_systemctl", ["restart"], Expect("value_error")),
    Case(
        "sysctl-mask",
        "helper_systemctl",
        ["mask", "fail2ban"],
        Expect("value_error"),
    ),
    Case(
        "sysctl-nginx",
        "helper_systemctl",
        ["restart", "nginx"],
        Expect("value_error"),
    ),
    Case(
        "sysctl-inject",
        "helper_systemctl",
        ["restart", "fail2ban;id"],
        Expect("value_error"),
    ),
    Case(
        "sysctl-enable-ssh",
        "helper_systemctl",
        ["enable-now", "ssh"],
        Expect("value_error"),
    ),
    *(
        Case(
            f"sysctl-meta-{i}",
            "helper_systemctl",
            ["restart", f"fail2ban{s}"],
            Expect("value_error"),
        )
        for i, s in enumerate(SHELL_METACHAR_SUFFIXES[:5])
    ),
)

SYSTEMCTL_OK_CASES: tuple[Case, ...] = (
    Case(
        "sysctl-ok-restart",
        "helper_systemctl",
        ["restart", "fail2ban"],
        Expect("ok_argv", substr="systemctl"),
    ),
)

FAIL2BAN_REJECT_CASES: tuple[Case, ...] = (
    Case("f2b-empty", "helper_fail2ban", [], Expect("value_error")),
    Case("f2b-unban-only", "helper_fail2ban", ["unban"], Expect("value_error")),
    Case(
        "f2b-unban-inject",
        "helper_fail2ban",
        ["unban", "1.2.3.4;id"],
        Expect("value_error"),
    ),
    Case(
        "f2b-unbanip-jail-only",
        "helper_fail2ban",
        ["unbanip", "sshd"],
        Expect("value_error"),
    ),
    Case(
        "f2b-unbanip-inject",
        "helper_fail2ban",
        ["unbanip", "sshd;rm", "1.2.3.4"],
        Expect("value_error"),
    ),
    Case(
        "f2b-bad-ip",
        "helper_fail2ban",
        ["unbanip", "sshd", "not-an-ip"],
        Expect("value_error"),
    ),
    Case(
        "f2b-ignore-pipe",
        "helper_fail2ban",
        ["addignoreip", "sshd", "10.0.0.1|x"],
        Expect("value_error"),
    ),
    Case("f2b-jail-start-empty", "helper_fail2ban", ["jail-start"], Expect("value_error")),
    Case(
        "f2b-jail-start-inject",
        "helper_fail2ban",
        ["jail-start", "a;b"],
        Expect("value_error"),
    ),
    Case("f2b-evil", "helper_fail2ban", ["evil"], Expect("value_error")),
)

# --- Concert abuse ---

CONCERT_ABUSE_CASES: tuple[Case, ...] = (
    Case(
        "concert-recipe-empty",
        "helper_concert",
        [],
        Expect("value_error"),
    ),
    Case(
        "concert-recipe-unknown",
        "helper_concert",
        ["--recipe=nope"],
        Expect("value_error"),
    ),
    Case(
        "concert-recipe-inject",
        "helper_concert",
        ["--recipe=setup;id"],
        Expect("value_error"),
    ),
    Case(
        "concert-recipe-blank",
        "helper_concert",
        ["--recipe="],
        Expect("value_error"),
    ),
    Case(
        "scan-plan-unknown-pack",
        "privilege_plan",
        {"packs": ["not-a-pack"], "job_id": "abcdef01-2345-6789-abcd-ef0123456789"},
        Expect("value_error"),
    ),
    Case(
        "scan-job-id-inject",
        "helper_scan_concert",
        "job;id",
        Expect("value_error"),
    ),
    Case(
        "scan-job-id-traversal",
        "helper_scan_concert",
        "../x",
        Expect("value_error"),
    ),
    Case(
        "scan-job-id-empty",
        "helper_scan_concert",
        "",
        Expect("value_error"),
    ),
    Case(
        "scan-runner-no-packs",
        "helper_scan_concert",
        ["--job-id=abcdef01-2345-6789-abcd-ef0123456789"],
        Expect("usage_exit_2"),
    ),
    Case(
        "scan-runner-bad-pack",
        "helper_scan_concert",
        [
            "--job-id=abcdef01-2345-6789-abcd-ef0123456789",
            "--pack=clamav",
        ],
        Expect("usage_exit_2"),
    ),
    Case(
        "scan-runner-bad-unhide",
        "helper_scan_concert",
        [
            "--job-id=abcdef01-2345-6789-abcd-ef0123456789",
            "--pack=unhide",
            "--unhide-mode=evil",
        ],
        Expect("usage_exit_2"),
    ),
    Case(
        "update-empty",
        "helper_update_concert",
        [],
        Expect("usage_exit_2"),
    ),
    Case(
        "install-pkg-traversal",
        "helper_fw_install",
        ("arch", ["../evil"]),
        Expect("value_error"),
    ),
    Case(
        "install-pkg-shell",
        "helper_fw_install",
        ("debian", ["ufw;id"]),
        Expect("value_error"),
    ),
    Case(
        "install-pkg-pipe",
        "helper_fw_install",
        ("fedora", ["pkg|x"]),
        Expect("value_error"),
    ),
    Case(
        "rkhunter-wl-empty",
        "helper_rkhunter_whitelist",
        [],
        Expect("value_error"),
    ),
    Case(
        "rkhunter-wl-set-incomplete",
        "helper_rkhunter_whitelist",
        ["set", "ALLOWHIDDENDIR"],
        Expect("value_error"),
    ),
    Case(
        "rkhunter-wl-set-many-no-eq",
        "helper_rkhunter_whitelist",
        ["set-many", "NOEQUALS"],
        Expect("value_error"),
    ),
    Case(
        "rkhunter-wl-weird",
        "helper_rkhunter_whitelist",
        ["weird"],
        Expect("value_error"),
    ),
    Case(
        "disclosure-only-run",
        "privilege_run",
        "install_all",
        Expect("value_error", substr="disclosure"),
    ),
)

# --- Helper argc edges ---

HELPER_ARGC_CASES: tuple[Case, ...] = (
    Case("helper-argc-empty", "oyst_helper", [], Expect("usage_exit_2")),
    Case(
        "helper-argc-unknown",
        "oyst_helper",
        ["not-a-subcommand"],
        Expect("usage_exit_2"),
    ),
    Case(
        "helper-argc-run-sealed-short",
        "oyst_helper",
        ["run-sealed", "/tmp/x"],
        Expect("usage_exit_2"),
    ),
    Case(
        "helper-argc-blank-sub",
        "oyst_helper",
        [""],
        Expect("usage_exit_2"),
    ),
)
