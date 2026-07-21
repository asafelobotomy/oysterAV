"""Route systemctl helper calls to systemctl-up vs systemctl."""

from __future__ import annotations

from oyst_core.audit import SecurityAudit
from oyst_core.privileged.auth_grant_scope import is_passwordless_systemctl
from oyst_core.privileged.helper import run_privileged_helper
from oyst_core.privileged.runner import CommandResult


def run_systemctl_helper(action: str, unit: str) -> CommandResult:
    """Use systemctl-up for AV start/enable/restart; otherwise passworded systemctl."""
    if is_passwordless_systemctl(action, unit):
        res = run_privileged_helper("systemctl-up", [action, unit])
        SecurityAudit().log(
            "auth.passwordless",
            f"{action} {unit}",
            success=res.returncode == 0,
            data={"helper": "systemctl-up", "action": action, "unit": unit},
        )
        return res
    return run_privileged_helper("systemctl", [action, unit])
