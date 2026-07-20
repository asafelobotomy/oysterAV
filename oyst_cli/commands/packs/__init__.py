"""Pack-specific CLI command groups."""

from __future__ import annotations

from oyst_cli.commands.packs.clamav_cmd import clamav_group
from oyst_cli.commands.packs.clamonacc_cmd import clamonacc_group
from oyst_cli.commands.packs.fail2ban_cmd import fail2ban_group
from oyst_cli.commands.packs.firewall_cmd import firewall_group
from oyst_cli.commands.packs.lynis_cmd import lynis_group
from oyst_cli.commands.packs.maldet_cmd import maldet_group
from oyst_cli.commands.packs.rkhunter_cmd import rkhunter_group
from oyst_cli.commands.packs.signatures_cmd import (
    chkrootkit_group,
    fangfrisch_group,
    freshclam_group,
    unhide_group,
)

__all__ = [
    "chkrootkit_group",
    "clamav_group",
    "clamonacc_group",
    "fail2ban_group",
    "fangfrisch_group",
    "firewall_group",
    "freshclam_group",
    "lynis_group",
    "maldet_group",
    "rkhunter_group",
    "unhide_group",
]
