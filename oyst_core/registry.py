"""Pack registry."""

from __future__ import annotations

from oyst_core.packs.base import Pack
from oyst_core.packs.chkrootkit import ChkrootkitPack
from oyst_core.packs.clamav import ClamAVPack
from oyst_core.packs.clamonacc import ClamonaccPack
from oyst_core.packs.fail2ban import Fail2banPack
from oyst_core.packs.fangfrisch import FangfrischPack
from oyst_core.packs.firewall import FirewallPack
from oyst_core.packs.freshclam import FreshclamPack
from oyst_core.packs.lynis import LynisPack
from oyst_core.packs.maldet import MaldetPack
from oyst_core.packs.rkhunter import RKHunterPack
from oyst_core.packs.unhide import UnhidePack


class PackRegistry:
    def __init__(self) -> None:
        self._packs: dict[str, Pack] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        for pack in (
            ClamAVPack(),
            FreshclamPack(),
            ClamonaccPack(),
            FangfrischPack(),
            RKHunterPack(),
            ChkrootkitPack(),
            LynisPack(),
            MaldetPack(),
            FirewallPack(),
            Fail2banPack(),
            UnhidePack(),
        ):
            self._packs[pack.name] = pack

    def get(self, name: str) -> Pack | None:
        return self._packs.get(name)

    def all(self) -> list[Pack]:
        return list(self._packs.values())

    def names(self) -> list[str]:
        return list(self._packs.keys())


_registry: PackRegistry | None = None


def get_registry() -> PackRegistry:
    global _registry
    if _registry is None:
        _registry = PackRegistry()
    return _registry
