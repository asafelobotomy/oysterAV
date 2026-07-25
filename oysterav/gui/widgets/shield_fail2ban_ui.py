"""Shield fail2ban jail / ban list UI helpers."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw  # noqa: E402

from oysterav.gui.widgets.common import make_button

if TYPE_CHECKING:
    from oysterav.gui.widgets.shield import ShieldPage


def rebuild_jail_rows(
    page: ShieldPage,
    jails: list[str],
    *,
    on_enable: Callable[[str], None],
    on_disable: Callable[[str], None],
) -> None:
    for row in page._jail_rows:
        page._f2b_group.remove(row)
    page._jail_rows.clear()
    for name in jails:
        row = Adw.ActionRow(title=name)
        en = make_button("Enable", row_suffix=True)
        en.connect("clicked", lambda *_a, n=name: on_enable(n))
        dis = make_button("Disable", row_suffix=True)
        dis.connect("clicked", lambda *_a, n=name: on_disable(n))
        row.add_suffix(en)
        row.add_suffix(dis)
        page._f2b_group.add(row)
        page._jail_rows.append(row)


def rebuild_ban_rows(
    page: ShieldPage,
    jails: dict[str, Any],
    *,
    on_unban: Callable[[str, str | None], None],
) -> None:
    for row in page._ban_rows:
        page._bans_group.remove(row)
    page._ban_rows.clear()
    total = 0
    for jail, ips in jails.items():
        if not isinstance(ips, list):
            continue
        for ip in ips:
            total += 1
            ip_s = str(ip)
            row = Adw.ActionRow(title=ip_s, subtitle=f"Jail: {jail}")
            btn = make_button("Unban", row_suffix=True)
            btn.connect("clicked", lambda *_a, i=ip_s, j=str(jail): on_unban(i, j))
            row.add_suffix(btn)
            page._bans_group.add(row)
            page._ban_rows.append(row)
    page._bans_status.set_subtitle(f"{total} banned address(es)" if total else "No bans")
