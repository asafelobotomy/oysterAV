"""System tray indicator for oysterAV (StatusNotifierItem over D-Bus).

GTK4 cannot share a process with Gtk 3 AppIndicator menus, so we implement a
minimal org.kde.StatusNotifierItem + DBusMenu for Show / Quit.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

import gi

gi.require_version("Gio", "2.0")
gi.require_version("GLib", "2.0")

from gi.repository import Gio, GLib  # noqa: E402

_logger = logging.getLogger("oyst.gui.tray")

_SNI_IFACE = "org.kde.StatusNotifierItem"
_WATCHER = "org.kde.StatusNotifierWatcher"
_WATCHER_PATH = "/StatusNotifierWatcher"
_ITEM_PATH = "/StatusNotifierItem"
_MENU_PATH = "/MenuBar"


def resolve_tray_icon_path() -> str:
    """Best-effort path to a PNG/SVG for IconThemePath / pixmap fallbacks."""
    candidates = [
        Path(__file__).resolve().parents[2] / "branding" / "oysterAV-icon.png",
        Path("/app/share/icons/hicolor/256x256/apps/oysterav.png"),
        Path.home() / ".local/share/icons/hicolor/256x256/apps/oysterav.png",
    ]
    for path in candidates:
        if path.is_file():
            return str(path)
    return "application-x-executable"


class OysterTray:
    """Session-bus StatusNotifierItem with a two-item DBusMenu."""

    def __init__(
        self,
        *,
        on_show: Callable[[], None],
        on_quit: Callable[[], None],
        title: str = "oysterAV",
    ) -> None:
        self._on_show = on_show
        self._on_quit = on_quit
        self._title = title
        self._icon_path = resolve_tray_icon_path()
        self._icon_name = "oysterav"
        self._conn: Gio.DBusConnection | None = None
        self._sni_id = 0
        self._menu_id = 0
        self._watcher_id = 0
        self._active = False

    @property
    def active(self) -> bool:
        return self._active

    def start(self) -> bool:
        try:
            self._conn = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        except GLib.Error as exc:
            _logger.warning("Tray: no session bus (%s)", exc)
            return False

        assert self._conn is not None
        node_sni = Gio.DBusNodeInfo.new_for_xml(_SNI_XML)
        node_menu = Gio.DBusNodeInfo.new_for_xml(_MENU_XML)
        try:
            self._sni_id = self._conn.register_object(
                _ITEM_PATH,
                node_sni.interfaces[0],
                self._sni_method,
                self._sni_get_property,
                None,
            )
            self._menu_id = self._conn.register_object(
                _MENU_PATH,
                node_menu.interfaces[0],
                self._menu_method,
                self._menu_get_property,
                None,
            )
        except GLib.Error as exc:
            _logger.warning("Tray: register_object failed (%s)", exc)
            self.stop()
            return False

        try:
            unique = self._conn.get_unique_name() or ""
            self._conn.call_sync(
                _WATCHER,
                _WATCHER_PATH,
                _WATCHER,
                "RegisterStatusNotifierItem",
                GLib.Variant("(s)", (unique,)),
                None,
                Gio.DBusCallFlags.NONE,
                3000,
                None,
            )
        except GLib.Error as exc:
            _logger.warning(
                "Tray: StatusNotifierWatcher unavailable (%s). "
                "Install a tray host (e.g. Ayatana indicators).",
                exc,
            )
            self.stop()
            return False

        self._active = True
        return True

    def stop(self) -> None:
        if self._conn is not None:
            if self._sni_id:
                self._conn.unregister_object(self._sni_id)
                self._sni_id = 0
            if self._menu_id:
                self._conn.unregister_object(self._menu_id)
                self._menu_id = 0
        self._conn = None
        self._active = False

    def _sni_method(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        _ = params
        if method in ("Activate", "SecondaryActivate"):
            GLib.idle_add(self._on_show)
            invocation.return_value(None)
            return
        if method == "ContextMenu":
            invocation.return_value(None)
            return
        if method == "Scroll":
            invocation.return_value(None)
            return
        invocation.return_error_literal(
            Gio.dbus_error_quark(),
            Gio.DBusError.UNKNOWN_METHOD,
            f"Unknown method {method}",
        )

    def _sni_get_property(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        prop: str,
    ) -> GLib.Variant | None:
        mapping: dict[str, Any] = {
            "Category": GLib.Variant("s", "ApplicationStatus"),
            "Id": GLib.Variant("s", "io.github.asafelobotomy.OysterAV"),
            "Title": GLib.Variant("s", self._title),
            "Status": GLib.Variant("s", "Active"),
            "WindowId": GLib.Variant("u", 0),
            "IconName": GLib.Variant("s", self._icon_name),
            "IconThemePath": GLib.Variant("s", str(Path(self._icon_path).parent)),
            "ToolTip": GLib.Variant(
                "(sa(iiay)ss)",
                (self._icon_name, [], self._title, "Show window · Quit from tray menu"),
            ),
            "ItemIsMenu": GLib.Variant("b", True),
            "Menu": GLib.Variant("o", _MENU_PATH),
        }
        return mapping.get(prop)

    def _menu_method(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        method: str,
        params: GLib.Variant,
        invocation: Gio.DBusMethodInvocation,
    ) -> None:
        if method == "GetLayout":
            parent, depth, props = params.unpack()
            _ = (parent, depth, props)
            layout = self._menu_layout()
            invocation.return_value(GLib.Variant("(u(ia{sv}av))", (0, layout)))
            return
        if method == "GetGroupProperties":
            invocation.return_value(GLib.Variant("(a(ia{sv}))", ([],)))
            return
        if method == "GetProperty":
            invocation.return_value(GLib.Variant("(v)", (GLib.Variant("s", ""),)))
            return
        if method == "Event":
            item_id, event_id, _data, _timestamp = params.unpack()
            if event_id == "clicked":
                if item_id == 1:
                    GLib.idle_add(self._on_show)
                elif item_id == 2:
                    GLib.idle_add(self._on_quit)
            invocation.return_value(None)
            return
        if method == "EventGroup":
            invocation.return_value(GLib.Variant("(ai)", ([],)))
            return
        if method == "AboutToShow":
            invocation.return_value(GLib.Variant("(b)", (False,)))
            return
        if method == "AboutToShowGroup":
            invocation.return_value(GLib.Variant("(aias)", ([], [])))
            return
        invocation.return_error_literal(
            Gio.dbus_error_quark(),
            Gio.DBusError.UNKNOWN_METHOD,
            f"Unknown method {method}",
        )

    def _menu_get_property(
        self,
        _conn: Gio.DBusConnection,
        _sender: str,
        _path: str,
        _iface: str,
        prop: str,
    ) -> GLib.Variant | None:
        if prop == "Version":
            return GLib.Variant("u", 3)
        if prop == "TextDirection":
            return GLib.Variant("s", "ltr")
        if prop == "Status":
            return GLib.Variant("s", "normal")
        if prop == "IconThemePath":
            return GLib.Variant("as", ([]))
        return None

    def _menu_layout(self) -> tuple[int, dict[str, GLib.Variant], list[GLib.Variant]]:
        def item(item_id: int, label: str) -> GLib.Variant:
            props = {
                "label": GLib.Variant("s", label),
                "type": GLib.Variant("s", "standard"),
                "enabled": GLib.Variant("b", True),
                "visible": GLib.Variant("b", True),
            }
            return GLib.Variant("(ia{sv}av)", (item_id, props, []))

        children = [
            item(1, "Show oysterAV"),
            item(2, "Quit"),
        ]
        root_props = {
            "children-display": GLib.Variant("s", "submenu"),
        }
        return (0, root_props, children)


_SNI_XML = """
<node>
  <interface name="org.kde.StatusNotifierItem">
    <method name="Activate">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="SecondaryActivate">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="ContextMenu">
      <arg type="i" name="x" direction="in"/>
      <arg type="i" name="y" direction="in"/>
    </method>
    <method name="Scroll">
      <arg type="i" name="delta" direction="in"/>
      <arg type="s" name="orientation" direction="in"/>
    </method>
    <property name="Category" type="s" access="read"/>
    <property name="Id" type="s" access="read"/>
    <property name="Title" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="WindowId" type="u" access="read"/>
    <property name="IconName" type="s" access="read"/>
    <property name="IconThemePath" type="s" access="read"/>
    <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
    <property name="ItemIsMenu" type="b" access="read"/>
    <property name="Menu" type="o" access="read"/>
  </interface>
</node>
"""

_MENU_XML = """
<node>
  <interface name="com.canonical.dbusmenu">
    <method name="GetLayout">
      <arg type="i" name="parentId" direction="in"/>
      <arg type="i" name="recursionDepth" direction="in"/>
      <arg type="as" name="propertyNames" direction="in"/>
      <arg type="u" name="revision" direction="out"/>
      <arg type="(ia{sv}av)" name="layout" direction="out"/>
    </method>
    <method name="GetGroupProperties">
      <arg type="ai" name="ids" direction="in"/>
      <arg type="as" name="propertyNames" direction="in"/>
      <arg type="a(ia{sv})" name="properties" direction="out"/>
    </method>
    <method name="GetProperty">
      <arg type="i" name="id" direction="in"/>
      <arg type="s" name="name" direction="in"/>
      <arg type="v" name="value" direction="out"/>
    </method>
    <method name="Event">
      <arg type="i" name="id" direction="in"/>
      <arg type="s" name="eventId" direction="in"/>
      <arg type="v" name="data" direction="in"/>
      <arg type="u" name="timestamp" direction="in"/>
    </method>
    <method name="EventGroup">
      <arg type="a(isvu)" name="events" direction="in"/>
      <arg type="ai" name="idErrors" direction="out"/>
    </method>
    <method name="AboutToShow">
      <arg type="i" name="id" direction="in"/>
      <arg type="b" name="needUpdate" direction="out"/>
    </method>
    <method name="AboutToShowGroup">
      <arg type="ai" name="ids" direction="in"/>
      <arg type="ai" name="updatesNeeded" direction="out"/>
      <arg type="ai" name="idErrors" direction="out"/>
    </method>
    <property name="Version" type="u" access="read"/>
    <property name="TextDirection" type="s" access="read"/>
    <property name="Status" type="s" access="read"/>
    <property name="IconThemePath" type="as" access="read"/>
  </interface>
</node>
"""


def create_tray(
    *,
    on_show: Callable[[], None],
    on_quit: Callable[[], None],
) -> OysterTray | None:
    tray = OysterTray(on_show=on_show, on_quit=on_quit)
    if tray.start():
        return tray
    return None
