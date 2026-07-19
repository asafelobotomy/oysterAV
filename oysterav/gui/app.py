"""GTK application."""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gdk", "4.0")
gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")

from gi.repository import Adw, Gdk, GLib, Gtk  # noqa: E402

from oyst_core.client import OystClient
from oyst_core.config import load_config
from oyst_core.serve import ensure_rpc_server
from oysterav.gui.tray import OysterTray, create_tray
from oysterav.gui.theme import apply_theme
from oysterav.gui.widgets import (
    DashboardPage,
    QuarantinePage,
    ReportsPage,
    ScanPage,
    SettingsPage,
)
from oysterav.gui.widgets.common import run_in_thread, show_command_dialog
from oysterav.gui.widgets.setup_wizard import SetupWizard, should_show_wizard
from oysterav.gui.widgets.status_bar import StatusBar

_ICON_NAME = "oysterav"


def _branding_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "branding"


def install_default_app_icon() -> None:
    """Register theme name oysterav; add checkout branding/ for unpackaged runs."""
    branding = _branding_dir()
    display = Gdk.Display.get_default()
    if display is not None and branding.is_dir():
        theme = Gtk.IconTheme.get_for_display(display)
        theme.add_search_path(str(branding))
    Gtk.Window.set_default_icon_name(_ICON_NAME)


class OysterApp(Adw.Application):
    def __init__(self, *, start_minimized: bool = False) -> None:
        super().__init__(application_id="io.github.asafelobotomy.OysterAV")
        self.client = OystClient()
        self._start_minimized_flag = start_minimized
        self._window: OysterWindow | None = None
        self._tray: OysterTray | None = None

    def do_activate(self) -> None:
        cfg = load_config()
        apply_theme(cfg.ui.theme)
        install_default_app_icon()
        self._ensure_serve()
        if self._window is not None:
            self._window.present_from_tray()
            return

        win = OysterWindow(application=self, client=self.client)
        self._window = win
        self._setup_tray(win)

        minimized = self._start_minimized_flag or cfg.ui.start_minimized
        if minimized and self._tray is not None and self._tray.active:
            win.present()
            win.hide_to_tray()
        else:
            win.present()
            if minimized and (self._tray is None or not self._tray.active):
                win.set_status("Start minimized requested but tray is unavailable")

    def _setup_tray(self, win: OysterWindow) -> None:
        self._tray = create_tray(
            on_show=win.present_from_tray,
            on_quit=self.quit_from_tray,
        )
        win.bind_tray(self._tray)

    def quit_from_tray(self) -> None:
        if self._tray is not None:
            self._tray.stop()
            self._tray = None
        self.quit()

    def _ensure_serve(self) -> None:
        ensure_rpc_server()


class OysterWindow(Adw.ApplicationWindow):
    def __init__(self, *, application: Adw.Application, client: OystClient) -> None:
        super().__init__(application=application, title="oysterAV")
        self.client = client
        self._tray: OysterTray | None = None
        self.set_icon_name(_ICON_NAME)
        self.set_default_size(960, 700)

        self.stack = Adw.ViewStack()
        self.stack.set_hexpand(True)
        self.stack.set_vexpand(True)
        self.stack.set_enable_transitions(False)

        self.dashboard = DashboardPage(
            client,
            on_navigate=self._navigate,
            on_status=self._set_status,
        )
        self.dashboard.set_window(self)
        self.scan = ScanPage(
            client,
            window=self,
            on_status=self._set_status,
            on_scan_complete=self._on_scan_complete,
        )
        self.reports = ReportsPage(
            client,
            window=self,
            on_status=self._set_status,
        )
        self.quarantine = QuarantinePage(
            client,
            window=self,
            on_status=self._set_status,
        )
        self.settings = SettingsPage(
            client,
            window=self,
            on_status=self._set_status,
            on_setup_wizard=self.present_setup_wizard,
            on_security_news_changed=self._on_security_news_changed,
            on_updates_changed=self._on_updates_changed,
        )

        self.stack.add_titled_with_icon(
            self.dashboard.widget,
            "dashboard",
            "Dashboard",
            "security-high-symbolic",
        )
        self.stack.add_titled_with_icon(
            self.scan.widget,
            "scan",
            "Scan",
            "system-search-symbolic",
        )
        self.stack.add_titled_with_icon(
            self.reports.widget,
            "reports",
            "Reports",
            "document-open-recent-symbolic",
        )
        self.stack.add_titled_with_icon(
            self.quarantine.widget,
            "quarantine",
            "Quarantine",
            "dialog-password-symbolic",
        )
        self.stack.add_titled_with_icon(
            self.settings.widget,
            "settings",
            "Settings",
            "preferences-system-symbolic",
        )

        self.stack.connect("notify::visible-child", self._on_tab_changed)

        switcher = Adw.ViewSwitcher()
        switcher.set_stack(self.stack)
        switcher.set_policy(Adw.ViewSwitcherPolicy.WIDE)

        header = Adw.HeaderBar()
        header.set_title_widget(switcher)

        self.status_bar = StatusBar(
            load_headlines=lambda: self.client.news_list(),
            load_updates=lambda: self.client.updates_check(),
            news_enabled=lambda: bool(load_config().ui.security_news),
        )

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        content.append(self.status_bar)
        content.append(self.stack)
        content.set_vexpand(True)

        toolbar_view = Adw.ToolbarView()
        toolbar_view.add_top_bar(header)
        toolbar_view.set_content(content)
        self.set_content(toolbar_view)

        self.connect("close-request", self._on_close_request)
        GLib.idle_add(self._initial_load)
        # Re-check package updates periodically while the GUI is open.
        GLib.timeout_add_seconds(30 * 60, self._periodic_updates_check)

    def bind_tray(self, tray: OysterTray | None) -> None:
        self._tray = tray

    def hide_to_tray(self) -> None:
        self.set_visible(False)

    def present_from_tray(self) -> None:
        self.set_visible(True)
        self.present()

    def _on_close_request(self, *_args: object) -> bool:
        cfg = load_config()
        if cfg.ui.minimize_to_tray and self._tray is not None and self._tray.active:
            self.hide_to_tray()
            return True
        if hasattr(self.get_application(), "quit_from_tray"):
            app = self.get_application()
            if isinstance(app, OysterApp):
                app.quit_from_tray()
                return True
        return False

    def set_status(self, text: str) -> None:
        self.status_bar.set_status(text)

    def _set_status(self, text: str) -> None:
        self.set_status(text)

    def _on_security_news_changed(self) -> None:
        self.status_bar.refresh_news()
        self.status_bar.refresh_updates()

    def _on_updates_changed(self) -> None:
        self.status_bar.refresh_updates()

    def _periodic_updates_check(self) -> bool:
        self.status_bar.refresh_updates()
        return True

    def _navigate(
        self,
        tab: str,
        *,
        job_id: str | None = None,
        section: str | None = None,
    ) -> None:
        if tab == "reports" and job_id:
            self.reports.focus_job(job_id)
        if tab == "settings":
            self.settings.show_section(section)
        self.stack.set_visible_child_name(tab)

    def _initial_load(self) -> bool:
        # Only refresh the visible Dashboard (+ news). Other tabs
        # refresh on first tab selection via _handle_tab_changed.
        self.dashboard.refresh()
        self.status_bar.refresh_news()
        self.status_bar.refresh_updates()
        run_in_thread(
            lambda: should_show_wizard(self.client),
            self._maybe_present_wizard,
            lambda _message: False,
        )
        return False

    def _maybe_present_wizard(self, show: object) -> bool:
        if show:
            self.present_setup_wizard()
        return False

    def present_setup_wizard(self) -> None:
        try:
            wizard = SetupWizard(
                self.client,
                window=self,
                on_complete=self._refresh_shell,
                on_changed=self._refresh_shell,
                on_navigate=self._navigate,
                on_status=self._set_status,
            )
            wizard.present()
        except Exception as exc:  # noqa: BLE001 — GUI boundary
            self._set_status(f"Setup wizard failed: {exc}")
            show_command_dialog(
                self,
                heading="Could not open setup wizard",
                body=str(exc),
                copy_text="oyst-cli setup run",
            )

    def _refresh_shell(self) -> None:
        self.dashboard.refresh()
        self.settings.refresh()
        self.scan.refresh()
        self.status_bar.refresh_news()
        self.status_bar.refresh_updates()

    def _on_tab_changed(self, _stack: Adw.ViewStack, _pspec: object) -> None:
        GLib.idle_add(self._handle_tab_changed)

    def _handle_tab_changed(self) -> bool:
        tab = self.stack.get_visible_child_name()
        if tab == "quarantine":
            self.quarantine.refresh()
        elif tab == "reports":
            self.reports.refresh()
        elif tab == "dashboard":
            self.dashboard.refresh()
        elif tab == "settings":
            self.settings.refresh()
        elif tab == "scan":
            self.scan.refresh()
        return False

    def _on_scan_complete(self) -> None:
        self.quarantine.refresh()
        self.reports.refresh()
        self.dashboard.refresh()
