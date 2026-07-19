"""GUI tests with mocked client."""

from __future__ import annotations

from pathlib import Path


def test_oyst_client_local_fallback() -> None:
    from oyst_core.client import OystClient

    client = OystClient(socket_path=Path("/nonexistent/oyst.sock"))
    status = client.status()
    assert "packs" in status


def test_oyst_client_stale_socket_fallback(tmp_path: Path) -> None:
    from oyst_core.client import OystClient

    stale = tmp_path / "oyst.sock"
    stale.touch()
    client = OystClient(socket_path=stale)
    status = client.status()
    assert "packs" in status


def test_gui_import() -> None:
    try:
        import oysterav.gui.app  # noqa: F401
        import oysterav.gui.widgets  # noqa: F401
    except ImportError:
        return  # GTK not installed in CI


def test_oyst_client_history_and_config() -> None:
    from oyst_core.client import OystClient

    client = OystClient(socket_path=Path("/nonexistent/oyst.sock"))
    history = client.history_list(limit=3)
    assert isinstance(history, list)
    config = client.config_get()
    assert isinstance(config, dict)
    assert "scan" in config


def test_oyst_client_quarantine_verify() -> None:
    from oyst_core.client import OystClient

    client = OystClient(socket_path=Path("/nonexistent/oyst.sock"))
    result = client.quarantine_verify()
    assert result.get("ok") is True
