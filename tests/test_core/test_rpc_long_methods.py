"""LONG_RPC_METHODS must be a subset of registered RPC handlers."""

from __future__ import annotations

from oyst_core.rpc_handlers import RPC_METHODS
from oyst_core.rpc_io import LONG_RPC_METHODS, timeout_for_method


def test_long_rpc_methods_subset_of_handlers() -> None:
    unknown = sorted(LONG_RPC_METHODS - RPC_METHODS)
    assert unknown == [], f"LONG_RPC_METHODS not in RPC_METHODS: {unknown}"


def test_maintenance_post_update_uses_long_timeout() -> None:
    assert timeout_for_method("maintenance.post-update") > timeout_for_method("config.get")
