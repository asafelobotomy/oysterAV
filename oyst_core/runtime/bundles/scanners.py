"""Non-ClamAV scanner runtime bundles (re-export façade)."""

from __future__ import annotations

from oyst_core.runtime.bundles.fangfrisch_bundle import install_fangfrisch_runtime
from oyst_core.runtime.bundles.lynis_bundle import (
    install_lynis_runtime,
    install_maldet_runtime_tree,
)
from oyst_core.runtime.bundles.rootkit_bundles import (
    install_chkrootkit_runtime,
    install_rkhunter_runtime,
    install_unhide_runtime,
)

__all__ = [
    "install_chkrootkit_runtime",
    "install_fangfrisch_runtime",
    "install_lynis_runtime",
    "install_maldet_runtime_tree",
    "install_rkhunter_runtime",
    "install_unhide_runtime",
]
