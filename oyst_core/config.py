"""XDG configuration management.

Re-export façade — implementations live in config_models / config_io / config_access.
"""

from __future__ import annotations

from oyst_core.config_access import (
    effective_scan_backend,
    effective_schedule_backend,
    get_config_value,
    set_config_value,
    setup_status,
)
from oyst_core.config_io import (
    config_dir,
    config_path,
    data_dir,
    load_config,
    save_config,
)
from oyst_core.config_models import (
    KNOWN_FANGFRISCH_PROVIDERS,
    ApplyLimitsTo,
    ClamavConfig,
    ClamavProfile,
    ClamonaccConfig,
    FangfrischConfig,
    LynisConfig,
    MaldetMonitorConfig,
    OysterConfig,
    QuarantineConfig,
    RKHunterConfig,
    RuntimeConfig,
    RuntimeMode,
    ScanDefaults,
    ScheduleBackend,
    ScheduleConfig,
    ScheduleFrequency,
    ScheduleQuarantine,
    SetupConfig,
    UiConfig,
)

__all__ = [
    "KNOWN_FANGFRISCH_PROVIDERS",
    "ApplyLimitsTo",
    "ClamavConfig",
    "ClamavProfile",
    "ClamonaccConfig",
    "FangfrischConfig",
    "LynisConfig",
    "MaldetMonitorConfig",
    "OysterConfig",
    "QuarantineConfig",
    "RKHunterConfig",
    "RuntimeConfig",
    "RuntimeMode",
    "ScanDefaults",
    "ScheduleBackend",
    "ScheduleConfig",
    "ScheduleFrequency",
    "ScheduleQuarantine",
    "SetupConfig",
    "UiConfig",
    "config_dir",
    "config_path",
    "data_dir",
    "effective_scan_backend",
    "effective_schedule_backend",
    "get_config_value",
    "load_config",
    "save_config",
    "set_config_value",
    "setup_status",
]
