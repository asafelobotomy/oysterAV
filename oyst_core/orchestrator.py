"""Scan job orchestration."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from oyst_core.config import load_config
from oyst_core.events import EventLog
from oyst_core.finding_status import MALWARE_PACKS
from oyst_core.models import (
    AUDIT_ONLY_PACKS,
    PROFILE_AUDIT_PACKS,
    PROFILE_PACKS,
    PROFILE_PATHS,
    ExitCode,
    Finding,
    FindingSeverity,
    JobState,
    PackError,
    PackTier,
    ScanProfile,
    ScanResult,
)
from oyst_core.quarantine import QuarantineVault
from oyst_core.registry import get_registry


class JobOrchestrator:
    def __init__(self, events: EventLog | None = None) -> None:
        self.events = events or EventLog()
        self.registry = get_registry()

    def _resolve_paths(self, profile: ScanProfile, paths: list[str] | None) -> list[str]:
        if paths:
            return [str(Path(p).expanduser()) for p in paths]
        defaults = PROFILE_PATHS.get(profile, ["~"])
        return [str(Path(p).expanduser()) for p in defaults]

    def _resolve_packs(self, profile: ScanProfile, packs: list[str] | None) -> list[str]:
        if packs:
            return packs
        return PROFILE_PACKS.get(profile, ["clamav"])

    def _split_path_and_audit_packs(
        self,
        profile: ScanProfile,
        packs: list[str] | None,
    ) -> tuple[list[str], list[str]]:
        """Separate path-scan packs from audit-only packs (e.g. lynis).

        Explicit ``--packs`` / custom selections may include lynis; it must run
        via audit(), never empty scan_paths().
        """
        resolved = self._resolve_packs(profile, packs)
        path_names: list[str] = []
        audit_names = list(PROFILE_AUDIT_PACKS.get(profile, []))
        for name in resolved:
            if name in AUDIT_ONLY_PACKS:
                if name not in audit_names:
                    audit_names.append(name)
            else:
                path_names.append(name)
        return path_names, audit_names

    def run_scan(
        self,
        *,
        profile: ScanProfile = ScanProfile.QUICK,
        paths: list[str] | None = None,
        packs: list[str] | None = None,
        backend: str = "auto",
        quarantine: bool = False,
        on_progress: Callable[[str, float], None] | None = None,
    ) -> tuple[ScanResult, ExitCode]:
        job_id = str(uuid.uuid4())
        if not self.events.acquire_job_lock(job_id):
            result = ScanResult(
                job_id=job_id,
                profile=profile,
                paths=[],
                started_at=datetime.now(),
            )
            result.pack_errors.append(PackError(pack="orchestrator", error="job already running"))
            return result, ExitCode.JOB_BUSY

        try:
            pack_names, audit_names = self._split_path_and_audit_packs(profile, packs)
            scan_paths = self._resolve_paths(profile, paths)
            result = ScanResult(
                job_id=job_id,
                profile=profile,
                paths=scan_paths,
                started_at=datetime.now(),
            )
            self.events.log("scan", f"started {profile.value}", {"job_id": job_id})
            self._emit_progress(
                job_id,
                pack="",
                message="Starting",
                percent=0.0,
                state="running",
                on_progress=on_progress,
            )

            total = len(pack_names) + len(audit_names)
            for idx, name in enumerate(pack_names):
                if self.events.cancel_requested():
                    result.finalize()
                    result.state = JobState.CANCELLED
                    self.events.log("scan", "cancelled", {"job_id": job_id})
                    self.events.save_scan(result.model_dump(mode="json"))
                    self._emit_progress(
                        job_id,
                        pack=name,
                        message="Cancelled",
                        percent=(idx / max(total, 1)) * 100,
                        state="cancelled",
                        on_progress=on_progress,
                    )
                    return result, ExitCode.ERROR
                pack = self.registry.get(name)
                if pack is None:
                    result.pack_errors.append(PackError(pack=name, error="unknown pack"))
                    continue
                status = pack.doctor()
                if not status.installed:
                    if status.tier == PackTier.REQUIRED:
                        result.pack_errors.append(
                            PackError(
                                pack=name,
                                error=f"required pack missing: {status.install_hint}",
                            )
                        )
                        result.finalize()
                        self._emit_progress(
                            job_id,
                            pack=name,
                            message=f"Missing required pack: {name}",
                            percent=(idx / max(total, 1)) * 100,
                            state="failed",
                            on_progress=on_progress,
                        )
                        return result, ExitCode.PACK_MISSING
                    result.pack_errors.append(
                        PackError(pack=name, error="optional pack not installed")
                    )
                    continue
                pct = (idx / max(total, 1)) * 100
                self._emit_progress(
                    job_id,
                    pack=name,
                    message=f"Running {name}",
                    percent=pct,
                    state="running",
                    on_progress=on_progress,
                )
                try:
                    findings = pack.scan_paths(scan_paths, backend=backend, profile=profile.value)
                    result.findings.extend(findings)
                except Exception as exc:  # noqa: BLE001 — pack boundary
                    result.pack_errors.append(PackError(pack=name, error=str(exc)))
                self._emit_progress(
                    job_id,
                    pack=name,
                    message=f"Finished {name}",
                    percent=((idx + 1) / max(total, 1)) * 100,
                    state="running",
                    on_progress=on_progress,
                )

            for offset, name in enumerate(audit_names):
                if self.events.cancel_requested():
                    result.finalize()
                    result.state = JobState.CANCELLED
                    self.events.log("scan", "cancelled", {"job_id": job_id})
                    self.events.save_scan(result.model_dump(mode="json"))
                    self._emit_progress(
                        job_id,
                        pack=name,
                        message="Cancelled",
                        percent=((len(pack_names) + offset) / max(total, 1)) * 100,
                        state="cancelled",
                        on_progress=on_progress,
                    )
                    return result, ExitCode.ERROR
                pack = self.registry.get(name)
                if pack is None:
                    result.pack_errors.append(PackError(pack=name, error="unknown pack"))
                    continue
                status = pack.doctor()
                if not status.installed:
                    result.pack_errors.append(
                        PackError(pack=name, error="optional pack not installed")
                    )
                    continue
                pct = ((len(pack_names) + offset) / max(total, 1)) * 100
                self._emit_progress(
                    job_id,
                    pack=name,
                    message=f"Running {name}",
                    percent=pct,
                    state="running",
                    on_progress=on_progress,
                )
                try:
                    result.findings.extend(self._run_audit_pack(pack))
                except Exception as exc:  # noqa: BLE001 — pack boundary
                    result.pack_errors.append(PackError(pack=name, error=str(exc)))
                self._emit_progress(
                    job_id,
                    pack=name,
                    message=f"Finished {name}",
                    percent=((len(pack_names) + offset + 1) / max(total, 1)) * 100,
                    state="running",
                    on_progress=on_progress,
                )

            if quarantine or load_config().quarantine.auto:
                self._quarantine_findings(result)

            result.finalize()
            self.events.save_scan(result.model_dump(mode="json"))
            self.events.log(
                "scan",
                f"finished {profile.value}",
                {"job_id": job_id, "clean": result.clean},
            )
            self._emit_progress(
                job_id,
                pack="",
                message="Completed",
                percent=100.0,
                state="completed",
                on_progress=on_progress,
            )
            code = ExitCode.SUCCESS if result.clean else ExitCode.THREATS_FOUND
            if result.pack_errors and not result.findings:
                required_failed = any(
                    ((p := self.registry.get(e.pack)) is not None and p.tier == PackTier.REQUIRED)
                    for e in result.pack_errors
                )
                if required_failed:
                    code = ExitCode.PACK_MISSING
                elif code == ExitCode.SUCCESS:
                    code = ExitCode.ERROR
            return result, code
        finally:
            self.events.release_job_lock(job_id)

    def _emit_progress(
        self,
        job_id: str,
        *,
        pack: str,
        message: str,
        percent: float,
        state: str,
        on_progress: Callable[[str, float], None] | None,
    ) -> None:
        self.events.set_job_progress(
            job_id,
            pack=pack,
            message=message,
            percent=percent,
            state=state,
        )
        if on_progress is not None:
            on_progress(pack or message, percent)

    def _run_audit_pack(self, pack: object) -> list[Finding]:
        """Run audit-only packs (e.g. lynis) and map results to findings."""
        audit = getattr(pack, "audit", None)
        if not callable(audit):
            return []
        quick = load_config().lynis.quick
        ok, output, score = audit(quick=quick)
        pack_name = str(getattr(pack, "name", "audit"))
        if not ok and "not installed" in str(output):
            return []
        message = "Hardening audit completed"
        if score is not None:
            message = f"Hardening index: {score}"
        severity = FindingSeverity.INFO
        if isinstance(score, int) and score < 65:
            severity = FindingSeverity.MEDIUM
        return [
            Finding(
                pack=pack_name,
                path="system",
                threat_name=f"hardening-index:{score}" if score is not None else "hardening-audit",
                severity=severity,
                message=message,
                raw_line=str(output)[:500],
            ),
        ]

    def _quarantine_findings(self, result: ScanResult) -> None:
        vault = QuarantineVault()
        for finding in result.findings:
            if finding.pack not in MALWARE_PACKS:
                continue
            if finding.path and finding.path != "system" and Path(finding.path).exists():
                try:
                    vault.add(finding.path, finding.threat_name)
                    finding.quarantined = True
                except (OSError, FileNotFoundError):
                    pass

    def cancel_job(self, job_id: str | None = None) -> dict[str, object]:
        """Request cooperative cancel of the active scan job."""
        active = self.events.active_job()
        if not active:
            return {"ok": False, "cancelled": False, "message": "no active job", "job_id": None}
        if job_id is not None and job_id != active:
            return {
                "ok": False,
                "cancelled": False,
                "message": f"active job is {active}, not {job_id}",
                "job_id": active,
            }
        requested = self.events.request_cancel(active)
        return {
            "ok": requested,
            "cancelled": requested,
            "message": "cancel requested" if requested else "failed to request cancel",
            "job_id": active,
        }

    def job_status(self) -> dict[str, object]:
        """Return live progress for the active scan job (if any)."""
        return self.events.get_job_progress()

    def aggregate_status(self) -> dict[str, object]:
        from oyst_core.doctor_cache import doctor_all
        from oyst_core.packs.clamav import ClamAVPack
        from oyst_core.packs.clamonacc import ClamonaccPack
        from oyst_core.packs.freshclam import FreshclamPack

        packs = doctor_all()
        clam = ClamAVPack()
        fresh = FreshclamPack()
        cfg = load_config()
        clamonacc = ClamonaccPack()
        # oysterAV never writes OnAccessPrevention into clamd.conf.
        prevention_enforced = False
        history = self.events.history(limit=1)
        last = history[0]["started_at"] if history else None
        return {
            "packs": packs,
            "clamd_running": clam.clamd_running(),
            "signature_age_hours": fresh.signature_age_hours(),
            "last_scan_at": last,
            "active_job": self.events.active_job(),
            "clamonacc_prevention_requested": cfg.clamonacc.prevention,
            "clamonacc_prevention_enforced": prevention_enforced,
            "clamonacc_uses_distro_unit": clamonacc._systemd_unit() is not None,
            "fangfrisch_providers": list(cfg.fangfrisch.providers),
            "scan_backend": cfg.scan.backend,
        }
