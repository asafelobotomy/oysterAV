"""History finding flag patches and bulk handle-open."""

from __future__ import annotations

from typing import Any

from oyst_core.events import EventLog
from oyst_core.finding_status import MALWARE_PACKS, finding_is_open
from oyst_core.packs.rkhunter_resolve import (
    is_resolvable_threat,
    resolve_finding,
    resolve_findings_batch,
)
from oyst_core.quarantine import QuarantineVault


def patch_scan_finding(
    job_id: str,
    *,
    pack: str,
    path: str,
    threat_name: str,
    message: str = "",
    quarantined: bool | None = None,
    resolved: bool | None = None,
) -> dict[str, Any]:
    return EventLog().patch_finding(
        job_id,
        pack=pack,
        path=path,
        threat_name=threat_name,
        message=message,
        quarantined=quarantined,
        resolved=resolved,
    )


def quarantine_and_patch(
    path: str,
    threat_name: str = "",
    *,
    job_id: str | None = None,
    pack: str = "",
    message: str = "",
) -> dict[str, Any]:
    entry = QuarantineVault().add(path, threat_name)
    payload: dict[str, Any] = entry.model_dump(mode="json")
    payload["ok"] = True
    if job_id:
        patch = patch_scan_finding(
            job_id,
            pack=pack or "clamav",
            path=path,
            threat_name=threat_name or str(payload.get("threat_name") or ""),
            message=message,
            quarantined=True,
        )
        payload["history_patch"] = patch
    return payload


def resolve_and_patch(
    threat_name: str,
    *,
    path: str = "",
    message: str = "",
    force: bool = False,
    dry_run: bool = False,
    job_id: str | None = None,
    pack: str = "rkhunter",
) -> dict[str, Any]:
    result = resolve_finding(
        threat_name,
        path=path,
        message=message,
        force=force,
        dry_run=dry_run,
    )
    if result.get("ok") and job_id and not dry_run:
        patch = patch_scan_finding(
            job_id,
            pack=pack,
            path=path or "system",
            threat_name=threat_name,
            message=message,
            resolved=True,
        )
        result["history_patch"] = patch
    return result


def handle_open_findings(
    job_id: str,
    *,
    quarantine: bool = False,
    resolve: bool = False,
    force: bool = False,
) -> dict[str, Any]:
    """Quarantine and/or resolve all open actionable findings for a scan."""
    if not quarantine and not resolve:
        return {"ok": False, "error": "specify quarantine and/or resolve", "errors": []}
    scan = EventLog().get_scan(job_id)
    if scan is None:
        return {"ok": False, "error": f"scan not found: {job_id}", "errors": []}
    findings = scan.get("findings")
    if not isinstance(findings, list):
        return {"ok": False, "error": "no findings", "errors": []}

    quarantined = 0
    resolved = 0
    errors: list[str] = []
    resolve_targets: list[dict[str, Any]] = []

    for finding in findings:
        if not isinstance(finding, dict) or not finding_is_open(finding):
            continue
        pack = str(finding.get("pack") or "")
        path = str(finding.get("path") or "")
        threat = str(finding.get("threat_name") or "")
        message = str(finding.get("message") or "")

        if quarantine and pack in MALWARE_PACKS and path and path != "system":
            try:
                result = quarantine_and_patch(
                    path,
                    threat,
                    job_id=job_id,
                    pack=pack,
                    message=message,
                )
                if result.get("ok"):
                    quarantined += 1
                    finding["quarantined"] = True
                else:
                    errors.append(f"{path}: quarantine failed")
            except (OSError, FileNotFoundError, ValueError) as exc:
                errors.append(f"{path}: {exc}")

        if resolve and pack == "rkhunter" and is_resolvable_threat(threat):
            resolve_targets.append(
                {
                    "finding": finding,
                    "threat_name": threat,
                    "path": path if path != "system" else "",
                    "message": message,
                    "pack": pack,
                }
            )

    if resolve_targets:
        batch = resolve_findings_batch(
            [
                {
                    "threat_name": t["threat_name"],
                    "path": t["path"],
                    "message": t["message"],
                }
                for t in resolve_targets
            ],
            force=force,
        )
        raw_errors = batch.get("errors")
        if isinstance(raw_errors, list):
            for err in raw_errors:
                errors.append(str(err))
        # Match successful batch items back to findings by threat/path/message.
        succeeded: set[tuple[str, str, str]] = set()
        raw_items = batch.get("items")
        if not isinstance(raw_items, list):
            raw_items = []
        for item in raw_items:
            if not isinstance(item, dict) or not item.get("ok"):
                continue
            key = (
                str(item.get("threat_name") or ""),
                str(item.get("path") or ""),
                str(item.get("message") or ""),
            )
            succeeded.add(key)
        for target in resolve_targets:
            key = (
                str(target["threat_name"]),
                str(target["path"]),
                str(target["message"]),
            )
            if key not in succeeded:
                continue
            finding = target["finding"]
            if not isinstance(finding, dict):
                continue
            patch = patch_scan_finding(
                job_id,
                pack=str(target["pack"]),
                path=str(target["path"] or "system"),
                threat_name=str(target["threat_name"]),
                message=str(target["message"]),
                resolved=True,
            )
            if patch.get("ok"):
                resolved += 1
                finding["resolved"] = True
            else:
                errors.append(
                    f"{target['threat_name']}: {patch.get('error') or 'history patch failed'}"
                )

    return {
        "ok": len(errors) == 0,
        "job_id": job_id,
        "quarantined": quarantined,
        "resolved": resolved,
        "errors": errors,
    }
