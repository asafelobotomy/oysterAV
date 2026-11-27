"""Parse maldet console lines and session.hits into oysterAV findings."""

from __future__ import annotations

import re
from pathlib import Path

from oyst_core.models import Finding, FindingSeverity
from oyst_core.runtime.manifest import is_full_mode, runtime_maldet_prefix
from oyst_core.schedule_linger import current_username

# maldet(123): {hit} malware hit {CAV}SigName found for /path/to/file
_HIT_LINE_RE = re.compile(
    r"\{hit\}\s+malware hit\s+(\S+)\s+found for\s+(\S+)",
    re.IGNORECASE,
)
# session.hits: {CAV}Sig : /path  OR  Sig : /path  OR  Sig : /path => /quar/...
_SESSION_HIT_RE = re.compile(
    r"^(\{[A-Z]+\}[^\s:]+|[^\s:]+)\s*:\s+(\S+?)(?:\s*=>.*)?\s*$",
)

_PACK = "maldet"


def parse_hit_console_line(line: str) -> Finding | None:
    """Parse a single console/event_log line; accept only real {hit} shapes."""
    stripped = line.strip()
    if not stripped:
        return None
    lowered = stripped.lower()
    if re.match(r"^linux malware detect\b", lowered):
        return None
    if "{scan}" in lowered or "{mon}" in lowered or "{quar}" in lowered:
        return None
    if "{sigup}" in lowered or "{update}" in lowered:
        return None
    match = _HIT_LINE_RE.search(stripped)
    if not match:
        return None
    threat = match.group(1).strip()
    path = _normalize_path(match.group(2))
    if not path:
        return None
    return Finding(
        pack=_PACK,
        path=path,
        threat_name=threat or "maldet-detection",
        severity=FindingSeverity.HIGH,
        message=f"maldet hit: {threat} @ {path}",
        raw_line=line,
    )


def parse_session_hit_line(line: str) -> Finding | None:
    """Parse one line from session.hits.<id>."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = _SESSION_HIT_RE.match(stripped)
    if not match:
        return None
    threat = match.group(1).strip()
    path = _normalize_path(match.group(2))
    if not path or not (path.startswith("/") or path.startswith("~")):
        return None
    if threat.lower() in {"host", "scan", "path", "total", "started", "completed"}:
        return None
    return Finding(
        pack=_PACK,
        path=path,
        threat_name=threat or "maldet-detection",
        severity=FindingSeverity.HIGH,
        message=f"maldet hit: {threat} @ {path}",
        raw_line=line,
    )


def maldet_abort_reason(output: str) -> str:
    """LMD's own "... aborting!" line (missing signatures, bad path): it still exits 0."""
    for line in (output or "").splitlines():
        if "aborting" in line.lower() and "{" in line:
            return re.sub(r"^.*?\}\s*", "", line.strip())[:300]
    return ""


def parse_console_output(output: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in output.splitlines():
        hit = parse_hit_console_line(line)
        if hit is not None:
            findings.append(hit)
    return findings


def parse_session_hits_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in text.splitlines():
        hit = parse_session_hit_line(line)
        if hit is not None:
            findings.append(hit)
    return findings


def merge_findings(primary: list[Finding], secondary: list[Finding]) -> list[Finding]:
    """Union by (path, threat_name); primary wins on conflict."""
    seen: dict[tuple[str, str], Finding] = {}
    for f in secondary:
        seen[(f.path, f.threat_name)] = f
    for f in primary:
        seen[(f.path, f.threat_name)] = f
    return list(seen.values())


def _normalize_path(raw: str) -> str | None:
    cleaned = raw.strip().strip("\",'")
    while cleaned.endswith(":"):
        cleaned = cleaned[:-1]
    if not cleaned:
        return None
    if not (cleaned.startswith("/") or cleaned.startswith("~")):
        return None
    return str(Path(cleaned).expanduser())


def maldet_inspath(binary: str | None) -> Path | None:
    if not binary:
        return None
    return Path(binary).resolve().parent


def maldet_user_pub_dir(binary: str | None) -> Path | None:
    """Return pub/<user> for the active install (runtime or system)."""
    inspath = maldet_inspath(binary)
    if inspath is None:
        return None
    user = current_username()
    pub_user = inspath / "pub" / user
    if pub_user.is_dir():
        return pub_user
    if is_full_mode():
        runtime_pub = runtime_maldet_prefix() / "pub" / user
        if runtime_pub.is_dir():
            return runtime_pub
    return pub_user if (inspath / "pub").is_dir() else None


def maldet_event_log_path(binary: str | None) -> Path:
    pub = maldet_user_pub_dir(binary)
    if pub is not None:
        return pub / "event_log"
    return Path("/usr/local/maldetect/logs/event_log")


def maldet_sess_dir(binary: str | None) -> Path | None:
    pub = maldet_user_pub_dir(binary)
    if pub is None:
        return None
    return pub / "sess"


def parse_session_tsv_text(text: str) -> list[Finding]:
    """Parse LMD 2.x ``session.tsv.<id>``: a ``#LMD:`` header, then one hit per line.

    Hit fields (tab-separated): signature, path, quarantine path or ``-``, hash type, ...
    """
    findings: list[Finding] = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        threat = fields[0].strip()
        path = _normalize_path(fields[1])
        if not threat or not path:
            continue
        findings.append(
            Finding(
                pack=_PACK,
                path=path,
                threat_name=threat,
                severity=FindingSeverity.HIGH,
                message=f"maldet hit: {threat} @ {path}",
                raw_line=line,
            )
        )
    return findings


def _session_last_id(sess_dir: Path) -> str:
    last = sess_dir / "session.last"
    if not last.is_file():
        return ""
    try:
        text = last.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""
    # LMD 1.x writes the scan id; keep only a plausible id (no path parts).
    return text if text and "/" not in text and len(text) < 64 else ""


_REPORT_ID_RE = re.compile(r"maldet --report ([0-9]{6}-[0-9]{4}\.[0-9]+)")


def scan_id_from_output(output: str) -> str:
    """The scan id LMD prints at the end of a scan (``... run: maldet --report ID``)."""
    match = _REPORT_ID_RE.search(output or "")
    return match.group(1) if match else ""


def resolve_session_hits_file(sess_dir: Path, scan_id: str = "") -> Path | None:
    """The scan's hits: ``session.tsv.<id>`` (LMD 2.x) or ``session.hits.<id>`` (1.x).

    Prefer ``scan_id`` (from the scan's own output), then the id in ``session.last``,
    else the newest of either kind.
    """
    scan_id = scan_id or _session_last_id(sess_dir)
    if scan_id:
        for name in (f"session.tsv.{scan_id}", f"session.hits.{scan_id}"):
            candidate = sess_dir / name
            if candidate.is_file():
                return candidate
    hits = sorted(
        (
            p
            for pattern in ("session.tsv.*", "session.hits.*")
            for p in sess_dir.glob(pattern)
            if p.is_file()
        ),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return hits[0] if hits else None


def load_session_hit_findings(binary: str | None, scan_id: str = "") -> list[Finding]:
    sess = maldet_sess_dir(binary)
    if sess is None or not sess.is_dir():
        return []
    hits_file = resolve_session_hits_file(sess, scan_id)
    if hits_file is None:
        return []
    try:
        text = hits_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if hits_file.name.startswith("session.tsv."):
        return parse_session_tsv_text(text)
    return parse_session_hits_text(text)


_SYSTEM_MALDET_PREFIXES = ("/usr/local/maldetect",)


def _real(path: str | Path) -> Path:
    try:
        return Path(path).expanduser().resolve()
    except (OSError, RuntimeError):
        return Path(path).expanduser()


def maldet_install_prefixes() -> list[Path]:
    """Real LMD install roots (system + oysterAV runtime); never path components."""
    roots = [_real(p) for p in _SYSTEM_MALDET_PREFIXES]
    try:
        roots.append(_real(runtime_maldet_prefix()))
    except (OSError, RuntimeError, ValueError):
        pass
    return roots


def is_maldet_self_signature_path(path: str) -> bool:
    """True only for LMD's own sigs under a real install root (not any */maldetect/sigs/*)."""
    resolved = _real(path)
    return any(resolved.is_relative_to(root / "sigs") for root in maldet_install_prefixes())


def filter_malware_findings(findings: list[Finding]) -> list[Finding]:
    """Drop self-signature FPs from malware findings list."""
    return [f for f in findings if not is_maldet_self_signature_path(f.path)]
