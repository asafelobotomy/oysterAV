"""The Harden button's sysctl drop-in: never loosens, caller can't pick keys, revert is safe."""

from __future__ import annotations

from pathlib import Path

import pytest

from oyst_core import hardening_fix as hf


def _sysctl(root: Path, key: str, value: int) -> None:
    path = root / "proc/sys" / key.replace(".", "/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{value}\n", encoding="utf-8")


def test_values_never_loosen_and_unknown_keys_are_skipped(tmp_path: Path) -> None:
    _sysctl(tmp_path, "kernel.yama.ptrace_scope", 3)  # stricter than oysterAV's 1
    _sysctl(tmp_path, "kernel.kptr_restrict", 0)
    _sysctl(tmp_path, "fs.suid_dumpable", 2)
    values = hf.dropin_values(tmp_path)
    assert values == {
        "kernel.yama.ptrace_scope": 3,
        "kernel.kptr_restrict": 1,
        "fs.suid_dumpable": 0,
    }
    text = hf.dropin_text(tmp_path)
    assert text.startswith(hf.HEADER)
    assert "kernel.yama.ptrace_scope = 3" in text


def test_plan_lists_only_weak_settings(tmp_path: Path) -> None:
    _sysctl(tmp_path, "kernel.kptr_restrict", 0)
    _sysctl(tmp_path, "kernel.dmesg_restrict", 1)
    _sysctl(tmp_path, "net.ipv4.conf.all.rp_filter", 0)
    _sysctl(tmp_path, "net.ipv4.conf.default.rp_filter", 2)  # the kernel uses the larger
    doc = hf.harden_plan("apply", tmp_path)
    assert doc["would_refuse"] is False
    assert [c["label"] for c in doc["changes"]] == ["kernel.kptr_restrict: 0 → 1"]
    _sysctl(tmp_path, "kernel.kptr_restrict", 2)
    assert hf.harden_plan("apply", tmp_path)["would_refuse"] is True
    assert hf.harden_plan("revert", tmp_path)["would_refuse"] is True


def test_helper_writes_only_its_file_and_reverts_only_its_own(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from oyst_core.privileged import helper_sysctl as hs

    dropin = tmp_path / "90-oysterav-hardening.conf"
    calls: list[list[str]] = []
    monkeypatch.setattr(hs, "DROPIN", dropin)
    monkeypatch.setattr(hs, "dropin_text", lambda: hf.HEADER + "\nkernel.kptr_restrict = 1\n")
    monkeypatch.setattr(hs, "_sysctl", lambda args: calls.append(args) or 0)
    assert hs.run_sysctl_harden(["apply", "extra"]) == 2
    assert hs.run_sysctl_harden(["kernel.kptr_restrict=0"]) == 2
    assert hs.run_sysctl_harden(["apply"]) == 0
    assert dropin.read_text(encoding="utf-8").endswith("kernel.kptr_restrict = 1\n")
    assert calls[-1] == ["-p", str(dropin)]
    assert hs.run_sysctl_harden(["revert"]) == 0
    assert not dropin.exists()
    assert calls[-1] == ["--system"]
    dropin.write_text("someone else's file\n", encoding="utf-8")
    assert hs.run_sysctl_harden(["revert"]) == 2
    assert dropin.exists()


def test_cli_dry_run_and_helper_routing(monkeypatch: pytest.MonkeyPatch) -> None:
    import json

    from click.testing import CliRunner

    from oyst_cli.main import cli
    from oyst_core.privileged import oyst_helper

    monkeypatch.setattr(hf, "harden_plan", lambda action: hf.refused("nothing"))
    out = CliRunner().invoke(cli, ["hardening", "set", "apply", "--dry-run", "--json"])
    assert json.loads(out.output)["would_refuse"] is True
    assert CliRunner().invoke(cli, ["hardening", "set", "apply", "--json"]).exit_code != 0
    seen: list[list[str]] = []
    monkeypatch.setattr(oyst_helper, "run_sysctl_harden", lambda argv: seen.append(list(argv)) or 0)
    assert oyst_helper.run_helper_argv(["sysctl-harden", "apply"]) == 0
    assert seen == [["apply"]]
