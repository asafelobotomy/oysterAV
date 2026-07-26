"""OystClient Shield-tab API methods (firewall + fail2ban)."""

from __future__ import annotations

from typing import Any


class OystClientShieldApi:
    """Mixin: firewall / fail2ban methods used by the Shield tab."""

    def _as_dict(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def firewall_ensure_enable(
        self,
        *,
        force_lockout_risk: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "firewall.ensure_enable",
            {
                "force_lockout_risk": force_lockout_risk,
                "dry_run": dry_run,
            },
        )

    def firewall_set_enabled(
        self,
        enabled: bool,
        *,
        force_lockout_risk: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "firewall.set_enabled",
            {
                "enabled": enabled,
                "force_lockout_risk": force_lockout_risk,
                "dry_run": dry_run,
            },
        )

    def firewall_select(
        self,
        backend: str,
        *,
        force_lockout_risk: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "firewall.select",
            {
                "backend": backend,
                "force_lockout_risk": force_lockout_risk,
                "dry_run": dry_run,
            },
        )

    def firewall_recommend(self) -> dict[str, Any]:
        return self._as_dict("firewall.recommend")

    def firewall_rules(self, *, verbose: bool = True) -> dict[str, Any]:
        return self._as_dict("firewall.rules", {"verbose": verbose})

    def firewall_export(self) -> dict[str, Any]:
        return self._as_dict("firewall.export")

    def firewall_ufw_rule(
        self,
        action: str,
        *,
        port: str | None = None,
        proto: str = "tcp",
        from_addr: str | None = None,
        rule_action: str | None = None,
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "action": action,
            "proto": proto,
            "dry_run": dry_run,
            "force_lockout_risk": force_lockout_risk,
        }
        if port is not None:
            params["port"] = port
        if from_addr is not None:
            params["from_addr"] = from_addr
        if rule_action is not None:
            params["rule_action"] = rule_action
        return self._as_dict("firewall.ufw_rule", params)

    def firewall_ufw_batch(
        self,
        rules: list[dict[str, Any]],
        *,
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "firewall.ufw_batch",
            {
                "rules": rules,
                "dry_run": dry_run,
                "force_lockout_risk": force_lockout_risk,
            },
        )

    def firewall_ufw_default(
        self,
        direction: str,
        policy: str,
        *,
        force_lockout_risk: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "firewall.ufw_default",
            {
                "direction": direction,
                "policy": policy,
                "force_lockout_risk": force_lockout_risk,
                "dry_run": dry_run,
            },
        )

    def firewall_firewalld_port(
        self,
        action: str,
        port_spec: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "firewall.firewalld_port",
            {
                "action": action,
                "port_spec": port_spec,
                "zone": zone,
                "dry_run": dry_run,
                "force_lockout_risk": force_lockout_risk,
            },
        )

    def firewall_firewalld_service(
        self,
        action: str,
        service: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "firewall.firewalld_service",
            {
                "action": action,
                "service": service,
                "zone": zone,
                "dry_run": dry_run,
                "force_lockout_risk": force_lockout_risk,
            },
        )

    def firewall_firewalld_reload(self, *, dry_run: bool = False) -> dict[str, Any]:
        return self._as_dict("firewall.firewalld_reload", {"dry_run": dry_run})

    def firewall_firewalld_rich_rule(
        self,
        action: str,
        rule: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]:
        return self._as_dict(
            "firewall.firewalld_rich_rule",
            {
                "action": action,
                "rule": rule,
                "zone": zone,
                "dry_run": dry_run,
                "force_lockout_risk": force_lockout_risk,
            },
        )

    def fail2ban_status(self) -> dict[str, Any]:
        return self._as_dict("fail2ban.status")

    def fail2ban_banned(self) -> dict[str, Any]:
        return self._as_dict("fail2ban.banned")

    def fail2ban_jail(self, name: str) -> dict[str, Any]:
        return self._as_dict("fail2ban.jail", {"name": name})

    def fail2ban_jail_enable(self, name: str) -> dict[str, Any]:
        return self._as_dict("fail2ban.jail_enable", {"name": name})

    def fail2ban_jail_disable(self, name: str) -> dict[str, Any]:
        return self._as_dict("fail2ban.jail_disable", {"name": name})

    def fail2ban_reload(self, *, unban: bool = False) -> dict[str, Any]:
        return self._as_dict("fail2ban.reload", {"unban": unban})
