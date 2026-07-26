"""GUI RPC wrappers for Shield tab (firewall + fail2ban)."""

from __future__ import annotations

from typing import Any, Protocol


class SupportsShieldClient(Protocol):
    def firewall_status(self) -> dict[str, Any]: ...
    def firewall_ensure_enable(
        self,
        *,
        force_lockout_risk: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]: ...
    def firewall_set_enabled(
        self,
        enabled: bool,
        *,
        force_lockout_risk: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]: ...
    def firewall_select(
        self,
        backend: str,
        *,
        force_lockout_risk: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]: ...
    def firewall_recommend(self) -> dict[str, Any]: ...
    def firewall_rules(self, *, verbose: bool = True) -> dict[str, Any]: ...
    def firewall_export(self) -> dict[str, Any]: ...
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
    ) -> dict[str, Any]: ...
    def firewall_ufw_batch(
        self,
        rules: list[dict[str, Any]],
        *,
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]: ...
    def firewall_ufw_default(
        self,
        direction: str,
        policy: str,
        *,
        force_lockout_risk: bool = False,
        dry_run: bool = False,
    ) -> dict[str, Any]: ...
    def firewall_firewalld_port(
        self,
        action: str,
        port_spec: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]: ...
    def firewall_firewalld_service(
        self,
        action: str,
        service: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]: ...
    def firewall_firewalld_reload(self, *, dry_run: bool = False) -> dict[str, Any]: ...
    def firewall_firewalld_rich_rule(
        self,
        action: str,
        rule: str,
        *,
        zone: str = "public",
        dry_run: bool = False,
        force_lockout_risk: bool = False,
    ) -> dict[str, Any]: ...
    def fail2ban_status(self) -> dict[str, Any]: ...
    def fail2ban_banned(self) -> dict[str, Any]: ...
    def fail2ban_jail(self, name: str) -> dict[str, Any]: ...
    def fail2ban_unban(
        self,
        ip: str,
        *,
        jail: str | None = None,
        ignore: bool = False,
        persist: bool = False,
    ) -> dict[str, Any]: ...
    def fail2ban_jail_enable(self, name: str) -> dict[str, Any]: ...
    def fail2ban_jail_disable(self, name: str) -> dict[str, Any]: ...
    def fail2ban_reload(self, *, unban: bool = False) -> dict[str, Any]: ...
    def services_status(self) -> dict[str, Any]: ...
    def services_set(self, name: str, state: str, *, boot: bool = False) -> dict[str, Any]: ...


def request_firewall_ensure_enable(
    client: SupportsShieldClient,
    *,
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_ensure_enable(force_lockout_risk=force_lockout_risk)


def request_firewall_set_enabled(
    client: SupportsShieldClient,
    enabled: bool,
    *,
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_set_enabled(enabled, force_lockout_risk=force_lockout_risk)


def request_firewall_select(
    client: SupportsShieldClient,
    backend: str,
    *,
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_select(backend, force_lockout_risk=force_lockout_risk)


def request_firewall_recommend(client: SupportsShieldClient) -> dict[str, Any]:
    return client.firewall_recommend()


def request_firewall_rules(client: SupportsShieldClient) -> dict[str, Any]:
    return client.firewall_rules(verbose=True)


def request_firewall_export(client: SupportsShieldClient) -> dict[str, Any]:
    return client.firewall_export()


def request_firewall_ufw_rule(
    client: SupportsShieldClient,
    action: str,
    *,
    port: str | None = None,
    proto: str = "tcp",
    from_addr: str | None = None,
    rule_action: str | None = None,
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_ufw_rule(
        action,
        port=port,
        proto=proto,
        from_addr=from_addr,
        rule_action=rule_action,
        force_lockout_risk=force_lockout_risk,
    )


def request_firewall_ufw_batch(
    client: SupportsShieldClient,
    rules: list[dict[str, Any]],
    *,
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_ufw_batch(rules, force_lockout_risk=force_lockout_risk)


def request_firewall_ufw_default(
    client: SupportsShieldClient,
    direction: str,
    policy: str,
    *,
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_ufw_default(
        direction,
        policy,
        force_lockout_risk=force_lockout_risk,
    )


def request_firewall_firewalld_port(
    client: SupportsShieldClient,
    action: str,
    port_spec: str,
    *,
    zone: str = "public",
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_firewalld_port(
        action,
        port_spec,
        zone=zone,
        force_lockout_risk=force_lockout_risk,
    )


def request_firewall_firewalld_service(
    client: SupportsShieldClient,
    action: str,
    service: str,
    *,
    zone: str = "public",
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_firewalld_service(
        action,
        service,
        zone=zone,
        force_lockout_risk=force_lockout_risk,
    )


def request_firewall_firewalld_reload(client: SupportsShieldClient) -> dict[str, Any]:
    return client.firewall_firewalld_reload()


def request_firewall_firewalld_rich_rule(
    client: SupportsShieldClient,
    action: str,
    rule: str,
    *,
    zone: str = "public",
    force_lockout_risk: bool = False,
) -> dict[str, Any]:
    return client.firewall_firewalld_rich_rule(
        action,
        rule,
        zone=zone,
        force_lockout_risk=force_lockout_risk,
    )


def request_fail2ban_status(client: SupportsShieldClient) -> dict[str, Any]:
    return client.fail2ban_status()


def request_fail2ban_banned(client: SupportsShieldClient) -> dict[str, Any]:
    return client.fail2ban_banned()


def request_fail2ban_jail(client: SupportsShieldClient, name: str) -> dict[str, Any]:
    return client.fail2ban_jail(name)


def request_fail2ban_jail_enable(client: SupportsShieldClient, name: str) -> dict[str, Any]:
    return client.fail2ban_jail_enable(name)


def request_fail2ban_jail_disable(client: SupportsShieldClient, name: str) -> dict[str, Any]:
    return client.fail2ban_jail_disable(name)


def request_fail2ban_reload(
    client: SupportsShieldClient,
    *,
    unban: bool = False,
) -> dict[str, Any]:
    return client.fail2ban_reload(unban=unban)
