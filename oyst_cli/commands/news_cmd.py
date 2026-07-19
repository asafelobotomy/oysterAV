"""Security news CLI (selectable advisory feeds)."""

from __future__ import annotations

import click

from oyst_cli.options import json_option
from oyst_cli.output import emit
from oyst_core.security_news import NEWS_SOURCES, list_security_news, normalize_source_ids


def _parse_sources_option(raw: str | None) -> list[str] | None:
    if raw is None or not raw.strip():
        return None
    return normalize_source_ids([s.strip() for s in raw.split(",") if s.strip()])


@click.group("news")
def news_group() -> None:
    """Security advisory headlines (selectable distro / OSS feeds)."""


@news_group.command("list")
@json_option
@click.option("--refresh", is_flag=True, help="Force fetch even if cache is fresh")
@click.option(
    "--sources",
    default=None,
    help=(
        "Comma-separated source ids "
        f"({', '.join(NEWS_SOURCES)}); default: config ui.security_news_sources"
    ),
)
def news_list_cmd(json_mode: bool, refresh: bool, sources: str | None) -> None:
    """List cached or freshly fetched security headlines."""
    selected = _parse_sources_option(sources)
    data = list_security_news(force_refresh=refresh, sources=selected)
    if json_mode:
        emit(data, json_mode=True)
        return
    items = data.get("items") if isinstance(data.get("items"), list) else []
    fetched = data.get("fetched_at", "—")
    click.echo(f"Fetched: {fetched}")
    used = data.get("sources")
    if isinstance(used, list) and used:
        click.echo(f"Sources: {', '.join(str(s) for s in used)}")
    if data.get("stale"):
        click.echo("Cache: stale (showing last good fetch)")
    elif data.get("from_cache"):
        click.echo("Cache: fresh")
    else:
        click.echo("Cache: updated")
    if not items:
        click.echo("No headlines available.")
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        source = item.get("source", "?")
        title = item.get("title", "")
        link = item.get("link", "")
        label = str(item.get("severity_label") or "unknown")
        if label != "unknown":
            click.echo(f"[{source}] ({label}) {title}")
        else:
            click.echo(f"[{source}] {title}")
        if link:
            click.echo(f"  {link}")


@news_group.command("refresh")
@json_option
@click.option(
    "--sources",
    default=None,
    help=(
        "Comma-separated source ids "
        f"({', '.join(NEWS_SOURCES)}); default: config ui.security_news_sources"
    ),
)
def news_refresh_cmd(json_mode: bool, sources: str | None) -> None:
    """Force-refresh advisory feeds and update the cache."""
    selected = _parse_sources_option(sources)
    data = list_security_news(force_refresh=True, sources=selected)
    errors_raw = data.get("errors")
    errors = errors_raw if isinstance(errors_raw, list) else []
    items_raw = data.get("items")
    items = items_raw if isinstance(items_raw, list) else []
    if json_mode:
        emit(data, json_mode=True)
    else:
        click.echo(f"Refreshed {len(items)} headline(s).")
        for err in errors:
            if isinstance(err, dict):
                click.echo(f"  warn {err.get('source')}: {err.get('error')}", err=True)
    if errors and not items:
        raise SystemExit(2)
