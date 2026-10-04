"""Readable summary of an HX host record, for analysts and SOAR incident fields."""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Any


def _time(value: Any) -> str:
    if not value:
        return "-"
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
    except ValueError:
        return str(value)


def summarize_host(host: dict[str, Any]) -> dict[str, str]:
    os_info = host.get("os") or {}
    stats = host.get("stats") or {}
    last_alert = host.get("last_alert") or {}
    return {
        "Hostname": str(host.get("hostname") or "-"),
        "Domain": str(host.get("domain") or "-"),
        "Primary IP": str(host.get("primary_ip_address") or "-"),
        "Primary MAC": str(host.get("primary_mac") or "-"),
        "OS": f"{os_info.get('product_name', '-')} {os_info.get('bitness', '')}, platform {os_info.get('platform', '-')}".strip(),
        "Kernel": str(os_info.get("kernel_version") or "-"),
        "Agent version": str(host.get("agent_version") or "-"),
        "Containment": f"{host.get('containment_state', '-')} (queued: {host.get('containment_queued', False)})",
        "Alerts": (
            f"{stats.get('alerts', 0)} total, {stats.get('malware_alerts', 0)} malware, "
            f"{stats.get('exploit_blocks', 0)} exploit blocks, {stats.get('malware_cleaned_count', 0)} cleaned, "
            f"{stats.get('malware_false_positive_alerts', 0)} false positives"
        ),
        "Last alert": f"{last_alert.get('_id', '-')} at {_time(host.get('last_alert_timestamp'))}",
        "Last poll": f"{_time(host.get('last_poll_timestamp'))} from {host.get('last_poll_ip') or '-'}",
        "Last audit": _time(host.get("last_audit_timestamp")),
        "First check-in": _time(host.get("initial_agent_checkin")),
    }


def summary_html(summary: dict[str, str]) -> str:
    return "".join(
        f"<div><b>{escape(key)}:</b> {escape(value)}</div>" for key, value in summary.items()
    )
