from unittest.mock import MagicMock

import requests

from picus_hx_integration.hostinfo import summarize_host, summary_html
from picus_hx_integration.sync import (
    collect_unblocked_hashes,
    extract_hash_from_action,
    extract_unblocked_action_ids,
    synchronize_hashes,
)

SHA256 = "a" * 64
MD5 = "b" * 32


def test_unblocked_action_ids():
    payload = {
        "data": {
            "actions": [
                {"actionId": 7, "preventionResult": "not_blocked"},
                {"actionId": 8, "preventionResult": "blocked"},
                {"actionId": 9, "result": "Failed"},
            ]
        }
    }
    assert extract_unblocked_action_ids(payload) == [7, 9]


def test_hash_extraction_prefers_sha256_and_rejects_garbage():
    assert extract_hash_from_action({"file": {"sha256": SHA256.upper(), "md5": MD5}}) == (
        "sha256",
        SHA256,
    )
    assert extract_hash_from_action({"sha256": "not-a-hash", "fileMd5": MD5}) == ("md5", MD5)
    assert extract_hash_from_action({"sha256": "*"}) == (None, None)


def test_collect_skips_unavailable_simulations_and_actions():
    picus = MagicMock()
    picus.get_latest_run.side_effect = [
        requests.HTTPError("404"),
        {
            "actions": [
                {"actionId": 1, "preventionResult": "not_blocked"},
                {"actionId": 2, "preventionResult": "not_blocked"},
                {"actionId": 3, "preventionResult": "not_blocked"},
            ]
        },
    ]
    picus.get_action_detail.side_effect = [
        {"sha256": SHA256},
        requests.HTTPError("500"),
        {"sha256": SHA256},
    ]
    assert collect_unblocked_hashes(picus, "token", [10, 11]) == [("sha256", SHA256)]


def test_synchronize_reports_each_hash():
    hx = MagicMock()
    hx.append_hash.side_effect = ["added", "duplicate", requests.HTTPError("HTTP 500")]
    results = synchronize_hashes(hx, [("sha256", SHA256), ("md5", MD5), ("md5", "c" * 32)])
    hx.ensure_indicator.assert_called_once()
    assert [status for _, _, status in results] == ["added", "duplicate", "error: HTTP 500"]


def test_host_summary():
    host = {
        "hostname": "WS-042",
        "domain": "corp",
        "primary_ip_address": "192.0.2.42",
        "agent_version": "35.31.0",
        "os": {"product_name": "Windows 11 Enterprise", "bitness": "64-bit", "platform": "win"},
        "containment_state": "normal",
        "stats": {"alerts": 3, "malware_alerts": 1},
        "last_poll_timestamp": "2026-03-01T10:15:00.000Z",
        "last_poll_ip": "192.0.2.42",
    }
    summary = summarize_host(host)
    assert summary["OS"] == "Windows 11 Enterprise 64-bit, platform win"
    assert summary["Last poll"] == "2026-03-01 10:15:00 from 192.0.2.42"
    assert summary["Alerts"].startswith("3 total, 1 malware")
    assert "<b>Hostname:</b> WS-042" in summary_html(summary)
