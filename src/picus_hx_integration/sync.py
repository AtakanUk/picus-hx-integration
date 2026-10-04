"""Picus -> HX deny list.

Picus breach-and-attack simulations run real malware samples against the
endpoints. Samples the EDR did not block are exactly the ones worth blocking by
hash: their hashes are collected from the latest run of each simulation and
appended to a custom HX indicator, which turns them into execution blocks.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable

import requests

from .hx import HxClient
from .picus import PicusClient

ACTION_HASH_FIELDS = {
    "md5": ["md5", "fileMd5", "file_md5", "md5_hash"],
    "sha1": ["sha1", "fileSha1", "file_sha1"],
    "sha256": ["sha256", "fileSha256", "file_sha256", "sha256_hash"],
}
PREFERRED_HASH_TYPE = "sha256"
HASH_PATTERNS = {
    "md5": re.compile(r"^[0-9a-f]{32}$"),
    "sha1": re.compile(r"^[0-9a-f]{40}$"),
    "sha256": re.compile(r"^[0-9a-f]{64}$"),
}

log = logging.getLogger(__name__)


def walk_json(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield key, value
            yield from walk_json(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_json(item)


def extract_hash_from_action(action_detail: dict) -> tuple[str | None, str | None]:
    found: dict[str, str] = {}
    for key, value in walk_json(action_detail):
        if not isinstance(value, str):
            continue
        lowered = key.lower()
        for hash_type, fields in ACTION_HASH_FIELDS.items():
            candidate = value.strip().lower()
            # only well-formed hashes; anything else must never reach a block list
            if lowered in {field.lower() for field in fields} and HASH_PATTERNS[hash_type].match(
                candidate
            ):
                found.setdefault(hash_type, candidate)
    if not found:
        return None, None
    if PREFERRED_HASH_TYPE in found:
        return PREFERRED_HASH_TYPE, found[PREFERRED_HASH_TYPE]
    for candidate in ("sha256", "md5", "sha1"):
        if candidate in found:
            return candidate, found[candidate]
    return None, None


def extract_unblocked_action_ids(run_payload: dict) -> list[int]:
    identifiers: set[int] = set()
    for key, value in walk_json(run_payload):
        if not isinstance(value, list) or key.lower() not in {
            "actions",
            "results",
            "actionresults",
            "threats",
        }:
            continue
        for item in value:
            if not isinstance(item, dict):
                continue
            action_id = item.get("actionId") or item.get("action_id") or item.get("id")
            result = str(
                item.get("preventionResult")
                or item.get("prevention_result")
                or item.get("result")
                or item.get("status")
                or ""
            ).lower()
            if action_id and any(
                fragment in result
                for fragment in ("not_blocked", "notblocked", "not blocked", "failed", "unblocked")
            ):
                identifiers.add(int(action_id))
    return sorted(identifiers)


def collect_unblocked_hashes(
    picus_client: PicusClient, access_token: str, simulation_ids: Iterable[int]
) -> list[tuple[str, str]]:
    found: dict[str, str] = {}
    for simulation_id in simulation_ids:
        try:
            run = picus_client.get_latest_run(access_token, simulation_id)
        except requests.HTTPError as exc:
            log.warning("Latest run of simulation %s not available: %s", simulation_id, exc)
            continue
        action_ids = extract_unblocked_action_ids(run)
        log.info("Simulation %s: %d action(s) not blocked", simulation_id, len(action_ids))
        for action_id in action_ids:
            try:
                detail = picus_client.get_action_detail(access_token, action_id)
            except requests.HTTPError as exc:
                log.warning("Action %s details not available: %s", action_id, exc)
                continue
            hash_type, hash_value = extract_hash_from_action(detail)
            if hash_type and hash_value:
                found.setdefault(hash_value, hash_type)
            else:
                log.info("Action %s has no file hash (not a file-based threat)", action_id)
    return [(hash_type, hash_value) for hash_value, hash_type in found.items()]


def synchronize_hashes(
    hx_client: HxClient, hashes: list[tuple[str, str]]
) -> list[tuple[str, str, str]]:
    hx_client.ensure_indicator()
    results = []
    for hash_type, hash_value in hashes:
        try:
            status = hx_client.append_hash(hash_type, hash_value)
        except requests.HTTPError as exc:
            status = f"error: {exc}"
        log.info("%s %s -> %s", hash_type, hash_value, status)
        results.append((hash_type, hash_value, status))
    return results
