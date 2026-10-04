from __future__ import annotations

import json

import requests
from requests.auth import HTTPBasicAuth

from .config import AppConfig


class HxClient:
    def __init__(self, config: AppConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.hx_verify_ssl
        self.token = self._login()

    def _login(self) -> str:
        response = self.session.get(
            f"{self.config.hx_base_url}/hx/api/v3/token",
            auth=HTTPBasicAuth(self.config.hx_username, self.config.hx_password),
            headers={"Accept": "application/json"},
            timeout=30,
        )
        response.raise_for_status()
        token = response.headers.get("X-FeApi-Token")
        if not token:
            raise RuntimeError("HX did not return X-FeApi-Token")
        return token

    def _headers(self) -> dict[str, str]:
        return {
            "X-FeApi-Token": self.token,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def ensure_indicator(self) -> None:
        path = (
            f"{self.config.hx_base_url}/hx/api/v3/indicators/"
            f"{self.config.hx_indicator_category}/{self.config.hx_indicator_name}"
        )
        response = self.session.get(path, headers=self._headers(), timeout=30)
        if response.status_code == 200:
            return
        if response.status_code != 404:
            response.raise_for_status()
        if self.config.dry_run:
            return
        create_response = self.session.post(
            f"{self.config.hx_base_url}/hx/api/v3/indicators",
            headers=self._headers(),
            data=json.dumps(
                {
                    "category": self.config.hx_indicator_category,
                    "display_name": self.config.hx_indicator_name,
                    "name": self.config.hx_indicator_name,
                    "description": "Hashes synchronized from Picus simulations",
                    "platforms": ["win", "osx", "linux"],
                }
            ),
            timeout=30,
        )
        create_response.raise_for_status()

    def append_hash(self, hash_type: str, hash_value: str) -> str:
        if hash_type not in {"md5", "sha256"}:
            return "unsupported"
        if self.config.dry_run:
            return "dry-run"
        response = self.session.post(
            f"{self.config.hx_base_url}/hx/api/v3/indicators/{self.config.hx_indicator_category}/{self.config.hx_indicator_name}/conditions/execution",
            headers=self._headers(),
            data=json.dumps(
                [
                    {
                        "tests": [
                            {
                                "token": f"fileWriteEvent/{hash_type}",
                                "operator": "equal",
                                "value": hash_value,
                            }
                        ]
                    }
                ]
            ),
            timeout=30,
        )
        if response.status_code in {200, 201}:
            return "added"
        if response.status_code == 409:
            return "duplicate"
        response.raise_for_status()
        return "added"

    def lookup_host_by_hostname(self, hostname: str) -> dict:
        response = self.session.get(
            f"{self.config.hx_base_url}/hx/api/v3/hosts",
            headers=self._headers(),
            params={"hostname": hostname},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def find_host(self, hostname: str | None = None, ip_address: str | None = None) -> dict | None:
        """First host entry for a hostname, or for an IP (search, then full record by hostname)."""
        if hostname:
            entries = (self.lookup_host_by_hostname(hostname).get("data") or {}).get(
                "entries"
            ) or []
            return entries[0] if entries else None
        entries = (self.lookup_host_by_ip(ip_address or "").get("data") or {}).get("entries") or []
        if not entries:
            return None
        return self.find_host(hostname=entries[0]["hostname"]) or entries[0]

    def lookup_host_by_ip(self, ip_address: str) -> dict:
        response = self.session.get(
            f"{self.config.hx_base_url}/hx/api/v3/hosts",
            headers=self._headers(),
            params={"search": ip_address},
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def start_filename_search(self, filename: str) -> dict:
        response = self.session.post(
            f"{self.config.hx_base_url}/hx/api/v3/searches",
            headers=self._headers(),
            data=json.dumps(
                {
                    "host_set": {"_id": self.config.hx_host_set_id},
                    "query": [
                        {
                            "field": "File Name",
                            "operator": "contains",
                            "value": filename,
                        }
                    ],
                }
            ),
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
