from __future__ import annotations

import os
from dataclasses import dataclass


def _as_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


@dataclass
class AppConfig:
    picus_api_base_url: str
    picus_refresh_token: str
    picus_verify_ssl: bool = True
    hx_base_url: str = "https://hx.example.com"
    hx_username: str = ""
    hx_password: str = ""
    hx_verify_ssl: bool = True
    hx_indicator_category: str = "Custom"
    hx_indicator_name: str = "picus_deny_list"
    hx_host_set_id: int = 1000
    dry_run: bool = True

    @classmethod
    def from_env(cls) -> AppConfig:
        return cls(
            picus_api_base_url=os.environ.get(
                "PICUS_API_BASE_URL", "https://api.picussecurity.com"
            ).rstrip("/"),
            picus_refresh_token=os.environ.get("PICUS_REFRESH_TOKEN", ""),
            picus_verify_ssl=_as_bool(os.environ.get("PICUS_VERIFY_SSL", "true"), True),
            hx_base_url=os.environ.get("HX_BASE_URL", "https://hx.example.com").rstrip("/"),
            hx_username=os.environ.get("HX_USERNAME", ""),
            hx_password=os.environ.get("HX_PASSWORD", ""),
            hx_verify_ssl=_as_bool(os.environ.get("HX_VERIFY_SSL", "true"), True),
            hx_indicator_category=os.environ.get("HX_INDICATOR_CATEGORY", "Custom"),
            hx_indicator_name=os.environ.get("HX_INDICATOR_NAME", "picus_deny_list"),
            hx_host_set_id=int(os.environ.get("HX_HOST_SET_ID", "1000")),
            dry_run=_as_bool(os.environ.get("DRY_RUN", "true"), True),
        )
