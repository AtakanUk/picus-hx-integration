from __future__ import annotations

import requests

from .config import AppConfig


class PicusClient:
    def __init__(self, config: AppConfig):
        self.config = config
        self.session = requests.Session()
        self.session.verify = config.picus_verify_ssl

    def get_access_token(self) -> str:
        response = self.session.post(
            f"{self.config.picus_api_base_url}/v1/auth/token",
            json={"refresh_token": self.config.picus_refresh_token},
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=30,
        )
        response.raise_for_status()
        token = response.json().get("access_token")
        if not token:
            raise RuntimeError("Picus access token is missing from the response")
        return token

    @staticmethod
    def _headers(access_token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}

    def list_simulation_ids(self, access_token: str) -> list[int]:
        response = self.session.get(
            f"{self.config.picus_api_base_url}/v1/simulations",
            headers=self._headers(access_token),
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
        items = payload.get("data") or payload.get("simulations") or []
        simulation_ids = []
        for item in items:
            simulation_id = item.get("id") or item.get("simulationId")
            if simulation_id is not None:
                simulation_ids.append(int(simulation_id))
        return simulation_ids

    def get_latest_run(self, access_token: str, simulation_id: int) -> dict:
        response = self.session.get(
            f"{self.config.picus_api_base_url}/v1/simulations/{simulation_id}/run/latest",
            headers=self._headers(access_token),
            timeout=30,
        )
        response.raise_for_status()
        return response.json()

    def get_action_detail(self, access_token: str, action_id: int) -> dict:
        response = self.session.get(
            f"{self.config.picus_api_base_url}/v1/threat-library/actions/{action_id}",
            headers=self._headers(access_token),
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
