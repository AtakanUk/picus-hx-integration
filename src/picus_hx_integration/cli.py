from __future__ import annotations

import argparse
import json
import logging
import os
from typing import Any

from .config import AppConfig
from .hostinfo import summarize_host, summary_html
from .hx import HxClient
from .picus import PicusClient
from .sync import collect_unblocked_hashes, synchronize_hashes


def _soar_client() -> Any:
    import resilient

    options: dict[str, Any] = {
        "host": os.environ["SOAR_HOST"],
        "port": int(os.environ.get("SOAR_PORT", "443")),
        "org": os.environ["SOAR_ORG"],
        "api_key_id": os.environ["SOAR_API_KEY_ID"],
        "api_key_secret": os.environ["SOAR_API_KEY_SECRET"],
    }
    if os.environ.get("SOAR_CAFILE"):
        options["cafile"] = os.environ["SOAR_CAFILE"]
    return resilient.get_client(options)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Picus / Trellix HX endpoint toolkit")
    commands = parser.add_subparsers(dest="command", required=True)

    sync = commands.add_parser("denylist-sync", help="block hashes of samples the EDR did not stop")
    sync.add_argument(
        "--simulation-id",
        action="append",
        type=int,
        default=[],
        help="limit to these simulations (default: all)",
    )

    host = commands.add_parser("host-lookup", help="HX host summary by hostname or IP")
    group = host.add_mutually_exclusive_group(required=True)
    group.add_argument("--hostname")
    group.add_argument("--ip-address")
    host.add_argument("--incident", type=int, help="write the summary into this SOAR incident")
    host.add_argument(
        "--field", default="hx_host_details", help="rich-text incident field for --incident"
    )

    search = commands.add_parser(
        "filename-search", help="start an HX enterprise search for a file name"
    )
    search.add_argument("--filename", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    config = AppConfig.from_env()

    if args.command == "denylist-sync":
        picus = PicusClient(config)
        token = picus.get_access_token()
        simulation_ids = args.simulation_id or picus.list_simulation_ids(token)
        hashes = collect_unblocked_hashes(picus, token, simulation_ids)
        results = synchronize_hashes(HxClient(config), hashes)
        print(json.dumps([{"type": t, "hash": h, "status": s} for t, h, s in results], indent=2))
        return 1 if any(status.startswith("error") for _, _, status in results) else 0

    hx = HxClient(config)
    if args.command == "host-lookup":
        host = hx.find_host(hostname=args.hostname, ip_address=args.ip_address)
        if host is None:
            print("Host not found")
            return 1
        summary = summarize_host(host)
        print(json.dumps(summary, indent=2))
        if args.incident:
            _soar_client().get_put(
                f"/incidents/{args.incident}",
                lambda incident: incident["properties"].update({args.field: summary_html(summary)}),
            )
        return 0

    print(json.dumps(hx.start_filename_search(args.filename), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
