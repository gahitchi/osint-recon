#!/usr/bin/env python3
"""Download the official WhatsMyName dataset (600+ sites) for broad username
coverage. The curated `data/sites.json` stays the zero-setup default; this is
opt-in.

Usage:
    python scripts/fetch_wmn.py            # -> data/wmn-data.json
    RECON_SITES_FILE=data/wmn-data.json recon scan --username torvalds

The loader (`recon.collectors.username.load_sites`) understands the raw wmn
schema natively (via `_from_wmn`), so no conversion step is needed.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

WMN_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
DEST = Path(__file__).resolve().parents[1] / "data" / "wmn-data.json"


def main() -> int:
    print(f"fetching {WMN_URL} ...", file=sys.stderr)
    try:
        with urllib.request.urlopen(WMN_URL, timeout=30) as resp:  # noqa: S310
            raw = resp.read()
    except Exception as e:  # noqa: BLE001
        print(f"error: download failed: {e}", file=sys.stderr)
        return 1

    try:
        data = json.loads(raw)
        count = len(data.get("sites", []))
    except json.JSONDecodeError as e:
        print(f"error: not valid JSON: {e}", file=sys.stderr)
        return 1

    DEST.write_bytes(raw)
    print(f"wrote {count} sites to {DEST}")
    print(f"enable with:  RECON_SITES_FILE={DEST.relative_to(DEST.parents[1])} "
          f"recon scan --username <handle>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
