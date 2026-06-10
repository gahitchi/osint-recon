"""Optional API-key vault.

osint-recon is keyless-first: every Phase-1 module runs with no credentials. But
the engine is built so *keyed* modules (Shodan, HaveIBeenPwned, VirusTotal, ...)
can be added later without re-architecting — a module declares `requires_keys`,
and the engine simply skips it when the named keys are absent.

Keys are read from (in priority order):
  1. environment variables, upper-cased + prefixed, e.g. RECON_KEY_SHODAN
  2. ~/.config/osint-recon/keys.toml   ([keys] shodan = "...")
Nothing is ever written; this module only reads.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

_CONFIG_PATH = Path(
    os.environ.get("RECON_KEYS_FILE")
    or (Path.home() / ".config" / "osint-recon" / "keys.toml")
)


class KeyVault:
    def __init__(self, path: Path = _CONFIG_PATH) -> None:
        self._path = path
        self._file_keys: dict[str, str] = {}
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        try:
            if self._path.is_file():
                data = tomllib.loads(self._path.read_text(encoding="utf-8"))
                keys = data.get("keys", data)
                self._file_keys = {str(k).lower(): str(v) for k, v in keys.items()}
        except Exception:  # noqa: BLE001 - a malformed key file must not crash a scan
            self._file_keys = {}

    def get(self, name: str) -> str | None:
        env = os.environ.get(f"RECON_KEY_{name.upper()}")
        if env:
            return env
        self._load()
        return self._file_keys.get(name.lower())

    def has(self, name: str) -> bool:
        return bool(self.get(name))

    def has_all(self, names: list[str]) -> bool:
        return all(self.has(n) for n in names)


VAULT = KeyVault()
