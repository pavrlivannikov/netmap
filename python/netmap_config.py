"""
NetMap Configuration — load/save settings from JSON file.

Default location: ~/.netmap_config.json
Override via NETMAP_CONFIG env var.

Usage:
    from netmap_config import config
    cfg = config.load()
    print(cfg["telegram_token"])

    config.update({"telegram_token": "123:abc"})
    config.save()
"""
import json
import os
from typing import Any, Dict, Optional


# ── Default values ────────────────────────────────────────────────

_DEFAULTS: Dict[str, Any] = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "snmp_community": "public",
    "scan_timeout": 5.0,
    "alert_cooldown": 300,
    "default_subnet": "192.168.1.0/24",
    # Internal marker
    "_version": 1,
}


def _default_path() -> str:
    """Resolve config file path: NETMAP_CONFIG env → ~/.netmap_config.json."""
    env = os.environ.get("NETMAP_CONFIG", "")
    if env:
        return os.path.expanduser(env)
    return os.path.expanduser("~/.netmap_config.json")


class NetMapConfig:
    """Thread-safe-ish config manager backed by a JSON file.

    Public API:
        cfg = config.load()          # cached or fresh
        config.update({"key": val})  # merge dict
        config.save()                # persist
        config.to_dict()             # export copy
        config.reload()              # discard cache, re-read
    """

    def __init__(self, path: Optional[str] = None) -> None:
        self._path = path or _default_path()
        self._data: Dict[str, Any] = dict(_DEFAULTS)
        self._loaded = False

    # ── Public helpers ────────────────────────

    def load(self) -> Dict[str, Any]:
        """Return current config (loads from file once, then cached)."""
        if not self._loaded:
            self._reload()
        return self._data

    def reload(self) -> Dict[str, Any]:
        """Force re-read from disk, discarding cache."""
        self._reload()
        return self._data

    def update(self, values: Dict[str, Any]) -> None:
        """Merge dict with validation: ignore unknown keys + type enforcement."""
        allowed = set(_DEFAULTS.keys())
        for k, v in values.items():
            if k == "_version":
                continue
            if k not in allowed:
                continue  # silently skip unknown keys
            # Coerce to expected type
            default_val = _DEFAULTS.get(k)
            if isinstance(default_val, str) and not isinstance(v, str):
                v = str(v)
            elif isinstance(default_val, int) and not isinstance(v, int):
                try:
                    v = int(v)
                except (TypeError, ValueError):
                    v = default_val
            elif isinstance(default_val, float) and not isinstance(v, (int, float)):
                try:
                    v = float(v)
                except (TypeError, ValueError):
                    v = default_val
            self._data[k] = v
        self._loaded = True

    def save(self) -> None:
        """Persist current config to JSON file. Creates directory if needed."""
        os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)
        with open(self._path, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False, default=str)
        self._loaded = True

    def to_dict(self) -> Dict[str, Any]:
        """Return a copy of current config (safe to mutate)."""
        return dict(self._data)

    def from_dict(self, d: Dict[str, Any]) -> None:
        """Replace entire config from a dict (validated)."""
        self._data = dict(_DEFAULTS)
        self.update(d)

    # ── Magic / convenience ──────────────────

    def __getitem__(self, key: str) -> Any:
        if not self._loaded:
            self._reload()
        if key not in _DEFAULTS:
            raise KeyError(key)
        return self._data.get(key, _DEFAULTS[key])

    def __setitem__(self, key: str, value: Any) -> None:
        self.update({key: value})

    def __contains__(self, key: str) -> bool:
        return key in _DEFAULTS

    def get(self, key: str, default: Any = None) -> Any:
        """Dict-like get with default fallback."""
        if not self._loaded:
            self._reload()
        return self._data.get(key, _DEFAULTS.get(key, default))

    # ── Internal ─────────────────────────────

    def _reload(self) -> None:
        """Read file or fall back to defaults."""
        self._data = dict(_DEFAULTS)
        if os.path.isfile(self._path):
            try:
                with open(self._path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if isinstance(raw, dict):
                    self._data.update(raw)
            except (json.JSONDecodeError, OSError):
                # Corrupt file → keep defaults
                pass
        # Save defaults if file doesn't exist yet (auto-bootstrap)
        if not os.path.isfile(self._path):
            try:
                self.save()
            except OSError:
                pass
        self._loaded = True


# ── Module-level singleton ────────────────────────────────────────

config = NetMapConfig()
