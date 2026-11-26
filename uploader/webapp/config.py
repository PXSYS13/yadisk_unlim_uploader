"""Потокобезопасное чтение и запись настроек в .env с ограниченными правами доступа."""

from __future__ import annotations

import logging
import os
import threading
from typing import Any

from dotenv import dotenv_values, set_key

from uploader import paths
from uploader.utils import (
    DEFAULT_CHUNK_MB,
    DEFAULT_WORKERS,
    IS_WINDOWS,
    MAX_CHUNK_MB,
    MAX_WORKERS,
    MIN_CHUNK_MB,
)

log = logging.getLogger("unlim_uploader")
_ENV_LOCK = threading.Lock()


def _as_bool(raw: Any, default: bool) -> bool:
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in ("1", "true", "yes", "on")


def _as_int(raw: Any, default: int, lo: int, hi: int, *, name: str = "") -> int:
    if raw is None or str(raw).strip() == "":
        return default
    try:
        val = int(str(raw).strip())
    except (TypeError, ValueError):
        if name:
            log.warning("Некорректное число в настройке %s=%r — использую %d", name, raw, default)
        return default
    return max(lo, min(hi, val))


def _ensure_private_file(path: os.PathLike) -> None:
    p = os.fspath(path)
    if not os.path.exists(p):
        fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(fd)
    if not IS_WINDOWS:
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass


def get_config() -> dict[str, Any]:
    with _ENV_LOCK:
        vals = dotenv_values(paths.ENV_FILE) if paths.ENV_FILE.exists() else {}

    def pick(key: str, default: Any = None) -> Any:
        if key in vals and vals[key] is not None:
            return vals[key]
        return os.environ.get(key, default)

    return {
        "source_dir": str(pick("SOURCE_DIR", "") or "").strip(),
        "max_workers": _as_int(
            pick("MAX_WORKERS"), DEFAULT_WORKERS, 1, MAX_WORKERS, name="MAX_WORKERS"
        ),
        "chunk_mb": _as_int(
            pick("CHUNK_MB"), DEFAULT_CHUNK_MB, MIN_CHUNK_MB, MAX_CHUNK_MB, name="CHUNK_MB"
        ),
        "strict_quota_guard": _as_bool(pick("STRICT_QUOTA_GUARD"), True),
        "watch_mode": _as_bool(pick("WATCH_MODE"), False),
        "watch_interval_sec": _as_int(
            pick("WATCH_INTERVAL_SEC"), 60, 15, 3600, name="WATCH_INTERVAL_SEC"
        ),
    }


def save_config(updates: dict[str, Any]) -> dict[str, Any]:
    with _ENV_LOCK:
        paths.ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
        _ensure_private_file(paths.ENV_FILE)

        env_path = os.fspath(paths.ENV_FILE)
        mapping = {
            "source_dir": ("SOURCE_DIR", lambda v: str(v or "").strip()),
            "max_workers": (
                "MAX_WORKERS",
                lambda v: str(_as_int(v, DEFAULT_WORKERS, 1, MAX_WORKERS)),
            ),
            "chunk_mb": (
                "CHUNK_MB",
                lambda v: str(_as_int(v, DEFAULT_CHUNK_MB, MIN_CHUNK_MB, MAX_CHUNK_MB)),
            ),
            "strict_quota_guard": (
                "STRICT_QUOTA_GUARD",
                lambda v: "1" if _as_bool(v, True) else "0",
            ),
            "watch_mode": ("WATCH_MODE", lambda v: "1" if _as_bool(v, False) else "0"),
            "watch_interval_sec": ("WATCH_INTERVAL_SEC", lambda v: str(_as_int(v, 60, 15, 3600))),
        }
        for key, val in updates.items():
            if key not in mapping or val is None:
                continue
            env_key, fmt = mapping[key]
            rendered = fmt(val)
            ok, _k, _v = set_key(env_path, env_key, rendered, quote_mode="auto")
            if not ok:
                raise OSError(f"Не удалось записать параметр {env_key} в .env")
            os.environ[env_key] = rendered
        if not IS_WINDOWS:
            try:
                os.chmod(env_path, 0o600)
            except OSError:
                pass
    return get_config()
