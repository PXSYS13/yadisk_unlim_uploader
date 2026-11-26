"""Изоляция всех путей и переменных окружения в тестах."""

from __future__ import annotations

import pytest

from uploader import paths
from uploader.webapp import manager as mgr_mod

_ENV_KEYS = (
    "SOURCE_DIR",
    "MAX_WORKERS",
    "CHUNK_MB",
    "STRICT_QUOTA_GUARD",
    "WATCH_MODE",
    "WATCH_INTERVAL_SEC",
    "YADISK_UPLOADER_PORT",
)


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "ENV_FILE", tmp_path / ".env")
    monkeypatch.setattr(paths, "COOKIES_FILE", tmp_path / "cookies.json")
    monkeypatch.setattr(paths, "DB_FILE", tmp_path / "upload_state.db")
    monkeypatch.setattr(paths, "LOG_DIR", tmp_path / "logs")
    monkeypatch.setattr(paths, "UPLOAD_LOG", tmp_path / "logs" / "upload.log")
    monkeypatch.setattr(paths, "WEBUI_LOG", tmp_path / "logs" / "webui.log")
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(mgr_mod, "manager", mgr_mod.UploadManager())
    yield
