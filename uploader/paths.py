"""Пути к файлам состояния, конфигурации и журналам.

Модули всегда читают атрибуты через модуль (`paths.DB_FILE`), а не копируют их при импорте,
чтобы тесты могли подменить пути на временную директорию без риска затронуть реальные файлы.
"""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

PROJECT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT / ".env"
load_dotenv(ENV_FILE)

COOKIES_FILE = PROJECT / "cookies.json"
DB_FILE = PROJECT / "upload_state.db"
LOG_DIR = PROJECT / "logs"
UPLOAD_LOG = LOG_DIR / "upload.log"
WEBUI_LOG = LOG_DIR / "webui.log"
ASSETS_DIR = PROJECT / "webui_assets"
