"""Проверка согласованности версий (APP_VERSION, pyproject.toml, uv.lock, лаунчеры/CI) и правил UI."""

from __future__ import annotations

import re
from pathlib import Path

from uploader import APP_VERSION

ROOT = Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', text)
        assert m, "В pyproject.toml не найдено поле version"
        return m.group(1)
    return str(tomllib.loads(text)["project"]["version"])


def test_app_version_matches_pyproject_and_uv_lock():
    pyproject_ver = _pyproject_version()
    assert APP_VERSION == pyproject_ver

    lock_text = (ROOT / "uv.lock").read_text(encoding="utf-8")
    m = re.search(
        r'name\s*=\s*"yadisk-unlim-uploader"\s*\r?\nversion\s*=\s*"([^"]+)"',
        lock_text,
    )
    assert m, "В uv.lock не найдена запись пакета yadisk-unlim-uploader"
    assert m.group(1) == pyproject_ver


def test_ui_assets_contain_no_bare_md_filenames():
    # Telegram и браузеры превращают *.md в кликабельную ссылку на домен .md
    for rel in ("webui_assets/index.html", "webui_assets/static/app.js"):
        text = (ROOT / rel).read_text(encoding="utf-8")
        assert not re.search(r"\b[A-Za-z0-9_-]+\.md\b", text), f"Найдено имя *.md в {rel}"
