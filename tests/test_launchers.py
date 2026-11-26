"""Проверки безопасности и формата лаунчеров (ASCII/CRLF, System32, --locked, SHA-256, 100755 в Git)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_windows_bat_is_ascii_crlf_and_av_safe():
    bat_bytes = (ROOT / "webui.bat").read_bytes()
    assert b"\r\n" in bat_bytes, "webui.bat должен храниться с CRLF для cmd.exe"
    assert bat_bytes.count(b"\n") == bat_bytes.count(b"\r\n"), "webui.bat содержит одиночные LF"

    text = bat_bytes.decode("ascii")
    low = text.lower()
    for forbidden in (
        "executionpolicy",
        "-file ",
        ".ps1",
        "invoke-webrequest",
        "downloadfile",
        "invoke-expression",
        "iex ",
        "| iex",
        "windowstyle",
        "encodedcommand",
        "%temp%",
        "certutil",
        "bitsadmin",
        "setx",
        "reg add",
        "astral.sh/uv/install",
    ):
        assert forbidden not in low, f"Запрещённый паттерн в webui.bat: {forbidden}"

    assert "setlocal" in low
    assert "%systemroot%\\system32\\chcp.com" in low
    assert "%systemroot%\\system32\\curl.exe" in low
    assert "%systemroot%\\system32\\tar.exe" in low
    assert "%systemroot%\\system32\\windowspowershell\\v1.0\\powershell.exe" in low
    assert "--proto =https --tlsv1.2" in low
    assert "--locked --no-dev webui.py" in low
    assert "get-filehash -algorithm sha256" in low
    assert 'cd /d "%~dp0"' in low


@pytest.mark.parametrize("name", ["webui.sh", "webui.command"])
def test_unix_launchers_are_lf_with_shebang(name):
    data = (ROOT / name).read_bytes()
    assert data.startswith(b"#!"), f"{name}: отсутствует shebang"
    assert b"\r" not in data, f"{name}: CRLF сломает bash/macOS"


def test_unix_launchers_pin_uv_sha256_https_locked_and_match_ci():
    bat = (ROOT / "webui.bat").read_text(encoding="ascii")
    sh = (ROOT / "webui.sh").read_text(encoding="utf-8")
    cmd = (ROOT / "webui.command").read_text(encoding="utf-8")
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    m = re.search(r'set "UV_VERSION=(\d+\.\d+\.\d+)"', bat)
    assert m is not None
    uv_ver = m.group(1)
    assert f'UV_VERSION="{uv_ver}"' in sh
    assert f'version: "{uv_ver}"' in ci

    for arch in ("X64", "ARM64", "X86"):
        assert re.search(rf'set "UV_ZIP_SHA256_{arch}=[0-9a-f]{{64}}"', bat), arch
    assert re.search(r'UV_INSTALLER_SHA256="[0-9a-f]{64}"', sh)

    assert "set -euo pipefail" in sh
    assert "sha256_of" in sh
    assert "--proto '=https' --tlsv1.2" in sh
    assert "exec uv run --locked --no-dev webui.py" in sh
    assert "| sh" not in sh and "astral.sh/uv/install" not in sh

    assert "./webui.sh" in cmd and 'exit "$status"' in cmd


@pytest.mark.skipif(not shutil.which("git"), reason="нужен git")
@pytest.mark.parametrize("name", ["webui.sh", "webui.command"])
def test_unix_launchers_are_executable_in_git(name):
    """Бит 100755 попадает в ZIP с GitHub — без него двойной клик на macOS не сработает."""
    if not (ROOT / ".git").exists():
        pytest.skip("репозиторий git ещё не инициализирован")
    out = subprocess.run(
        ["git", "ls-files", "-s", name],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.strip()
    if not out:
        pytest.skip("файл ещё не в индексе git")
    assert out.split()[0] == "100755", out
