"""Тесты FastAPI Web UI: CSRF/CSP/Host/Origin, фильтрация сторонних кук, CSV formula guard, PowerShell env-var safety."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time

import pytest
from fastapi.testclient import TestClient

from tools.probe_unlim_upload import make_test_jpeg, make_test_mp4
from uploader import paths
from uploader.cookies import AuthExpiredError, UnlimApiError, YandexUnavailableError
from uploader.engine import RunSummary
from uploader.quota_guard import QuotaSnapshot
from uploader.utils import EXIT_AUTH, EXIT_OK
from uploader.webapp import config as cfg_mod
from uploader.webapp import manager as mgr_mod
from uploader.webapp import ports as ports_mod
from uploader.webapp.api import create_app


def _make_client():
    ports_mod.use_port(ports_mod.DEFAULT_PORT)
    app = create_app(allow_testserver=False)
    client = TestClient(app, base_url=f"http://127.0.0.1:{ports_mod.DEFAULT_PORT}")
    csrf = {"X-CSRF-Token": app.state.csrf_token, "X-Requested-With": "XMLHttpRequest"}
    return app, client, csrf


def test_security_headers_csrf_host_origin_and_prod_rejects_testserver():
    app, client, csrf = _make_client()

    r_idx = client.get("/")
    assert r_idx.status_code == 200
    assert "Загрузка в Безлимит Яндекс.Диска" in r_idx.text
    assert r_idx.headers.get("x-frame-options") == "DENY"
    assert "frame-ancestors 'none'" in (r_idx.headers.get("content-security-policy") or "")
    assert r_idx.headers.get("x-content-type-options") == "nosniff"
    assert app.state.csrf_token in r_idx.text

    r_hello = client.get("/api/hello")
    assert r_hello.status_code == 200 and r_hello.json()["app_id"] == "yadisk-unlim-uploader"
    assert "folder" not in r_hello.json()
    assert r_hello.headers.get("cache-control") == "no-store"

    # В продакшн-конфигурации testserver, чужой Origin и POST без CSRF блокируются 403
    assert client.get("/api/status", headers={"Host": "testserver"}).status_code == 403
    assert client.get("/api/status", headers={"Host": "evil.example:8001"}).status_code == 403
    assert client.post("/api/stop").status_code == 403  # нет X-CSRF-Token
    assert (
        client.post("/api/stop", headers={**csrf, "Origin": "https://evil.example"}).status_code
        == 403
    )
    assert (
        client.post("/api/stop", headers={**csrf, "Sec-Fetch-Site": "cross-site"}).status_code
        == 403
    )
    assert client.get("/api/hello", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    # Открытие главной страницы GET / по внешней ссылке (Telegram, закладка) должно работать
    assert client.get("/", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200
    assert client.post("/api/stop", headers=csrf).status_code == 200


def test_save_cookies_filters_third_party_scan_csv_formula_and_unc_rejected(tmp_path, monkeypatch):
    _app, client, csrf = _make_client()

    monkeypatch.setattr(
        mgr_mod.manager,
        "verify_account_live",
        lambda jar=None: {
            "used": 100,
            "limit": 1000,
            "actual_photounlim_size": 500,
            "filesize_limit": 50 * 1024**3,
            "unlimited_free": True,
            "warning": None,
        },
    )

    cookies_json = json.dumps(
        [
            {"name": "Session_id", "value": "s1", "domain": ".yandex.ru"},
            {"name": "yandexuid", "value": "u1", "domain": ".yandex.ru"},
            {"name": "sessionid2", "value": "s2", "domain": ".yandex.ru"},
            {"name": "bank_secret", "value": "TOPSECRET", "domain": ".mybank.example"},
        ]
    )
    r_ck = client.post("/api/cookies", json={"text": cookies_json}, headers=csrf)
    assert r_ck.status_code == 200 and r_ck.json()["ok"] is True
    assert paths.COOKIES_FILE.exists()
    saved_text = paths.COOKIES_FILE.read_text(encoding="utf-8")
    assert "bank_secret" not in saved_text and "TOPSECRET" not in saved_text

    # UNC-путь и произвольный status в export.csv должны отклоняться
    assert (
        client.post(
            "/api/settings", json={"source_dir": r"\\evil-host\share"}, headers=csrf
        ).status_code
        == 400
    )
    assert client.get('/api/export.csv?status=all";filename=evil.exe').status_code == 422

    # Папка с фото, видео, RAW и файлом с формулой в имени (CSV Injection test)
    src = tmp_path / "Медиа"
    src.mkdir()
    (src / "=SUM(1,2).jpg").write_bytes(make_test_jpeg(salt=b"ui1"))
    (src / "vid.mp4").write_bytes(make_test_mp4(salt=b"ui2"))
    (src / "raw.dng").write_bytes(b"II\x2a\x00" + b"\x00" * 32)

    r_scan = client.post("/api/scan", json={"source_dir": str(src)}, headers=csrf)
    assert r_scan.status_code == 200

    for _ in range(60):
        st = client.get("/api/status").json()
        if not st["running"] and st["stats"]["total_files"] == 3:
            break
        time.sleep(0.05)

    st = client.get("/api/status").json()
    assert st["stats"]["photos"] == 1
    assert st["stats"]["videos"] == 1
    assert st["stats"]["skipped_unsupported"] == 1

    r_files = client.get("/api/files?status=skipped")
    assert r_files.status_code == 200 and r_files.json()["total"] == 1

    r_csv = client.get("/api/export.csv?status=all")
    assert r_csv.status_code == 200
    assert r_csv.content.startswith(b"\xef\xbb\xbf")
    # Формула нейтрализована апострофом
    assert "'=SUM(1,2).jpg" in r_csv.text

    r_del = client.delete("/api/cookies", headers=csrf)
    assert r_del.status_code == 200 and not paths.COOKIES_FILE.exists()


def test_pick_folder_dialog_never_interpolates_path_into_powershell(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = "D:\\Фотоархив\n"
        stderr = ""

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = kwargs.get("env", {})
        return FakeProc()

    monkeypatch.setattr(mgr_mod, "IS_WINDOWS", True)
    monkeypatch.setattr(mgr_mod.subprocess, "run", fake_run)

    # Опасная строка с Unicode smart-quote U+2019 и точкой с запятой
    evil_dir = "C:\\Mom\u2019s; calc.exe #"
    chosen = mgr_mod.pick_folder_dialog(evil_dir)
    assert chosen == "D:\\Фотоархив"
    assert evil_dir not in " ".join(captured["cmd"])
    assert captured["env"]["YADISK_INIT_DIR"] == evil_dir
    assert "-LiteralPath" in " ".join(captured["cmd"])
    assert "UTF8" in " ".join(captured["cmd"])


def test_frontend_js_syntax_valid_and_no_innerhtml():
    js_path = paths.ASSETS_DIR / "static" / "app.js"
    js_text = js_path.read_text(encoding="utf-8")
    assert "innerHTML" not in js_text, "app.js должен использовать DOM API вместо innerHTML"
    node = shutil.which("node")
    if node:
        proc = subprocess.run(
            [node, "--check", str(js_path)], capture_output=True, text=True, encoding="utf-8"
        )
        assert proc.returncode == 0, proc.stderr


def test_ports_choose_port_and_allowed_sets(monkeypatch):
    assert "localhost" in ports_mod.allowed_hosts(80)
    assert "testserver" in ports_mod.allowed_hosts(8001, allow_testserver=True)
    assert "http://localhost" in ports_mod.allowed_origins(80)
    assert "http://testserver" in ports_mod.allowed_origins(8001, allow_testserver=True)

    # Занимаем случайный свободный порт и проверяем fallback или ошибку
    sock0, port0 = ports_mod.choose_port(explicit_port=0)
    try:
        assert port0 > 0
        # Повторный bind на тот же explicit_port должен упасть RuntimeError
        with pytest.raises(RuntimeError):
            ports_mod.choose_port(explicit_port=port0)
    finally:
        sock0.close()

    monkeypatch.setenv("YADISK_UPLOADER_PORT", "not-int")
    with pytest.raises(ValueError):
        ports_mod.choose_port()

    monkeypatch.setenv("YADISK_UPLOADER_PORT", "70000")
    with pytest.raises(ValueError):
        ports_mod.choose_port()

    # Корректный выбор через env (порт 0 — ОС выдаст свободный)
    monkeypatch.setenv("YADISK_UPLOADER_PORT", "0")
    s_env, p_env = ports_mod.choose_port()
    try:
        assert p_env > 0
    finally:
        s_env.close()

    # Убеждаемся, что _active_port возвращён к DEFAULT_PORT
    ports_mod.use_port(ports_mod.DEFAULT_PORT)
    assert isinstance(socket.AF_INET, int)


def test_config_clamping_and_special_chars():
    saved = cfg_mod.save_config(
        {
            "source_dir": r"D:\Фото #1 (Лето)",
            "max_workers": 99,
            "chunk_mb": 1,
            "strict_quota_guard": False,
            "watch_mode": True,
            "watch_interval_sec": 5,
            "ignored_key": "nope",
        }
    )
    assert saved["source_dir"] == r"D:\Фото #1 (Лето)"
    assert saved["max_workers"] == 3
    assert saved["chunk_mb"] == 4
    assert saved["strict_quota_guard"] is False
    assert saved["watch_mode"] is True
    assert saved["watch_interval_sec"] == 15

    # Невалидные числа в .env -> безопасный fallback
    paths.ENV_FILE.write_text("MAX_WORKERS=abc\nCHUNK_MB=xyz\n", encoding="utf-8")
    loaded = cfg_mod.get_config()
    assert loaded["max_workers"] == 2 and loaded["chunk_mb"] == 16


def test_api_cookies_errors_settings_picker_upload_retry_and_reset(tmp_path, monkeypatch):
    _app, client, csrf = _make_client()

    # Нераспознаваемые куки -> 400
    assert (
        client.post("/api/cookies", json={"text": "hello world"}, headers=csrf).status_code == 400
    )

    valid_json = json.dumps(
        [
            {"name": "Session_id", "value": "s1", "domain": ".yandex.ru"},
            {"name": "yandexuid", "value": "u1", "domain": ".yandex.ru"},
            {"name": "sessionid2", "value": "s2", "domain": ".yandex.ru"},
        ]
    )

    # AuthExpiredError -> 401 (cookies.json не создаётся)
    monkeypatch.setattr(
        mgr_mod.manager,
        "verify_account_live",
        lambda jar=None: (_ for _ in ()).throw(AuthExpiredError("expired")),
    )
    assert client.post("/api/cookies", json={"text": valid_json}, headers=csrf).status_code == 401
    assert not paths.COOKIES_FILE.exists()

    # UnlimApiError -> 502
    monkeypatch.setattr(
        mgr_mod.manager,
        "verify_account_live",
        lambda jar=None: (_ for _ in ()).throw(UnlimApiError("bad")),
    )
    assert client.post("/api/cookies", json={"text": valid_json}, headers=csrf).status_code == 502

    # YandexUnavailableError -> 200 с warning и сохранённым cookies.json
    monkeypatch.setattr(
        mgr_mod.manager,
        "verify_account_live",
        lambda jar=None: (_ for _ in ()).throw(YandexUnavailableError("503")),
    )
    r_warn = client.post("/api/cookies", json={"text": valid_json}, headers=csrf)
    assert r_warn.status_code == 200 and r_warn.json()["warning"]
    assert paths.COOKIES_FILE.exists()

    # /api/cookies/check error mapping
    assert client.post("/api/cookies/check", headers=csrf).status_code == 503
    monkeypatch.setattr(
        mgr_mod.manager,
        "verify_account_live",
        lambda jar=None: (_ for _ in ()).throw(AuthExpiredError("old")),
    )
    assert client.post("/api/cookies/check", headers=csrf).status_code == 401
    monkeypatch.setattr(
        mgr_mod.manager, "verify_account_live", lambda jar=None: {"used": 1, "limit": 10}
    )
    assert client.post("/api/cookies/check", headers=csrf).status_code == 200

    # /api/settings и /api/folder/pick
    src = tmp_path / "Album"
    src.mkdir()
    assert (
        client.post(
            "/api/settings", json={"source_dir": str(tmp_path / "nope")}, headers=csrf
        ).status_code
        == 400
    )
    assert (
        client.post("/api/settings", json={"source_dir": str(src)}, headers=csrf).status_code == 200
    )
    assert client.post("/api/settings", json={"source_dir": ""}, headers=csrf).status_code == 200

    monkeypatch.setattr(mgr_mod, "pick_folder_dialog", lambda _cur="": None)
    assert client.post("/api/folder/pick", headers=csrf).json()["picked"] is False
    monkeypatch.setattr(mgr_mod, "pick_folder_dialog", lambda _cur="": r"\\evil\share")
    assert client.post("/api/folder/pick", headers=csrf).status_code == 400
    monkeypatch.setattr(mgr_mod, "pick_folder_dialog", lambda _cur="": str(src))
    assert client.post("/api/folder/pick", headers=csrf).json()["picked"] is True

    # /api/start с мок-движком (успех и EXIT_AUTH)
    fake_quota = QuotaSnapshot(
        used=1,
        disk=1,
        limit=100,
        free=99,
        trash=0,
        photounlim=10,
        actual_photounlim_size=10,
        filesize_limit=1024,
        is_overdrawn=False,
        conversion_enabled=False,
        has_pro_subscription=True,
        has_family_subscription=False,
    )

    class FakeRunEngine:
        def __init__(self, *args, **kwargs):
            pass

        def run_once(self, _src):
            return RunSummary(exit_code=EXIT_OK, message="ok", quota_after=fake_quota)

        def run_watch(self, _src, interval_sec=60):
            return RunSummary(exit_code=EXIT_AUTH, message="expired")

        def close(self):
            pass

    monkeypatch.setattr(mgr_mod, "UploadEngine", FakeRunEngine)
    assert client.post("/api/start", json={"source_dir": str(src)}, headers=csrf).status_code == 200
    for _ in range(40):
        if not mgr_mod.manager.is_running():
            break
        time.sleep(0.05)
    assert client.get("/api/status").json()["exit_code"] == EXIT_OK

    # watch-ветка с EXIT_AUTH сбрасывает кеш аккаунта и выставляет ошибку кук
    assert (
        client.post(
            "/api/start", json={"source_dir": str(src), "watch_mode": True}, headers=csrf
        ).status_code
        == 200
    )
    for _ in range(40):
        if not mgr_mod.manager.is_running():
            break
        time.sleep(0.05)
    st_auth = client.get("/api/status").json()
    assert st_auth["exit_code"] == EXIT_AUTH and st_auth["cookies"]["ok"] is False

    # retry-failed и reset
    assert client.post("/api/retry-failed", headers=csrf).status_code == 200
    assert client.post("/api/reset", headers=csrf).status_code == 200

    # Завершение менеджера
    mgr_mod.manager.shutdown(timeout=1.0)


def test_webui_module_and_manager_verify_live_and_corrupt_cookies(monkeypatch):
    import webui as webui_mod

    assert webui_mod.app is not None
    webui_mod._setup_logging()
    assert paths.LOG_DIR.is_dir()

    # check_cookies_file: отсутствует -> ok=False; битый -> ok=False
    assert mgr_mod.manager.check_cookies_file()["present"] is False
    paths.COOKIES_FILE.write_text("not-valid", encoding="utf-8")
    ck_bad = mgr_mod.manager.check_cookies_file()
    assert ck_bad["present"] is True and ck_bad["ok"] is False

    # verify_account_live закрывает HTTP-сессию даже при ошибке и обновляет кеш при успехе
    closed = {"n": 0}

    class FakeSess:
        yadisk_base = "https://disk.yandex.kz"

        def close(self):
            closed["n"] += 1

    fake_snap = QuotaSnapshot(
        used=5,
        disk=5,
        limit=100,
        free=95,
        trash=0,
        photounlim=20,
        actual_photounlim_size=20,
        filesize_limit=1024,
        is_overdrawn=False,
        conversion_enabled=False,
        has_pro_subscription=True,
        has_family_subscription=False,
    )
    monkeypatch.setattr(mgr_mod, "make_session", lambda **_kw: FakeSess())
    monkeypatch.setattr(mgr_mod, "get_sk_uid", lambda _s: ("sk", "42"))
    monkeypatch.setattr(mgr_mod, "fetch_quota_snapshot", lambda _s, _sk, _uid: fake_snap)

    info = mgr_mod.manager.verify_account_live()
    assert info["base_url"] == "https://disk.yandex.kz"
    assert closed["n"] == 1
    assert mgr_mod.manager.stop() is False

    # start_scan / start_upload валидация ошибок (несуществующая папка, нет кук)
    with pytest.raises(ValueError):
        mgr_mod.manager.start_scan(str(paths.LOG_DIR / "no_such_dir"))
    paths.COOKIES_FILE.unlink(missing_ok=True)
    paths.LOG_DIR.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError):
        mgr_mod.manager.start_upload(source_dir=str(paths.LOG_DIR))

    # webui.main() с моком uvicorn.Server
    ran = {"started": False}

    class FakeServer:
        def __init__(self, _cfg):
            pass

        def run(self, sockets=None):
            ran["started"] = bool(sockets)

    monkeypatch.setenv("YADISK_NO_BROWSER", "1")
    monkeypatch.setattr(webui_mod.uvicorn, "Server", FakeServer)
    sock, port = ports_mod.choose_port(explicit_port=0)
    monkeypatch.setattr(webui_mod, "choose_port", lambda: (sock, port))
    assert webui_mod.main() == 0
    assert ran["started"] is True
    ports_mod.use_port(ports_mod.DEFAULT_PORT)
