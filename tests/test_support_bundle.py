"""Тесты безопасного ZIP-архива поддержки (логи + support-info.json без утечки секретов)."""

from __future__ import annotations

import io
import json
import os
import time
import zipfile

from fastapi.testclient import TestClient

from uploader import APP_VERSION, paths
from uploader.state import UploadState
from uploader.webapp import config as cfg_mod
from uploader.webapp import logs as logs_mod
from uploader.webapp import manager as mgr_mod
from uploader.webapp import ports as ports_mod
from uploader.webapp.api import create_app


def _make_client():
    ports_mod.use_port(ports_mod.DEFAULT_PORT)
    app = create_app(allow_testserver=False)
    client = TestClient(app, base_url=f"http://127.0.0.1:{ports_mod.DEFAULT_PORT}")
    return app, client


def test_scrub_support_text_redacts_secrets_and_usernames():
    raw = (
        "Cookie: Session_id=TOPSECRET1; yandexuid=999888; sessionid2=SECRET2\n"
        "Authorization: OAuth y0_AgAAAASECRETTOKEN123456\n"
        '{"sk": "u12345secret", "uid": 987654321, "account_name": "ivan.petrov"}\n'
        "{'Session_id': 'PYDICT_SID', 'Cookie': 'L=PYCOOKIE; mda2_beacon=BEACON1', 'Authorization': 'Basic U0VDUkVU'}\n"
        "Session_id=\"QUOTED_SID\" sk='QUOTED_SK'\n"
        "https://proxyuser:proxypass99@proxy.local:8080/upload/x?tok=1\n"
        "https://uploader1.disk.yandex.net/upload-target/abc?uid=42&rtoken=SIGN123\n"
        r"File C:\Users\IvanPetrov\Pictures\family.jpg and C:\\Users\\EscapedAlice\\img.jpg failed"
        "\n/home/ivanpetrov/photos/a.jpg and /Users/anna/img.jpg"
    )
    cleaned = logs_mod.scrub_support_text(raw)
    for secret in (
        "TOPSECRET1",
        "SECRET2",
        "999888",
        "y0_AgAAAASECRETTOKEN123456",
        "u12345secret",
        "987654321",
        "ivan.petrov",
        "PYDICT_SID",
        "PYCOOKIE",
        "BEACON1",
        "U0VDUkVU",
        "QUOTED_SID",
        "QUOTED_SK",
        "proxyuser",
        "proxypass99",
        "SIGN123",
        "uid=42",
        "IvanPetrov",
        "EscapedAlice",
        "ivanpetrov",
        "anna",
    ):
        assert secret not in cleaned, f"Секрет утек в очищенный текст: {secret}"
    assert "uploader1.disk.yandex.net/<redacted>" in cleaned
    assert r"C:\Users\<USER>" in cleaned
    assert r"C:\\Users\\<USER>" in cleaned
    assert "/home/<USER>" in cleaned
    assert logs_mod.scrub_support_text("") == ""


def test_support_bundle_endpoint_and_sanitization(tmp_path):
    _app, client = _make_client()

    # Создаём чувствительные файлы рядом и в logs/
    paths.LOG_DIR.mkdir(parents=True, exist_ok=True)
    (paths.LOG_DIR / "upload.log").write_text(
        "INFO | url https://uploader1.disk.yandex.net/t/1?rtoken=LEAK1\n"
        "WARN | Session_id=COOKIELEAK sk=SKLEAK uid=123456\n",
        encoding="utf-8",
    )
    (paths.LOG_DIR / "probe_unlim_upload.txt").write_text("OK photo\n", encoding="utf-8")
    # Посторонний файл в logs/ не должен попасть в ZIP
    (paths.LOG_DIR / "cookies.json").write_text(
        '{"Session_id": "SHOULD_NOT_INCLUDE"}', encoding="utf-8"
    )
    # Старый архив (>1 ч) должен автоматически удалиться
    stale_zip = paths.LOG_DIR / "yadisk-unlim-logs-20200101-000000.zip"
    stale_zip.write_bytes(b"old")
    old_ts = time.time() - 7200
    os.utime(stale_zip, (old_ts, old_ts))

    # Настройки, аккаунт и запись об ошибке в БД
    cfg_mod.save_config({"source_dir": str(tmp_path / "SecretUserFolder")})
    mgr_mod.manager.set_account_cache(
        {
            "used": 100,
            "limit": 1000,
            "actual_photounlim_size": 500,
            "filesize_limit": 1024**3,
            "unlimited_free": True,
            "account_name": "PRIVATE_LOGIN_123",
            "warning": None,
        }
    )
    mgr_mod.manager.add_event("err", "Сбой для https://disk.yandex.ru/x?sk=EVENT_SK_LEAK")

    st = UploadState(paths.DB_FILE)
    st.upsert_scanned_files(
        [
            {
                "local_path": str(tmp_path / "private_family.jpg"),
                "rel_path": "private_family.jpg",
                "name": "private_family.jpg",
                "accepted": True,
                "media_kind": "photo",
                "mime": "image/jpeg",
                "reason": None,
                "size": 1234,
                "mtime_ns": 100,
                "shot_time": 1_700_000_000.0,
            }
        ],
        str(tmp_path),
    )
    row = st.take_next_pending()
    assert row is not None
    st.mark_failed_permanent(row.id, "HTTP 500 at https://uploader.disk.yandex.net/u?token=ERRLEAK")

    # Cross-site запрос на /api/logs/bundle обязан блокироваться, а GET / — открываться
    assert (
        client.get("/api/logs/bundle", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403
    )
    assert client.get("/", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200

    resp = client.get("/api/logs/bundle")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/zip")
    assert resp.headers.get("cache-control") == "no-store"
    assert not stale_zip.exists()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        names = set(zf.namelist())
        assert "upload.log" in names
        assert "probe_unlim_upload.txt" in names
        assert "support-info.json" in names
        assert "cookies.json" not in names
        assert zf.getinfo("upload.log").date_time[0] >= 2024

        all_text = "".join(zf.read(n).decode("utf-8") for n in names)
        for leak in (
            "LEAK1",
            "COOKIELEAK",
            "SKLEAK",
            "SHOULD_NOT_INCLUDE",
            "PRIVATE_LOGIN_123",
            "SecretUserFolder",
            "EVENT_SK_LEAK",
            "ERRLEAK",
            "private_family.jpg",
        ):
            assert leak not in all_text, f"Утечка в support bundle: {leak}"

        info = json.loads(zf.read("support-info.json"))
        assert info["app_version"] == APP_VERSION
        assert info["config"]["source_dir_set"] is True
        assert "source_dir" not in info["config"]
        assert "account_name" not in (info["account"] or {})
        assert info["stats"]["failed"] == 1
        assert len(info["recent_errors"]) == 1


def test_support_bundle_truncates_oversized_log(monkeypatch):
    monkeypatch.setattr(logs_mod, "_MAX_LOG_BYTES_PER_FILE", 256)
    paths.LOG_DIR.mkdir(parents=True, exist_ok=True)
    big = "\n".join(f"line-{i:04d}-payload-xxxxxxxx" for i in range(60)) + "\n"
    (paths.LOG_DIR / "webui.log").write_text(big, encoding="utf-8")

    bundle = logs_mod.build_support_bundle()
    with zipfile.ZipFile(bundle) as zf:
        content = zf.read("webui.log").decode("utf-8")
    assert "обрезаны первые" in content
    assert "line-0059" in content
    assert "line-0000" not in content


def test_support_bundle_json_stays_valid_with_cookie_headers_and_unique_names():
    mgr_mod.manager.add_event(
        "err",
        "Header Cookie: Session_id=TOPSECRET_JSON; yandexuid=123 | Authorization: Bearer TOKEN_JSON",
    )
    b1 = logs_mod.build_support_bundle()
    b2 = logs_mod.build_support_bundle()
    assert b1 != b2 and b1.exists() and b2.exists()

    with zipfile.ZipFile(b1) as zf:
        raw_json = zf.read("support-info.json").decode("utf-8")
    parsed = json.loads(raw_json)  # не должно падать JSONDecodeError!
    assert "TOPSECRET_JSON" not in raw_json
    assert "TOKEN_JSON" not in raw_json
    assert any("Header Cookie:" in ev["text"] for ev in parsed["events"])
