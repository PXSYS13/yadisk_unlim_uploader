"""Тесты общих утилит: redact_urls, безопасность путей, UTF-8 обрезка, хеширование, SQLite и форматирование."""

from __future__ import annotations

import sqlite3
import threading

import pytest

from uploader import utils


def test_redact_urls_masks_paths_and_queries():
    assert utils.redact_urls("") == ""
    assert (
        utils.redact_urls(
            "GET https://uploader1.disk.yandex.net/upload-target/secret?uid=1&tok=abc failed"
        )
        == "GET https://uploader1.disk.yandex.net/<redacted> failed"
    )
    assert utils.redact_urls("See https://disk.yandex.ru") == "See https://disk.yandex.ru"


def test_validate_source_dir_safe_blocks_unc_devices_and_control_chars():
    assert utils.validate_source_dir_safe("  D:/Фото  ") == "D:/Фото"
    for bad in (
        "",
        "   ",
        "C:\\bad\x00dir",
        "C:\\bad\ndir",
        r"\\server\share",
        r"\\.\C:",
        r"\\?\UNC\srv\sh",
    ):
        with pytest.raises(ValueError):
            utils.validate_source_dir_safe(bad)
    with pytest.raises(ValueError):
        utils.validate_source_dir_safe(123)  # type: ignore[arg-type]
    assert utils.validate_source_dir_safe(r"\\server\share", allow_unc=True) == r"\\server\share"


def test_long_path_strip_and_is_path_inside(tmp_path):
    assert utils.strip_long_prefix(r"\\?\C:\Photos\a.jpg") == r"C:\Photos\a.jpg"
    assert utils.strip_long_prefix(r"\\?\UNC\srv\share\a.jpg") == r"\\srv\share\a.jpg"
    assert utils.strip_long_prefix("/tmp/a.jpg") == "/tmp/a.jpg"

    long_rel = str(tmp_path / ("a" * 260))
    lp = utils.to_long_path(long_rel)
    if utils.IS_WINDOWS:
        assert lp.startswith("\\\\?\\")
        assert utils.to_long_path(lp) == lp

    root = tmp_path / "root"
    child = root / "sub" / "pic.jpg"
    outside = tmp_path / "other" / "pic.jpg"
    child.parent.mkdir(parents=True)
    outside.parent.mkdir(parents=True)
    child.write_bytes(b"1")
    outside.write_bytes(b"2")

    assert utils.is_path_inside(str(child), str(root)) is True
    assert utils.is_path_inside(str(outside), str(root)) is False


def test_sanitize_and_truncate_utf8_names():
    assert utils.sanitize_remote_name('bad:name*?"<>|.jpg') == "bad_name_.jpg"
    assert utils.sanitize_remote_name("   ...  ") == "media"
    assert utils.sanitize_remote_name(".jpg") == "jpg"

    # Многобайтовая кириллица не должна резаться посередине UTF-8 символа
    long_cyr = "Фотография_" * 40
    res = utils.truncate_utf8_name(long_cyr, ".jpeg", max_bytes=64)
    assert res.endswith(".jpeg")
    assert len(res.encode("utf-8")) <= 64

    tagged = utils.name_with_tag("IMG_0001.JPG", "_abc123")
    assert tagged == "IMG_0001_abc123.JPG"


def test_compute_hashes_and_cancellation(tmp_path):
    p = tmp_path / "data.bin"
    p.write_bytes(b"hello world" * 100)
    md5, sha256, sz = utils.compute_hashes_with_size(str(p), chunk_size=32)
    assert sz == p.stat().st_size
    assert utils.compute_hashes(str(p), chunk_size=32) == (md5, sha256)

    ev = threading.Event()
    ev.set()
    with pytest.raises(utils.CancelledError):
        utils.compute_hashes_with_size(str(p), stop_event=ev)


def test_sqlite_tx_and_disk_error_classification():
    conn = sqlite3.connect(":memory:", isolation_level=None)
    conn.execute("CREATE TABLE t (x INTEGER)")
    with utils.sqlite_tx(conn):
        conn.execute("INSERT INTO t VALUES (1)")
    assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1

    with pytest.raises(RuntimeError), utils.sqlite_tx(conn):
        conn.execute("INSERT INTO t VALUES (2)")
        raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1
    conn.close()

    assert utils.is_sqlite_disk_error(sqlite3.OperationalError("database or disk is full")) is True
    assert (
        utils.is_sqlite_disk_error(sqlite3.DatabaseError("database disk image is malformed"))
        is True
    )
    assert utils.is_sqlite_disk_error(sqlite3.OperationalError("no such table")) is False
    assert utils.is_sqlite_disk_error(ValueError("disk is full")) is False


def test_formatting_and_keep_awake():
    assert utils.plural(1, "файл", "файла", "файлов") == "файл"
    assert utils.plural(3, "файл", "файла", "файлов") == "файла"
    assert utils.plural(11, "файл", "файла", "файлов") == "файлов"
    assert utils.plural(22, "файл", "файла", "файлов") == "файла"
    assert utils.files_text(1005) == "1 005 файлов"

    assert utils.human_bytes(None) == "0 Б"
    assert utils.human_bytes(512) == "512 Б"
    assert utils.human_bytes(1536) == "1.5 КБ"
    assert utils.human_bytes(-2 * 1024 * 1024) == "-2.0 МБ"
    assert utils.human_bytes(5 * 1024**4) == "5.0 ТБ"

    with utils.keep_awake():
        pass


def test_windows_safe_rotating_handler_rollover_and_locked_fallback(tmp_path, monkeypatch):
    import logging

    log_file = tmp_path / "rot.log"
    h = utils.WindowsSafeRotatingFileHandler(log_file, maxBytes=40, backupCount=2, delay=True)
    # delay=True: файл не создаётся до первой записи
    assert not log_file.exists()

    rec = logging.LogRecord("t", logging.INFO, "", 0, "A" * 50, (), None)
    try:
        h.emit(rec)
        h.emit(rec)
        assert log_file.exists() and (tmp_path / "rot.log.1").exists()

        # Имитируем WinError 32 при ротации: .1 бэкап НЕ удаляется, запись не падает
        monkeypatch.setattr(
            utils.os, "replace", lambda _a, _b: (_ for _ in ()).throw(PermissionError("locked"))
        )
        h.emit(rec)
        assert (tmp_path / "rot.log.1").exists()
    finally:
        h.close()
