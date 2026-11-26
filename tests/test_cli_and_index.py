"""Тесты CLI (upload_unlim.py) и постраничной индексации remote_index (с защитой от зацикливания)."""

from __future__ import annotations

import json
import sqlite3
import threading

import pytest

import upload_unlim
from tools.probe_unlim_upload import make_test_jpeg, make_test_mp4
from uploader.cookies import UnlimApiError, YandexUnavailableError
from uploader.engine import RunSummary
from uploader.remote_index import sync_remote_index
from uploader.state import UploadState
from uploader.utils import EXIT_INTERRUPTED, EXIT_LOCAL_IO, EXIT_OK, EXIT_PARTIAL, CancelledError


def test_cli_scan_status_retry_reset(tmp_path, capsys):
    src = tmp_path / "Папка"
    src.mkdir()
    (src / "photo.jpg").write_bytes(make_test_jpeg(salt=b"cli1"))
    (src / "clip.mp4").write_bytes(make_test_mp4(salt=b"cli2"))
    (src / "doc.pdf").write_bytes(b"%PDF-1.4")

    assert upload_unlim.main(["scan", "--source", str(src)]) == EXIT_OK
    out_scan = capsys.readouterr().out
    assert "Фото:" in out_scan and "Видео:" in out_scan

    assert upload_unlim.main(["status"]) == EXIT_OK
    out_st = capsys.readouterr().out
    assert "1 фото" in out_st and "1 видео" in out_st

    assert upload_unlim.main(["retry-failed"]) == EXIT_OK
    assert upload_unlim.main(["reset"]) == EXIT_OK
    assert UploadState().stats()["total_files"] == 0


def test_remote_index_pagination_and_repeat_guard(tmp_path):
    class FakeResp:
        def __init__(self, body):
            self.status_code = 200
            self.text = json.dumps(body)
            self.headers = {"Content-Type": "application/json"}
            self.url = "https://disk.yandex.ru/models-v2"
            self._body = body

        def json(self):
            return self._body

    class LoopingSession:
        yadisk_base = "https://disk.yandex.ru"

        def __init__(self):
            self.offsets: list[int] = []

        def post(self, _url, params=None, json=None, timeout=60):
            rp = (json or {}).get("requestParams") or {}
            off = rp["offset"]
            self.offsets.append(off)
            if off == 0:
                return FakeResp(
                    [
                        {"path": "/photounlim", "type": "dir"},
                        {
                            "path": "/photounlim/a.jpg",
                            "name": "a.jpg",
                            "meta": {"size": 10, "md5": "AAA"},
                        },
                        {
                            "path": "/photounlim/b.mp4",
                            "name": "b.mp4",
                            "meta": {"size": 20, "md5": "BBB"},
                        },
                    ]
                )
            # Яндекс зациклился и повторно прислал те же файлы при offset=2
            return FakeResp(
                [
                    {"path": "/photounlim", "type": "dir"},
                    {
                        "path": "/photounlim/a.jpg",
                        "name": "a.jpg",
                        "meta": {"size": 10, "md5": "AAA"},
                    },
                    {
                        "path": "/photounlim/b.mp4",
                        "name": "b.mp4",
                        "meta": {"size": 20, "md5": "BBB"},
                    },
                ]
            )

    st = UploadState(tmp_path / "idx.db")
    sess = LoopingSession()
    count = sync_remote_index(sess, "sk", "1", st, page_size=2)
    assert count == 2
    assert sess.offsets == [0, 2]
    assert st.find_remote_by_hash("aaa", 10) == "/photounlim/a.jpg"
    assert st.find_remote_by_hash("bbb", 20) == "/photounlim/b.mp4"


def test_remote_index_404_empty_sk_refresh_500_and_cancel(tmp_path, monkeypatch):
    monkeypatch.setattr("uploader.remote_index.LIST_PAGE_PAUSES", (0,))

    class FakeResp:
        def __init__(self, status, body):
            self.status_code = status
            self._body = body
            self.text = body if isinstance(body, str) else json.dumps(body)
            self.headers = {"Content-Type": "application/json"}
            self.url = "https://disk.yandex.ru/models-v2"

        def json(self):
            if isinstance(self._body, (dict, list)):
                return self._body
            return json.loads(self.text)

    class ScriptedSession:
        yadisk_base = "https://disk.yandex.ru"

        def __init__(self, posts, gets=None):
            self.posts = list(posts)
            self.gets = list(gets or [])

        def get(self, url, timeout=30):
            return self.gets.pop(0)

        def post(self, _url, params=None, json=None, timeout=60):
            return self.posts.pop(0)

    # HTTP 404 на новом аккаунте -> пустой индекс без ошибки
    st = UploadState(tmp_path / "empty.db")
    assert sync_remote_index(ScriptedSession([FakeResp(404, "not found")]), "sk", "1", st) == 0  # type: ignore[arg-type]

    # bad_sk -> автообновление sk через GET /client/disk и повтор
    sess_refresh = ScriptedSession(
        posts=[
            FakeResp(200, {"error": "bad_sk"}),
            FakeResp(
                200,
                [{"path": "/photounlim/x.jpg", "name": "x.jpg", "meta": {"size": 5, "md5": "abc"}}],
            ),
        ],
        gets=[FakeResp(200, '{"sk":"sk-new","uid":"1"}')],
    )
    assert sync_remote_index(sess_refresh, "sk-old", "1", st) == 1  # type: ignore[arg-type]

    # HTTP 200 с бизнес-ошибкой -> UnlimApiError
    with pytest.raises(UnlimApiError):
        sync_remote_index(ScriptedSession([FakeResp(200, {"error": "unknown"})]), "sk", "1", st)  # type: ignore[arg-type]

    # HTTP 503 на всех попытках -> YandexUnavailableError
    with pytest.raises(YandexUnavailableError):
        sync_remote_index(
            ScriptedSession([FakeResp(503, "err"), FakeResp(503, "err")]), "sk", "1", st
        )  # type: ignore[arg-type]

    # Отмена через stop_event
    ev = threading.Event()
    ev.set()
    with pytest.raises(CancelledError):
        sync_remote_index(ScriptedSession([]), "sk", "1", st, stop_event=ev)  # type: ignore[arg-type]


def test_cli_run_watch_probe_and_error_exit_codes(tmp_path, monkeypatch):
    src = tmp_path / "Pics"
    src.mkdir()

    calls: list[str] = []

    class FakeEngine:
        def __init__(self, *args, **kwargs):
            pass

        def run_once(self, source):
            calls.append(f"once:{source}")
            return RunSummary(exit_code=EXIT_OK)

        def run_watch(self, source, interval_sec=60):
            calls.append(f"watch:{source}:{interval_sec}")
            return RunSummary(exit_code=EXIT_OK)

        def close(self):
            calls.append("close")

    monkeypatch.setattr(upload_unlim, "UploadEngine", FakeEngine)
    assert upload_unlim.main(["run", "--source", str(src)]) == EXIT_OK
    assert (
        upload_unlim.main(["run", "--source", str(src), "--watch", "--watch-interval", "30"])
        == EXIT_OK
    )
    assert any(c.startswith("once:") for c in calls)
    assert any(c.startswith("watch:") and c.endswith(":30") for c in calls)
    assert calls.count("close") == 2

    # Несуществующая папка при scan -> EXIT_LOCAL_IO
    assert (
        upload_unlim.main(["scan", "--source", str(tmp_path / "does-not-exist")]) == EXIT_LOCAL_IO
    )

    # Некорректный _env_int -> fallback
    monkeypatch.setenv("MAX_WORKERS", "not-a-number")
    assert upload_unlim._env_int("MAX_WORKERS", 2) == 2

    # probe subcommand
    monkeypatch.setattr(
        "tools.probe_unlim_upload.run_probe", lambda cookies_file=None, keep_files=False: EXIT_OK
    )
    assert upload_unlim.main(["probe"]) == EXIT_OK

    # Глобальные обработчики исключений в main()
    monkeypatch.setattr(
        upload_unlim, "_cmd_status", lambda _a: (_ for _ in ()).throw(KeyboardInterrupt())
    )
    assert upload_unlim.main(["status"]) == EXIT_INTERRUPTED

    monkeypatch.setattr(
        upload_unlim,
        "_cmd_status",
        lambda _a: (_ for _ in ()).throw(sqlite3.OperationalError("locked")),
    )
    assert upload_unlim.main(["status"]) == EXIT_LOCAL_IO

    monkeypatch.setattr(
        upload_unlim, "_cmd_status", lambda _a: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    assert upload_unlim.main(["status"]) == EXIT_PARTIAL
