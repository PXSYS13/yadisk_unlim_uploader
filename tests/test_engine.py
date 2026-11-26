"""Интеграционные тесты UploadEngine: дедуп, in-flight дубли, отключённый диск, лимит размера, смена папки, watch."""

from __future__ import annotations

import os
import threading
import time

from tools.probe_unlim_upload import make_test_jpeg, make_test_mp4
from uploader.cookies import (
    AuthExpiredError,
    CaptchaError,
    RateLimitError,
    UnlimApiError,
    YandexUnavailableError,
)
from uploader.engine import LiveProgress, UploadEngine, scan_source_folder
from uploader.quota_guard import QuotaSnapshot
from uploader.state import UploadRow, UploadState
from uploader.transport_base import UploadResult
from uploader.utils import (
    EXIT_AUTH,
    EXIT_INTERRUPTED,
    EXIT_LOCAL_IO,
    EXIT_OK,
    EXIT_OUTAGE,
    EXIT_PARTIAL,
    EXIT_QUOTA_DRIFT,
)


def _ok_quota(
    used: int = 1000, unlim: int = 5000, filesize_limit: int = 50 * 1024**3
) -> QuotaSnapshot:
    return QuotaSnapshot(
        used=used,
        disk=used,
        limit=200 * 1024**3,
        free=199 * 1024**3,
        trash=0,
        photounlim=unlim,
        actual_photounlim_size=unlim,
        filesize_limit=filesize_limit,
        is_overdrawn=False,
        conversion_enabled=False,
        has_pro_subscription=True,
        has_family_subscription=False,
        unlimited_free=True,
        warning=None,
    )


class FakeTransport:
    name = "fake"

    def __init__(self, fail_always: Exception | None = None, fail_first_rel: str | None = None):
        self.uploaded: list[str] = []
        self.fail_always = fail_always
        self.fail_first_rel = fail_first_rel
        self._lock = threading.Lock()

    def upload_file(
        self, row: UploadRow, *, md5: str, sha256: str, on_progress=None, stop_event=None
    ) -> UploadResult:
        if self.fail_always is not None:
            raise self.fail_always
        if self.fail_first_rel and row.rel_path == self.fail_first_rel:
            time.sleep(0.05)
            raise UnlimApiError("temporary file-specific rejection")
        if on_progress:
            on_progress(row.size, row.size)
        with self._lock:
            self.uploaded.append(row.rel_path)
        return UploadResult(
            outcome="uploaded",
            remote_id=f"/photounlim/{row.remote_name}",
            remote_name=row.remote_name,
            resource={
                "path": f"/photounlim/{row.remote_name}",
                "meta": {"storage_type": "photounlim"},
            },
        )


def test_full_cycle_dedup_idempotency_and_readonly_source(tmp_path):
    src = tmp_path / "Фотоархив"
    sub = src / "2024 Лето"
    sub.mkdir(parents=True)

    f_jpg = src / "a.jpg"
    f_jpg_dup = sub / "a_copy.jpg"
    f_mp4 = sub / "video.mp4"
    f_dng = src / "raw_photo.dng"
    f_txt = src / "readme.txt"

    jpg_bytes = make_test_jpeg("2024:06:10 10:00:00", b"unique-jpg")
    mp4_bytes = make_test_mp4(1718000000, b"unique-mp4")
    f_jpg.write_bytes(jpg_bytes)
    f_jpg_dup.write_bytes(jpg_bytes)
    f_mp4.write_bytes(mp4_bytes)
    f_dng.write_bytes(b"II\x2a\x00" + b"\x00" * 64)
    f_txt.write_text("не фото", encoding="utf-8")

    before_files = {
        p: (p.stat().st_size, p.stat().st_mtime_ns) for p in (f_jpg, f_jpg_dup, f_mp4, f_dng, f_txt)
    }

    st = UploadState(tmp_path / "state.db")
    tr = FakeTransport()
    eng = UploadEngine(
        st,
        workers=2,
        transport=tr,
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    res1 = eng.run_once(str(src))
    assert res1.exit_code == EXIT_OK
    assert res1.uploaded == 2
    assert res1.skipped_dup_local == 1

    counts = st.stats()
    assert counts["uploaded"] == 2
    assert counts["skipped_dup_local"] == 1
    assert counts["skipped_unsupported"] == 2
    assert counts["pending"] == 0

    for p, expected in before_files.items():
        assert p.exists() and (p.stat().st_size, p.stat().st_mtime_ns) == expected

    res2 = eng.run_once(str(src))
    assert res2.exit_code == EXIT_OK
    assert res2.uploaded == 0
    assert len(tr.uploaded) == 2


def test_inflight_duplicate_does_not_lose_file_when_first_copy_fails(tmp_path):
    src = tmp_path / "dups"
    src.mkdir()
    payload = make_test_jpeg("2024:06:10 10:00:00", b"race-dup")
    (src / "a_first.jpg").write_bytes(payload)
    (src / "b_second.jpg").write_bytes(payload)

    st = UploadState(tmp_path / "state.db")
    # Первый файл всегда падает с UnlimApiError — второй ОБЯЗАН дождаться и загрузиться сам, не пропасть!
    tr = FakeTransport(fail_first_rel="a_first.jpg")
    eng = UploadEngine(
        st,
        workers=2,
        transport=tr,
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    res = eng.run_once(str(src))
    assert "b_second.jpg" in tr.uploaded
    assert st.stats()["uploaded"] == 1
    assert res.exit_code in (EXIT_OK, EXIT_PARTIAL)


def test_oversized_file_not_looped_and_folder_switch_prunes_old_pending(tmp_path):
    dir_a = tmp_path / "FolderA"
    dir_b = tmp_path / "FolderB"
    dir_a.mkdir()
    dir_b.mkdir()
    (dir_a / "big.mp4").write_bytes(make_test_mp4(salt=b"big") + b"\x00" * 2048)
    (dir_b / "small.jpg").write_bytes(make_test_jpeg(salt=b"small"))

    st = UploadState(tmp_path / "state.db")
    tr = FakeTransport()
    # Лимит файла 500 байт -> big.mp4 уходит в skipped_limit
    eng = UploadEngine(
        st,
        workers=1,
        transport=tr,
        quota_fetcher=lambda: _ok_quota(filesize_limit=500),
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    r1 = eng.run_once(str(dir_a))
    assert r1.exit_code == EXIT_OK
    assert st.stats()["skipped_limit"] == 1
    assert st.stats()["pending"] == 0

    # Повторный скан FolderA не должен сбрасывать skipped_limit обратно в pending!
    r1b = eng.run_once(str(dir_a))
    assert r1b.uploaded == 0 and st.stats()["skipped_limit"] == 1 and st.stats()["pending"] == 0

    # Переключение на FolderB: загрузится только small.jpg
    r2 = eng.run_once(str(dir_b))
    assert r2.exit_code == EXIT_OK
    assert tr.uploaded == ["small.jpg"]


def test_disconnected_drive_exits_local_io_without_failing_queue(tmp_path):
    src = tmp_path / "usb_drive"
    src.mkdir()
    for i in range(3):
        (src / f"p{i}.jpg").write_bytes(make_test_jpeg(salt=f"u{i}".encode()))

    class DisconnectingTransport:
        name = "disc"

        def upload_file(self, row, *, md5, sha256, on_progress=None, stop_event=None):
            # Имитируем отключение USB-диска (папка исчезла)
            for f in src.iterdir():
                f.unlink()
            src.rmdir()
            raise FileNotFoundError(row.local_path)

    st = UploadState(tmp_path / "state.db")
    eng = UploadEngine(
        st,
        workers=1,
        transport=DisconnectingTransport(),
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    res = eng.run_once(str(src))
    assert res.exit_code == EXIT_LOCAL_IO
    # Очередь не испорчена — ни один файл не помечен failed
    assert st.stats()["failed"] == 0
    assert st.stats()["pending"] == 3


def test_outage_circuit_breaker_exits_with_outage(tmp_path, monkeypatch):
    monkeypatch.setattr("uploader.engine.OUTAGE_STREAK_LIMIT", 3)
    src = tmp_path / "src"
    src.mkdir()
    for i in range(4):
        (src / f"p{i}.jpg").write_bytes(make_test_jpeg(salt=f"s{i}".encode()))

    st = UploadState(tmp_path / "state.db")
    tr = FakeTransport(fail_always=YandexUnavailableError("HTTP 503"))
    eng = UploadEngine(
        st,
        workers=1,
        transport=tr,
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    monkeypatch.setattr(eng, "_wait_cooldown", lambda: None)
    res = eng.run_once(str(src))
    assert res.exit_code == EXIT_OUTAGE
    assert st.stats()["failed"] == 0
    assert st.stats()["pending"] == 4


def test_quota_drift_stops_engine_mid_run(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "one.jpg").write_bytes(make_test_jpeg(salt=b"drift"))

    calls = {"n": 0}

    def quota_fn():
        calls["n"] += 1
        return _ok_quota(used=1000 if calls["n"] == 1 else 25 * 1024 * 1024)

    st = UploadState(tmp_path / "state.db")
    eng = UploadEngine(
        st,
        workers=1,
        transport=FakeTransport(),
        quota_fetcher=quota_fn,
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    res = eng.run_once(str(src))
    assert res.exit_code == EXIT_QUOTA_DRIFT


def test_watch_mode_picks_up_new_settled_file(tmp_path):
    src = tmp_path / "watch_dir"
    src.mkdir()
    first = src / "first.jpg"
    first.write_bytes(make_test_jpeg(salt=b"first"))
    old = time.time() - 60
    os.utime(first, (old, old))

    st = UploadState(tmp_path / "state.db")
    tr = FakeTransport()
    stop_event = threading.Event()
    eng = UploadEngine(
        st,
        workers=1,
        transport=tr,
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
        stop_event=stop_event,
    )

    wait_calls = {"n": 0}
    orig_wait = stop_event.wait

    def fake_wait(_sec=None):
        wait_calls["n"] += 1
        if wait_calls["n"] == 1:
            second = src / "second.mp4"
            second.write_bytes(make_test_mp4(salt=b"second"))
            os.utime(second, (old, old))
            return False
        stop_event.set()
        return orig_wait(0)

    stop_event.wait = fake_wait  # type: ignore[method-assign]
    eng.run_watch(str(src), interval_sec=10)
    assert set(tr.uploaded) == {"first.jpg", "second.mp4"}


def test_engine_auth_expired_rate_limit_captcha_single_missing_and_progress(tmp_path, monkeypatch):
    # LiveProgress speed_bps & snapshot
    prog = LiveProgress()
    prog.set_phase("uploading")
    prog.bytes_samples.append((10.0, 0))
    prog.bytes_samples.append((12.0, 2000))
    prog.session_bytes = 2000
    snap = prog.snapshot()
    assert snap["phase"] == "uploading" and snap["session_bytes"] == 2000

    src = tmp_path / "src_misc"
    (src / "$RECYCLE.BIN").mkdir(parents=True)
    (src / "$RECYCLE.BIN" / "ignored.jpg").write_bytes(make_test_jpeg(salt=b"ign"))
    p1 = src / "one.jpg"
    p1.write_bytes(make_test_jpeg(salt=b"m1"))

    st = UploadState(tmp_path / "misc.db")
    sc = scan_source_folder(str(src), st)
    assert sc.photos == 1

    # 1. AuthExpiredError во время загрузки -> EXIT_AUTH, файл остаётся pending
    eng_auth = UploadEngine(
        st,
        workers=1,
        transport=FakeTransport(fail_always=AuthExpiredError("bad cookies")),
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    r_auth = eng_auth.run_once(str(src))
    assert r_auth.exit_code == EXIT_AUTH
    assert st.stats()["pending"] == 1

    # 2. RateLimitError на первой попытке, затем успех
    class FlakyRLTransport:
        name = "flaky-rl"

        def __init__(self):
            self.calls = 0

        def upload_file(self, row, *, md5, sha256, on_progress=None, stop_event=None):
            self.calls += 1
            if self.calls == 1:
                raise RateLimitError("HTTP 429")
            if self.calls == 2:
                raise CaptchaError("SmartCaptcha")
            return UploadResult(
                outcome="hardlinked",
                remote_id=f"/photounlim/{row.remote_name}",
                remote_name=row.remote_name,
                resource={
                    "path": f"/photounlim/{row.remote_name}",
                    "meta": {"storage_type": "photounlim"},
                },
            )

    eng_rl = UploadEngine(
        st,
        workers=1,
        transport=FlakyRLTransport(),
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    monkeypatch.setattr(eng_rl, "_wait_cooldown", lambda: None)
    r_rl = eng_rl.run_once(str(src))
    assert r_rl.exit_code == EXIT_OK
    assert r_rl.hardlinked == 1

    # 3. Одиночный пропавший файл (папка на месте) -> помечается failed, а не drive_gone
    p2 = src / "vanish.jpg"
    p2.write_bytes(make_test_jpeg(salt=b"vanish"))

    class VanishingTransport:
        name = "vanish"

        def upload_file(self, row, *, md5, sha256, on_progress=None, stop_event=None):
            p2.unlink(missing_ok=True)
            raise FileNotFoundError(row.local_path)

    eng_v = UploadEngine(
        st,
        workers=1,
        transport=VanishingTransport(),
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    r_v = eng_v.run_once(str(src))
    assert r_v.exit_code == EXIT_PARTIAL
    assert st.stats()["failed"] == 1

    # 4. Остановка через stop_event до начала -> EXIT_INTERRUPTED
    ev = threading.Event()
    ev.set()
    eng_stop = UploadEngine(
        st,
        workers=1,
        transport=FakeTransport(),
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index([]),
        stop_event=ev,
    )
    assert eng_stop.run_once(str(src)).exit_code == EXIT_INTERRUPTED
    eng_stop.close()


def test_engine_scan_missing_dir_remote_dup_and_quota_preflight_block(tmp_path):
    st = UploadState(tmp_path / "e2.db")
    try:
        scan_source_folder(str(tmp_path / "missing_dir"), st)
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("Ожидался FileNotFoundError для отсутствующей папки")

    src = tmp_path / "src_e2"
    src.mkdir()
    img_bytes = make_test_jpeg("2024:01:01 12:00:00", b"remote-dup-bytes")
    (src / "in_cloud.jpg").write_bytes(img_bytes)
    (src / "modified.jpg").write_bytes(make_test_jpeg("2024:01:02 12:00:00", b"mod-before"))

    import hashlib

    md5_cloud = hashlib.md5(img_bytes).hexdigest()

    # 1. Preflight QuotaGuard без подписки (strict=True, allow_quota_count=False) -> EXIT_QUOTA_DRIFT
    bad_q = QuotaSnapshot(
        used=20 * 1024**3,
        disk=20 * 1024**3,
        limit=10 * 1024**3,
        free=0,
        trash=0,
        photounlim=0,
        actual_photounlim_size=0,
        filesize_limit=1024**3,
        is_overdrawn=True,
        conversion_enabled=True,
        has_pro_subscription=False,
        has_family_subscription=False,
        unlimited_free=False,
        warning="Нет подписки Яндекс 360",
    )
    eng_block = UploadEngine(
        st,
        workers=1,
        strict_quota_guard=True,
        allow_quota_count=False,
        transport=FakeTransport(),
        quota_fetcher=lambda: bad_q,
        remote_indexer=lambda: st.replace_remote_index([]),
    )
    assert eng_block.run_once(str(src)).exit_code == EXIT_QUOTA_DRIFT

    # 2. Файл уже в remote_unlim_index -> skipped_remote, а второй файл возвращает duplicate_remote от транспорта
    class RemoteDupTransport:
        name = "rdup"

        def upload_file(self, row, *, md5, sha256, on_progress=None, stop_event=None):
            return UploadResult(
                outcome="duplicate_remote",
                remote_id=f"/photounlim/{row.remote_name}",
                remote_name=row.remote_name,
            )

    eng_dup = UploadEngine(
        st,
        workers=1,
        transport=RemoteDupTransport(),
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: st.replace_remote_index(
            [
                (
                    "/photounlim/in_cloud.jpg",
                    "in_cloud.jpg",
                    len(img_bytes),
                    md5_cloud,
                    1_700_000_000.0,
                )
            ]
        ),
    )
    res_dup = eng_dup.run_once(str(src))
    assert res_dup.exit_code == EXIT_OK
    assert res_dup.skipped_remote == 2
    assert st.stats()["skipped_remote"] == 2
    assert st.stats()["pending"] == 0


def test_engine_periodic_quota_check_and_remote_index_errors(tmp_path, monkeypatch):
    from uploader.quota_guard import QuotaGuard

    st = UploadState(tmp_path / "e3.db")
    src = tmp_path / "src_e3"
    src.mkdir()
    (src / "a.jpg").write_bytes(make_test_jpeg(salt=b"pq1"))

    # 1. Ошибка при sync_remote -> EXIT_AUTH / EXIT_OUTAGE
    eng_idx_auth = UploadEngine(
        st,
        workers=1,
        transport=FakeTransport(),
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: (_ for _ in ()).throw(AuthExpiredError("bad")),
    )
    assert eng_idx_auth.run_once(str(src)).exit_code == EXIT_AUTH

    eng_idx_out = UploadEngine(
        st,
        workers=1,
        transport=FakeTransport(),
        quota_fetcher=lambda: _ok_quota(),
        remote_indexer=lambda: (_ for _ in ()).throw(YandexUnavailableError("503")),
    )
    assert eng_idx_out.run_once(str(src)).exit_code == EXIT_OUTAGE

    # 2. _maybe_check_quota_drift: 3 ошибки подряд -> EXIT_OUTAGE; AuthExpired -> EXIT_AUTH; RateLimit -> cooldown
    monkeypatch.setattr("uploader.engine.QUOTA_CHECK_EVERY_FILES", 1)
    monkeypatch.setattr("uploader.engine.MAX_CONSECUTIVE_QUOTA_ERRORS", 2)

    q_calls = {"n": 0}

    def flaky_quota():
        q_calls["n"] += 1
        if q_calls["n"] == 1:
            raise RateLimitError("429")
        raise RuntimeError("net err")

    eng_q = UploadEngine(st, workers=1, transport=FakeTransport(), quota_fetcher=flaky_quota)
    guard = QuotaGuard(_ok_quota(), strict=True)
    eng_q._maybe_check_quota_drift(guard, 100)
    assert not eng_q._has_fatal()
    eng_q._maybe_check_quota_drift(guard, 100)
    assert not eng_q._has_fatal()
    eng_q._maybe_check_quota_drift(guard, 100)
    assert eng_q._has_fatal() and eng_q._fatal_code == EXIT_OUTAGE

    # AuthExpiredError внутри _maybe_check_quota_drift
    eng_qa = UploadEngine(
        st,
        workers=1,
        transport=FakeTransport(),
        quota_fetcher=lambda: (_ for _ in ()).throw(AuthExpiredError("expired")),
    )
    eng_qa._maybe_check_quota_drift(guard, 100)
    assert eng_qa._has_fatal() and eng_qa._fatal_code == EXIT_AUTH

    # _wait_cooldown при stop_event возвращается сразу
    eng_qa._set_cooldown(10.0)
    eng_qa.stop_event.set()
    eng_qa._wait_cooldown()
