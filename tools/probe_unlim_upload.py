"""Протокольный зонд (Фаза 0): проверяет прямую загрузку 1 тестового фото и 1 видео в /photounlim.

Что делает:
  1. Проверяет cookies.json и квоту аккаунта (mpfs/space + mpfs/get-user-info).
  2. Генерирует минимальные валидные JPEG (с EXIF датой) и MP4 (~250 байт каждый) во временной папке.
  3. Загружает их в /photounlim/_probe_test_<ts>.jpg/.mp4 через WebModelsTransport.
  4. Проверяет storage_type == 'photounlim' и изменение квоты (used vs actual_photounlim_size).
  5. В блоке finally гарантированно удаляет созданные тестовые файлы из /photounlim и /trash,
     дожидаясь завершения операций удаления через mpfs/bulk-operation-status.
  6. Пишет отчёт в logs/probe_unlim_upload.txt.
"""

from __future__ import annotations

import os
import struct
import sys
import tempfile
import time

from uploader import paths
from uploader.cookies import (
    AuthExpiredError,
    CookiesFormatError,
    UnlimApiError,
    YandexUnavailableError,
    api_call,
    get_sk_uid,
    make_session,
)
from uploader.quota_guard import fetch_quota_snapshot
from uploader.state import UploadRow
from uploader.transport_web import SessionContext, WebModelsTransport
from uploader.utils import (
    EXIT_AUTH,
    EXIT_OK,
    EXIT_OUTAGE,
    EXIT_PARTIAL,
    EXIT_QUOTA_DRIFT,
    compute_hashes,
    ensure_utf8_stdio,
    human_bytes,
)


def make_test_jpeg(dt_str: str = "2023:05:15 12:34:56", salt: bytes = b"probe") -> bytes:
    """Минимальный валидный 1x1 JPEG с APP1 EXIF DateTimeOriginal."""
    dt_bytes = (dt_str[:19] + "\x00").encode("ascii")
    tiff = (
        b"II"
        + struct.pack("<HI", 42, 8)
        + struct.pack("<H", 1)
        + struct.pack("<HHII", 0x8769, 4, 1, 26)
        + struct.pack("<I", 0)
        + struct.pack("<H", 1)
        + struct.pack("<HHII", 0x9003, 2, 20, 44)
        + struct.pack("<I", 0)
        + dt_bytes
    )
    app1_payload = b"Exif\x00\x00" + tiff
    app1 = b"\xff\xe1" + struct.pack(">H", len(app1_payload) + 2) + app1_payload
    com = b"\xff\xfe" + struct.pack(">H", len(salt) + 2) + salt
    dqt = b"\xff\xdb\x00\x43\x00" + bytes([16] * 64)
    sof0 = b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    dht = (
        b"\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b"
        b"\xff\xc4\x00\x14\x10\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    )
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00\x7f\x00"
    return b"\xff\xd8" + app1 + com + dqt + sof0 + dht + sos + b"\xff\xd9"


def make_test_mp4(creation_unix: int = 1684154096, salt: bytes = b"probe") -> bytes:
    """Минимальный валидный контейнер MP4 (ftyp + moov/mvhd + free)."""

    def box(btype: bytes, payload: bytes) -> bytes:
        return struct.pack(">I", 8 + len(payload)) + btype + payload

    mp4_time = creation_unix + 2_082_844_800
    ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 0x200) + b"isomiso2mp41")
    mvhd_payload = (
        struct.pack(">IIIIII", 0, mp4_time, mp4_time, 1000, 1000, 0x00010000)
        + struct.pack(">H", 0x0100)
        + b"\x00" * 10
        + struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000)
        + b"\x00" * 24
        + struct.pack(">I", 2)
    )
    moov = box(b"moov", box(b"mvhd", mvhd_payload))
    free = box(b"free", salt + b"\x00" * 64)
    return ftyp + moov + free


def _wait_oids(session, sk: str, uid: str, oids: list[str], timeout_sec: float = 20.0) -> bool:
    pending = set(oids)
    failed = False
    deadline = time.monotonic() + timeout_sec
    while pending and time.monotonic() < deadline:
        st = api_call(
            session, sk, uid, "mpfs/bulk-operation-status", {"oids": sorted(pending)}, retries=2
        )
        if isinstance(st, dict):
            for oid in list(pending):
                op = st.get(oid)
                if not isinstance(op, dict):
                    continue
                state = str(op.get("state") or "").upper()
                if state in ("DONE", "COMPLETED"):
                    pending.discard(oid)
                elif state in ("FAILED", "ERROR", "ABORTED", "CANCELLED"):
                    pending.discard(oid)
                    failed = True
        if pending:
            time.sleep(0.8)
    return not pending and not failed


def _cleanup_probe_files(session, sk: str, uid: str, uploaded: list[str], marker: str, out) -> bool:
    ok = True
    try:
        res = api_call(
            session,
            sk,
            uid,
            "mpfs/bulk-async-delete",
            {"operations": [{"src": p} for p in uploaded]},
            retries=2,
        )
        oids = (
            [it["oid"] for it in res if isinstance(it, dict) and it.get("oid")]
            if isinstance(res, list)
            else []
        )
        if oids:
            if not _wait_oids(session, sk, uid, oids):
                ok = False
        else:
            time.sleep(2.0)

        # Ищем в корзине ТОЛЬКО файлы с нашим уникальным marker (постранично до 200 записей)
        in_trash: list[str] = []
        for offset in (0, 100):
            trash = api_call(
                session,
                sk,
                uid,
                "mpfs/list",
                {"path": "/trash", "amount": 100, "offset": offset},
                retries=2,
            )
            if not isinstance(trash, list):
                ok = False
                break
            page_items = [
                it
                for it in trash
                if isinstance(it, dict) and str(it.get("path") or "").startswith("/trash/")
            ]
            for it in page_items:
                p = str(it.get("path") or "")
                if marker in p:
                    in_trash.append(p)
            if len(page_items) < 100:
                break

        if in_trash:
            res2 = api_call(
                session,
                sk,
                uid,
                "mpfs/bulk-async-delete",
                {"operations": [{"src": p} for p in in_trash]},
                retries=2,
            )
            oids2 = (
                [it["oid"] for it in res2 if isinstance(it, dict) and it.get("oid")]
                if isinstance(res2, list)
                else []
            )
            if oids2 and not _wait_oids(session, sk, uid, oids2):
                ok = False
        out(
            f"Уборка тестовых файлов завершена (удалено из /photounlim: {len(uploaded)}, из корзины: {len(in_trash)})."
        )
    except Exception as e:  # noqa: BLE001
        out(f"Внимание: не удалось полностью убрать тестовые файлы ({e}).")
        ok = False
    return ok


def run_probe(*, cookies_file: str | None = None, keep_files: bool = False) -> int:
    ensure_utf8_stdio()
    lines: list[str] = []

    def out(msg: str) -> None:
        lines.append(msg)
        print(msg, flush=True)

    exit_code = EXIT_OK
    session = None
    ctx = None
    transport = None
    uploaded: list[str] = []
    ts = int(time.time())
    marker = f"_probe_test_{ts}"

    try:
        try:
            session = make_session(cookies_file=cookies_file)
            sk, uid = get_sk_uid(session)
        except (CookiesFormatError, AuthExpiredError) as e:
            out(f"Ошибка авторизации: {e}")
            return EXIT_AUTH
        except YandexUnavailableError as e:
            out(f"Яндекс временно недоступен: {e}")
            return EXIT_OUTAGE
        except UnlimApiError as e:
            out(f"Ошибка API Яндекс.Диска: {e}")
            return EXIT_PARTIAL

        before = fetch_quota_snapshot(session, sk, uid)
        out(
            f"Аккаунт: занято {human_bytes(before.used)} из {human_bytes(before.limit)}, "
            f"безлимит {human_bytes(before.actual_photounlim_size)}, "
            f"лимит файла {human_bytes(before.filesize_limit)}"
        )
        if before.warning:
            out(f"Внимание: {before.warning}")

        ctx = SessionContext(session, sk, uid, owns_session=False)
        transport = WebModelsTransport(ctx)
        salt = f"probe-unlim-{ts}".encode()

        with tempfile.TemporaryDirectory() as tmp:
            samples = [
                (
                    f"{marker}.jpg",
                    "photo",
                    "image/jpeg",
                    make_test_jpeg("2023:05:15 12:34:56", salt),
                ),
                (f"{marker}.mp4", "video", "video/mp4", make_test_mp4(1684154096, salt)),
            ]
            for idx, (fname, kind, mime, payload) in enumerate(samples, start=1):
                local_p = os.path.join(tmp, fname)
                with open(local_p, "wb") as f:
                    f.write(payload)
                md5, sha256 = compute_hashes(local_p)
                row = UploadRow(
                    id=idx,
                    local_path=local_p,
                    rel_path=fname,
                    name=fname,
                    media_kind=kind,
                    mime=mime,
                    size=len(payload),
                    mtime_ns=0,
                    md5=md5,
                    sha256=sha256,
                    shot_time=None,
                    remote_name=fname,
                    remote_id=None,
                    status="uploading",
                    error=None,
                    attempts=0,
                )
                res = transport.upload_file(row, md5=md5, sha256=sha256)
                uploaded.append(res.remote_id)
                st_type = ((res.resource or {}).get("meta") or {}).get("storage_type")
                out(f"  OK {kind}: {res.remote_id} (outcome={res.outcome}, storage_type={st_type})")
                if st_type != "photounlim":
                    out(f"  ОШИБКА: ожидался storage_type='photounlim', получен {st_type!r}")
                    exit_code = EXIT_QUOTA_DRIFT

        after = fetch_quota_snapshot(session, sk, uid)
        used_diff = after.used - before.used
        unlim_diff = after.actual_photounlim_size - before.actual_photounlim_size
        out(
            f"Изменение после теста: used {used_diff:+d} Б, actual_photounlim_size {unlim_diff:+d} Б"
        )
        if before.unlimited_free and used_diff > 0:
            out("ОШИБКА: при активной подписке выросло обычное занятое место (used)!")
            exit_code = EXIT_QUOTA_DRIFT

        if not keep_files and uploaded:
            cleaned = _cleanup_probe_files(session, sk, uid, uploaded, marker, out)
            if not cleaned and exit_code == EXIT_OK:
                exit_code = EXIT_PARTIAL
            uploaded.clear()
        return exit_code
    except (AuthExpiredError, CookiesFormatError) as e:
        out(f"Ошибка доступа зонда: {e}")
        return EXIT_AUTH
    except YandexUnavailableError as e:
        out(f"Яндекс временно недоступен в зонде: {e}")
        return EXIT_OUTAGE
    except Exception as e:  # noqa: BLE001
        out(f"Сбой зонда: {type(e).__name__}: {e}")
        return EXIT_PARTIAL
    finally:
        if not keep_files and uploaded and session is not None and ctx is not None:
            try:
                sk_c, uid_c, _ = ctx.get()
                _cleanup_probe_files(session, sk_c, uid_c, uploaded, marker, out)
            except Exception as cleanup_err:  # noqa: BLE001
                out(f"Не удалось убрать тестовые файлы в finally: {cleanup_err}")
        for obj in (transport, ctx, session):
            if obj is not None:
                try:
                    obj.close()
                except Exception as close_err:  # noqa: BLE001
                    print(
                        f"Предупреждение при закрытии ресурса зонда: {close_err}", file=sys.stderr
                    )
        try:
            os.makedirs(paths.LOG_DIR, exist_ok=True)
            with open(paths.LOG_DIR / "probe_unlim_upload.txt", "w", encoding="utf-8") as log_f:
                log_f.write("\n".join(lines) + "\n")
        except OSError as log_err:
            print(
                f"Предупреждение: не удалось записать probe_unlim_upload.txt: {log_err}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    raise SystemExit(run_probe())
