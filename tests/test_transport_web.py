"""Тесты WebModelsTransport: store, hardlink, code 72/47, RFC Content-Range, _LocalStreamError, sk-refresh."""

from __future__ import annotations

import hashlib
import json

import pytest
import requests

from tools.probe_unlim_upload import make_test_jpeg
from uploader.quota_guard import QuotaGuardError
from uploader.state import UploadRow
from uploader.transport_web import SessionContext, WebModelsTransport, _LocalStreamError


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        body: dict | list | str = "",
        headers: dict | None = None,
        url: str = "https://disk.yandex.ru/models-v2",
    ):
        self.status_code = status_code
        self._body = body
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.headers = headers or {"Content-Type": "application/json"}
        self.url = url

    def json(self):
        if isinstance(self._body, (dict, list)):
            return self._body
        return json.loads(self.text)


class FakeYandexTransportSession:
    """Имитирует disk.yandex.ru/models-v2 + uploader*.disk.yandex.net со строгой проверкой RFC Content-Range."""

    def __init__(self):
        self.yadisk_base = "https://disk.yandex.ru"
        self.valid_sk = "sk-v1"
        self.stored_by_path: dict[str, dict] = {}
        self.stored_hashes: set[str] = set()
        self.uploads: dict[str, bytearray] = {}
        self.ops: dict[str, dict] = {}
        self.drop_next_put = False
        self.force_hardlink = False
        self.force_507 = False
        self.force_bad_host = False
        self.put_calls = 0
        self.head_calls = 0
        self.seen_content_ranges: list[str] = []

    def get(self, url, timeout=30):
        self.valid_sk = "sk-v2"
        return FakeResponse(
            200,
            f'<html>{{"sk":"{self.valid_sk}","uid":"777"}}</html>',
            headers={"Content-Type": "text/html"},
            url=url,
        )

    def post(self, url, params=None, json=None, timeout=60):
        method = (params or {}).get("m") or (json or {}).get("apiMethod")
        sk = (json or {}).get("sk")
        if sk != self.valid_sk:
            return FakeResponse(200, {"error": "bad_sk"})

        rp = (json or {}).get("requestParams") or {}
        if method == "mpfs/store":
            if self.force_507:
                return FakeResponse(
                    507,
                    {
                        "error": {
                            "type": "mpfs",
                            "statusCode": 507,
                            "code": 85,
                            "title": "no free space",
                        }
                    },
                )
            path = rp["path"]
            md5 = rp["md5"]
            if self.force_hardlink:
                self.stored_by_path[path] = {"md5": md5, "size": rp["size"]}
                return FakeResponse(200, {"status": "hardlinked"})
            if md5 in self.stored_hashes:
                return FakeResponse(
                    409,
                    {
                        "error": {
                            "type": "mpfs",
                            "statusCode": 409,
                            "code": 72,
                            "title": "file already exists",
                        }
                    },
                )
            if path in self.stored_by_path:
                return FakeResponse(
                    409,
                    {
                        "error": {
                            "type": "mpfs",
                            "statusCode": 409,
                            "code": 47,
                            "title": "STORE_FILE_EXISTS",
                        }
                    },
                )
            oid = f"oid-{len(self.ops) + 1}"
            host = "evil.example" if self.force_bad_host else "uploader1.disk.yandex.net"
            up_url = f"https://{host}/upload-target/{oid}"
            self.uploads[up_url] = bytearray()
            self.ops[oid] = {
                "path": path,
                "size": rp["size"],
                "md5": md5,
                "up_url": up_url,
                "polls": 0,
            }
            return FakeResponse(200, {"upload_url": up_url, "oid": oid, "type": "store"})

        if method == "mpfs/info":
            path = rp.get("path", "")
            rec = self.stored_by_path.get(path)
            if rec:
                return FakeResponse(
                    200,
                    {
                        "path": path,
                        "name": path.rsplit("/", 1)[-1],
                        "meta": {"storage_type": "photounlim", "size": rec["size"]},
                    },
                )
            return FakeResponse(404, {"error": "not found"})

        if method == "mpfs/bulk-operation-status":
            out = {}
            for oid in rp.get("oids", []):
                info = self.ops[oid]
                info["polls"] += 1
                if info["polls"] == 1:
                    out[oid] = {"state": "EXECUTING"}
                else:
                    self.stored_by_path[info["path"]] = {"md5": info["md5"], "size": info["size"]}
                    self.stored_hashes.add(info["md5"])
                    out[oid] = {
                        "state": "DONE",
                        "resource": {
                            "path": info["path"],
                            "name": info["path"].rsplit("/", 1)[-1],
                            "meta": {"storage_type": "photounlim", "size": info["size"]},
                        },
                    }
            return FakeResponse(200, out)

        raise AssertionError(f"Unexpected method: {method}")

    def head(self, url, timeout=30):
        self.head_calls += 1
        buf = self.uploads[url]
        return FakeResponse(200, "", headers={"Content-Length": str(len(buf))})

    def put(self, url, data=None, headers=None, timeout=180):
        self.put_calls += 1
        chunk = b"".join(data) if not isinstance(data, (bytes, bytearray)) else bytes(data)
        buf = self.uploads[url]
        if self.drop_next_put:
            self.drop_next_put = False
            buf.extend(chunk[: len(chunk) // 2])
            raise requests.ConnectionError("reset by peer")
        cr = (headers or {}).get("Content-Range")
        if cr:
            # Строгая проверка RFC 9110: пробел после "bytes ", без "="
            assert cr.startswith("bytes "), f"Невалидный RFC Content-Range: {cr!r}"
            self.seen_content_ranges.append(cr)
            rng = cr.split(" ", 1)[1].split("/", 1)[0]
            start = int(rng.split("-", 1)[0])
            del buf[start:]
        buf.extend(chunk)
        return FakeResponse(201, "")


def _make_row(path, name: str, data: bytes) -> tuple[UploadRow, str, str]:
    path.write_bytes(data)
    md5 = hashlib.md5(data).hexdigest()
    sha = hashlib.sha256(data).hexdigest()
    row = UploadRow(
        id=1,
        local_path=str(path),
        rel_path=name,
        name=name,
        media_kind="photo",
        mime="image/jpeg",
        size=len(data),
        mtime_ns=0,
        md5=md5,
        sha256=sha,
        shot_time=None,
        remote_name=name,
        remote_id=None,
        status="uploading",
        error=None,
        attempts=0,
    )
    return row, md5, sha


def test_upload_success_and_code72_duplicate_and_code47_collision(tmp_path):
    fake = FakeYandexTransportSession()
    ctx = SessionContext(fake, "sk-v1", "777")
    tr = WebModelsTransport(ctx, chunk_mb=1, put_session=fake, poll_sleep=0.01)

    data1 = make_test_jpeg("2023:05:15 12:00:00", b"photo-one")
    row1, md5_1, sha_1 = _make_row(tmp_path / "IMG_1.jpg", "IMG_1.jpg", data1)
    res1 = tr.upload_file(row1, md5=md5_1, sha256=sha_1)
    assert res1.outcome == "uploaded"
    assert res1.remote_id == "/photounlim/IMG_1.jpg"
    assert fake.put_calls == 1

    row_dup, md5_d, sha_d = _make_row(tmp_path / "copy.jpg", "copy.jpg", data1)
    res_dup = tr.upload_file(row_dup, md5=md5_d, sha256=sha_d)
    assert res_dup.outcome == "duplicate_remote"
    assert fake.put_calls == 1

    data2 = make_test_jpeg("2023:05:16 12:00:00", b"photo-two-different")
    row2, md5_2, sha_2 = _make_row(tmp_path / "IMG_1_other.jpg", "IMG_1.jpg", data2)
    res2 = tr.upload_file(row2, md5=md5_2, sha256=sha_2)
    assert res2.outcome == "uploaded"
    assert res2.remote_name == f"IMG_1_{md5_2[:6]}.jpg"
    assert res2.remote_id == f"/photounlim/IMG_1_{md5_2[:6]}.jpg"


def test_chunked_resumable_put_uses_rfc_content_range_and_recovers(tmp_path, monkeypatch):
    monkeypatch.setattr("uploader.transport_web._sleep_interruptible", lambda _s, _ev=None: None)
    fake = FakeYandexTransportSession()
    fake.drop_next_put = True
    ctx = SessionContext(fake, "sk-v1", "777")
    tr = WebModelsTransport(ctx, chunk_mb=1, put_session=fake, poll_sleep=0.01)

    big = b"\xff\xd8\xff\xe0" + (b"ABCD1234" * (320 * 1024))
    row, md5, sha = _make_row(tmp_path / "big.jpg", "big.jpg", big)
    progress_marks: list[int] = []
    res = tr.upload_file(
        row, md5=md5, sha256=sha, on_progress=lambda sent, _tot: progress_marks.append(sent)
    )
    assert res.outcome == "uploaded"
    assert fake.head_calls == 1
    assert len(fake.seen_content_ranges) >= 3
    up_url = next(iter(fake.uploads.keys()))
    assert bytes(fake.uploads[up_url]) == big
    assert progress_marks[-1] == len(big)


def test_hardlink_sk_autorefresh_507_and_bad_upload_host(tmp_path):
    fake = FakeYandexTransportSession()
    fake.force_hardlink = True
    ctx = SessionContext(fake, "stale-sk", "777")
    tr = WebModelsTransport(ctx, put_session=fake, poll_sleep=0.01)

    row, md5, sha = _make_row(tmp_path / "hl.jpg", "hl.jpg", make_test_jpeg(salt=b"hl"))
    res = tr.upload_file(row, md5=md5, sha256=sha)
    assert res.outcome == "hardlinked"
    assert ctx.get()[0] == "sk-v2"

    fake.force_hardlink = False
    fake.force_507 = True
    with pytest.raises(QuotaGuardError):
        tr.upload_file(row, md5=md5, sha256=sha)

    fake.force_507 = False
    fake.force_bad_host = True
    from uploader.cookies import UnlimApiError

    with pytest.raises(UnlimApiError, match="посторонний хост"):
        tr.upload_file(row, md5=md5, sha256=sha)


def test_local_oserror_in_chunk_stream_not_swallowed_as_yandex_outage(tmp_path):
    fake = FakeYandexTransportSession()
    ctx = SessionContext(fake, "sk-v1", "777")
    tr = WebModelsTransport(ctx, chunk_mb=1, put_session=fake, poll_sleep=0.01)

    # Создаём файл, но подменяем размер в UploadRow на больший, чтобы _ChunkStream поймал короткое чтение OSError
    p = tmp_path / "shrunk.jpg"
    data = make_test_jpeg(salt=b"shrink")
    row, md5, sha = _make_row(p, "shrunk.jpg", data)
    row.size = len(data) + 100

    # _LocalStreamError не является подклассом OSError, поэтому urllib3 его не оборачивает,
    # а _put_file_resumable распаковывает обратно в исходный OSError
    assert not issubclass(_LocalStreamError, OSError)
    with pytest.raises(OSError, match="уменьшился"):
        tr.upload_file(row, md5=md5, sha256=sha)


def test_put_status_codes_url_expiry_and_operation_failed(tmp_path, monkeypatch):
    monkeypatch.setattr("uploader.transport_web._sleep_interruptible", lambda _s, _ev=None: None)
    from uploader.cookies import (
        AuthExpiredError,
        CaptchaError,
        RateLimitError,
        UnlimApiError,
        YandexUnavailableError,
    )

    class CustomSession(FakeYandexTransportSession):
        def __init__(self):
            super().__init__()
            self.put_responses: list[FakeResponse] = []
            self.force_op_failed = False

        def put(self, url, data=None, headers=None, timeout=180):
            if self.put_responses:
                # Потребляем поток так же, как requests
                if not isinstance(data, (bytes, bytearray)):
                    b"".join(data)
                return self.put_responses.pop(0)
            return super().put(url, data=data, headers=headers, timeout=timeout)

        def post(self, url, params=None, json=None, timeout=60):
            method = (params or {}).get("m") or (json or {}).get("apiMethod")
            if method == "mpfs/bulk-operation-status" and self.force_op_failed:
                rp = (json or {}).get("requestParams") or {}
                return FakeResponse(
                    200,
                    {oid: {"state": "FAILED", "error": "disk_err"} for oid in rp.get("oids", [])},
                )
            return super().post(url, params=params, json=json, timeout=timeout)

    fake = CustomSession()
    ctx = SessionContext(fake, "sk-v1", "777")
    tr = WebModelsTransport(ctx, chunk_mb=1, put_session=fake, poll_sleep=0.01)
    row, md5, sha = _make_row(tmp_path / "p.jpg", "p.jpg", make_test_jpeg(salt=b"codes"))

    # HTTP 410 на PUT -> переполучение upload_url на url_attempt=1 и успешная загрузка
    fake.put_responses = [FakeResponse(410, "gone")]
    res = tr.upload_file(row, md5=md5, sha256=sha)
    assert res.outcome == "uploaded"

    # Новое фото для проверки кодов ошибок PUT
    row2, md5_2, sha_2 = _make_row(tmp_path / "p2.jpg", "p2.jpg", make_test_jpeg(salt=b"codes2"))

    fake.put_responses = [FakeResponse(401, "unauth")]
    with pytest.raises(AuthExpiredError):
        tr.upload_file(row2, md5=md5_2, sha256=sha_2)

    fake.put_responses = [FakeResponse(429, "rate limit")]
    with pytest.raises(RateLimitError):
        tr.upload_file(row2, md5=md5_2, sha256=sha_2)

    fake.put_responses = [FakeResponse(507, "no space")]
    with pytest.raises(QuotaGuardError):
        tr.upload_file(row2, md5=md5_2, sha256=sha_2)

    fake.put_responses = [FakeResponse(400, "bad req")]
    with pytest.raises(UnlimApiError):
        tr.upload_file(row2, md5=md5_2, sha256=sha_2)

    fake.put_responses = [
        FakeResponse(200, "<html>SmartCaptcha</html>", headers={"Content-Type": "text/html"})
    ]
    with pytest.raises(CaptchaError):
        tr.upload_file(row2, md5=md5_2, sha256=sha_2)

    # HTTP 416 -> HEAD -> повтор -> успех
    fake.put_responses = [FakeResponse(416, "range")]
    res2 = tr.upload_file(row2, md5=md5_2, sha256=sha_2)
    assert res2.outcome == "uploaded"

    # bulk-operation-status state=FAILED -> UnlimApiError
    row3, md5_3, sha_3 = _make_row(tmp_path / "p3.jpg", "p3.jpg", make_test_jpeg(salt=b"codes3"))
    fake.force_op_failed = True
    with pytest.raises(UnlimApiError, match="FAILED"):
        tr.upload_file(row3, md5=md5_3, sha256=sha_3)

    # _query_uploaded_offset на HTTP 500 -> YandexUnavailableError
    fake.head = lambda url, timeout=30: FakeResponse(500, "err")  # type: ignore[method-assign]
    with pytest.raises(YandexUnavailableError):
        tr._query_uploaded_offset("https://uploader1.disk.yandex.net/upload-target/x")

    tr.close()
    ctx.close()
