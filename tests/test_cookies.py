"""Тесты парсера cookies.json, региональных доменов и разбора ответов Яндекса."""

from __future__ import annotations

import json
import threading
import time

import pytest
import requests

from uploader.cookies import (
    AuthExpiredError,
    CaptchaError,
    CookiesFormatError,
    RateLimitError,
    UnlimApiError,
    YandexUnavailableError,
    api_call,
    build_cookie_jar,
    cookies_dict,
    filter_yandex_cookies,
    get_sk_uid,
    is_captcha_response,
    load_cookies,
    make_session,
    missing_required_cookies,
    parse_cookies_text,
    raw_api_call,
    resolve_cookies_base,
)
from uploader.utils import CancelledError


def test_parse_cookie_editor_json_and_regional_domain():
    raw = [
        {"name": "Session_id", "value": "sid-kz", "domain": ".yandex.kz"},
        {"name": "yandexuid", "value": "uid-kz", "domain": ".yandex.kz"},
        {"name": "sessionid2", "value": "sid2-kz", "domain": ".yandex.kz"},
        {"name": "Session_id", "value": "wrong", "domain": "passport.yandex.ru"},
    ]
    parsed = parse_cookies_text(json.dumps(raw))
    assert isinstance(parsed, list)
    assert missing_required_cookies(parsed) == []
    base, tld = resolve_cookies_base(parsed)
    assert base == "https://disk.yandex.kz" and tld == "yandex.kz"
    jar = cookies_dict(parsed, base_domain=tld)
    assert jar["Session_id"] == "sid-kz"


def test_parse_curl_and_header_string_and_netscape():
    curl_cmd = "curl 'https://disk.yandex.ru/client/photo' -H 'Cookie: Session_id=abc; yandexuid=123; sessionid2=xyz'"
    rows = parse_cookies_text(curl_cmd)
    assert rows is not None and missing_required_cookies(rows) == []

    hdr = "Cookie: Session_id=abc; yandexuid=123; sessionid2=xyz"
    rows2 = parse_cookies_text(hdr)
    assert rows2 is not None and missing_required_cookies(rows2) == []

    netscape = (
        "# Netscape HTTP Cookie File\n"
        ".yandex.ru\tTRUE\t/\tTRUE\t0\tSession_id\tabc\n"
        ".yandex.ru\tTRUE\t/\tTRUE\t0\tyandexuid\t123\n"
        ".yandex.ru\tTRUE\t/\tTRUE\t0\tsessionid2\txyz\n"
    )
    rows3 = parse_cookies_text(netscape)
    assert rows3 is not None and missing_required_cookies(rows3) == []


def test_expired_cookies_detected():
    past = time.time() - 3600
    raw = [
        {"name": "Session_id", "value": "old", "domain": ".yandex.ru", "expirationDate": past},
        {"name": "yandexuid", "value": "123", "domain": ".yandex.ru"},
        {"name": "sessionid2", "value": "xyz", "domain": ".yandex.ru"},
    ]
    assert missing_required_cookies(raw) == ["Session_id"]


def test_captcha_detection_ignores_filename_in_200_json():
    class FakeResp:
        def __init__(
            self, status, body, ctype="application/json", url="https://disk.yandex.ru/models-v2"
        ):
            self.status_code = status
            self.text = body
            self.headers = {"Content-Type": ctype}
            self.url = url

        def json(self):
            return json.loads(self.text)

    r_ok = FakeResp(200, json.dumps({"path": "/photounlim/captcha_screenshot.png"}))
    assert not is_captcha_response(r_ok)

    r_cap = FakeResp(200, "<html>SmartCaptcha</html>", ctype="text/html")
    assert is_captcha_response(r_cap)
    assert is_captcha_response(FakeResp(200, "ok", url="https://disk.yandex.ru/showcaptcha"))
    assert is_captcha_response(FakeResp(200, json.dumps({"captcha": True})))
    assert is_captcha_response(FakeResp(200, json.dumps({"error": "captcha_required"})))
    assert is_captcha_response(FakeResp(403, "please solve captcha", ctype="text/plain"))


def test_parse_extra_formats_filter_load_and_session(tmp_path):
    assert parse_cookies_text("") is None
    assert parse_cookies_text("12345") is None
    assert parse_cookies_text(json.dumps({"other": "x"})) is None

    wrapped = json.dumps(
        {
            "cookies": [
                {"name": "Session_id", "value": "a"},
                {"name": "yandexuid", "value": "b"},
                {"name": "sessionid2", "value": "c"},
            ]
        }
    )
    assert missing_required_cookies(parse_cookies_text(wrapped) or []) == []

    flat = json.dumps({"Session_id": "a", "yandexuid": "b", "sessionid2": "c"})
    assert missing_required_cookies(parse_cookies_text(flat) or []) == []

    devtools = (
        "Session_id\ta\t.yandex.ru\t/\nyandexuid\tb\t.yandex.ru\t/\nsessionid2\tc\t.yandex.ru\t/"
    )
    assert missing_required_cookies(parse_cookies_text(devtools) or []) == []

    multiline = "Cookie: Session_id=a\nyandexuid=b\nsessionid2=c"
    assert missing_required_cookies(parse_cookies_text(multiline) or []) == []

    filtered = filter_yandex_cookies(
        [
            {
                "name": "Session_id",
                "value": "a",
                "domain": ".yandex.ru",
                "path": "/",
                "expirationDate": time.time() + 3600,
            },
            {"name": "yandexuid", "value": "b", "domain": ".yandex.ru"},
            {"name": "sessionid2", "value": "c", "domain": ".yandex.ru"},
            {"name": "evil", "value": "secret", "domain": ".other.com"},
            {"name": "bad\nname", "value": "x", "domain": ".yandex.ru"},
        ]
    )
    assert {c["name"] for c in filtered} == {"Session_id", "yandexuid", "sessionid2"}

    jar = build_cookie_jar(filtered)
    sess = make_session(cookies=jar)
    try:
        assert sess.yadisk_base == "https://disk.yandex.ru"  # type: ignore[attr-defined]
        assert sess.cookies.get("Session_id") == "a"
    finally:
        sess.close()

    with pytest.raises(CookiesFormatError):
        build_cookie_jar([{"name": "Session_id", "value": "only-one"}])

    missing_file = tmp_path / "missing.json"
    with pytest.raises(CookiesFormatError):
        load_cookies(missing_file)

    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not cookies at all", encoding="utf-8")
    with pytest.raises(CookiesFormatError):
        load_cookies(bad_file)

    ok_file = tmp_path / "ok.json"
    ok_file.write_text("\ufeff" + json.dumps(filtered), encoding="utf-8")
    assert load_cookies(ok_file)["Session_id"] == "a"


def test_get_sk_uid_raw_api_call_and_api_call_retries(monkeypatch):
    monkeypatch.setattr("uploader.cookies._sleep_interruptible", lambda _s, _ev=None: None)

    class Resp:
        def __init__(
            self,
            status=200,
            body="",
            ctype="application/json",
            url="https://disk.yandex.ru/models-v2",
        ):
            self.status_code = status
            self.text = body if isinstance(body, str) else json.dumps(body)
            self._body = body
            self.headers = {"Content-Type": ctype, "x-request-id": "req-1"}
            self.url = url

        def json(self):
            if isinstance(self._body, (dict, list)):
                return self._body
            return json.loads(self.text)

    class FakeSession:
        yadisk_base = "https://disk.yandex.ru"

        def __init__(self, gets=None, posts=None):
            self.gets = list(gets or [])
            self.posts = list(posts or [])

        def get(self, url, timeout=30):
            nxt = self.gets.pop(0)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt

        def post(self, url, params=None, json=None, timeout=60):
            nxt = self.posts.pop(0)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt

    # get_sk_uid: /client/disk пустой -> fallback на /client/photo
    s1 = FakeSession(
        gets=[
            Resp(200, "<html>no keys</html>", "text/html"),
            Resp(200, '{"sk":"sk1","uid":"42"}', "text/html"),
        ]
    )
    assert get_sk_uid(s1) == ("sk1", "42")  # type: ignore[arg-type]

    # guest uid=0 -> AuthExpiredError
    with pytest.raises(AuthExpiredError):
        get_sk_uid(FakeSession(gets=[Resp(200, '{"sk":"sk0","uid":"0"}', "text/html")]))  # type: ignore[arg-type]

    # passport redirect -> AuthExpiredError
    with pytest.raises(AuthExpiredError):
        get_sk_uid(
            FakeSession(
                gets=[Resp(200, "login", "text/html", url="https://passport.yandex.ru/auth")]
            )
        )  # type: ignore[arg-type]

    # HTTP 500 -> YandexUnavailableError
    with pytest.raises(YandexUnavailableError):
        get_sk_uid(FakeSession(gets=[Resp(502, "bad gateway", "text/html")]))  # type: ignore[arg-type]

    # raw_api_call error mappings
    with pytest.raises(YandexUnavailableError):
        raw_api_call(FakeSession(posts=[requests.ConnectionError("net")]), "sk", "1", "m")  # type: ignore[arg-type]
    with pytest.raises(RateLimitError):
        raw_api_call(FakeSession(posts=[Resp(429, "limit", "text/plain")]), "sk", "1", "m")  # type: ignore[arg-type]
    with pytest.raises(AuthExpiredError):
        raw_api_call(FakeSession(posts=[Resp(401, "unauth", "text/plain")]), "sk", "1", "m")  # type: ignore[arg-type]
    with pytest.raises(AuthExpiredError):
        raw_api_call(FakeSession(posts=[Resp(200, {"error": "bad_sk"})]), "sk", "1", "m")  # type: ignore[arg-type]
    with pytest.raises(CaptchaError):
        raw_api_call(
            FakeSession(posts=[Resp(200, "<html>SmartCaptcha</html>", "text/html")]), "sk", "1", "m"
        )  # type: ignore[arg-type]

    # api_call retries on 503 and 429 then succeeds
    s_retry = FakeSession(
        posts=[Resp(503, "busy", "text/plain"), Resp(429, "rl", "text/plain"), Resp(200, {"ok": 1})]
    )
    assert api_call(s_retry, "sk", "1", "mpfs/space", retries=3) == {"ok": 1}  # type: ignore[arg-type]

    # api_call 200 with non-auth JSON error -> UnlimApiError
    with pytest.raises(UnlimApiError):
        api_call(
            FakeSession(posts=[Resp(200, {"error": "weird_error"})]), "sk", "1", "m", retries=1
        )  # type: ignore[arg-type]

    # api_call cancelled
    ev = threading.Event()
    ev.set()
    with pytest.raises(CancelledError):
        api_call(FakeSession(), "sk", "1", "m", stop_event=ev)  # type: ignore[arg-type]
