"""Тесты QuotaGuard: проверка подписки, лимита размера, строгий verify_resource и дрейф used_space."""

from __future__ import annotations

import pytest

from uploader.cookies import AuthExpiredError, UnlimApiError
from uploader.quota_guard import QuotaGuard, QuotaGuardError, QuotaSnapshot, fetch_quota_snapshot


def _snap(**overrides) -> QuotaSnapshot:
    base = dict(
        used=5 * 1024**3,
        disk=5 * 1024**3,
        limit=200 * 1024**3,
        free=195 * 1024**3,
        trash=0,
        photounlim=10 * 1024**3,
        actual_photounlim_size=10 * 1024**3,
        filesize_limit=50 * 1024**3,
        is_overdrawn=False,
        conversion_enabled=False,
        has_pro_subscription=True,
        has_family_subscription=False,
        unlimited_free=True,
        warning=None,
    )
    base.update(overrides)
    return QuotaSnapshot(**base)


def test_preflight_blocks_overdraft_unless_allowed():
    bad = _snap(
        is_overdrawn=True, unlimited_free=False, has_pro_subscription=False, warning="Нет подписки"
    )
    with pytest.raises(QuotaGuardError):
        QuotaGuard(bad, strict=True, allow_quota_count=False).check_preflight()

    QuotaGuard(bad, strict=True, allow_quota_count=True).check_preflight()


def test_file_size_limit_and_strict_resource_storage_type():
    guard = QuotaGuard(_snap(filesize_limit=1024**3))
    assert guard.check_file_size(500) is None
    assert guard.check_file_size(2 * 1024**3) is not None

    QuotaGuard.verify_resource(
        {"path": "/photounlim/a.jpg", "meta": {"storage_type": "photounlim"}}
    )
    with pytest.raises(QuotaGuardError):
        QuotaGuard.verify_resource(None)
    with pytest.raises(QuotaGuardError):
        QuotaGuard.verify_resource({"path": "/photounlim/a.jpg", "meta": {}})
    with pytest.raises(QuotaGuardError):
        QuotaGuard.verify_resource({"path": "/disk/a.jpg", "meta": {"storage_type": "disk"}})
    with pytest.raises(QuotaGuardError):
        QuotaGuard.verify_resource({"path": "/photounlim/a.jpg", "meta": {"storage_type": "disk"}})


def test_drift_detection_catches_used_space_growth():
    before = _snap(used=1_000_000_000, actual_photounlim_size=5_000_000_000)
    guard = QuotaGuard(before, strict=True)

    ok_after = _snap(used=1_000_000_000, actual_photounlim_size=5_050_000_000)
    guard.check_drift(ok_after, 50_000_000)

    bad_after = _snap(used=1_020_000_000, actual_photounlim_size=5_070_000_000)
    with pytest.raises(QuotaGuardError):
        guard.check_drift(bad_after, 20_000_000)

    # При strict=False или allow_quota_count=True дрейф не блокирует
    QuotaGuard(before, strict=False).check_drift(bad_after, 20_000_000)
    QuotaGuard(before, strict=True, allow_quota_count=True).check_drift(bad_after, 20_000_000)
    assert before.to_dict()["used"] == 1_000_000_000


def test_fetch_quota_snapshot_branches(monkeypatch):
    def _run(space_resp, ui_resp):
        def fake_call(_s, _sk, _uid, method, _params, retries=1):
            if method == "mpfs/space":
                return space_resp
            if isinstance(ui_resp, Exception):
                raise ui_resp
            return ui_resp

        monkeypatch.setattr("uploader.quota_guard.api_call", fake_call)
        return fetch_quota_snapshot(object(), "sk", "1")  # type: ignore[arg-type]

    # 1. Активная Pro-подписка -> unlimited_free=True
    s_pro = _run(
        {"used": 100, "limit": 200 * 1024**3, "photounlim": 500, "filesize_limit": 50 * 1024**3},
        {"hasProSubscription": True, "name": "Tester"},
    )
    assert s_pro.unlimited_free is True and s_pro.warning is None and s_pro.account_name == "Tester"

    # 2. Переполненный аккаунт без подписки -> unlimited_free=False с предупреждением
    s_over = _run(
        {
            "used": 20 * 1024**3,
            "limit": 10 * 1024**3,
            "is_overdrawn": True,
            "filesize_limit": 1024**3,
        },
        {"hasProSubscription": False},
    )
    assert s_over.unlimited_free is False and s_over.warning is not None

    # 3. Бесплатный conversion-аккаунт с пустым photounlim -> warning
    s_conv = _run(
        {
            "used": 100,
            "limit": 10 * 1024**3,
            "photounlim": 0,
            "photounlim_conversion_experiment_enabled": True,
            "filesize_limit": 1024**3,
        },
        RuntimeError("get-user-info unavailable"),
    )
    assert s_conv.unlimited_free is False and s_conv.warning is not None

    # 4. AuthExpiredError из get-user-info пробрасывается
    with pytest.raises(AuthExpiredError):
        _run({"used": 1, "limit": 10}, AuthExpiredError("expired"))

    # 5. Битый mpfs/space -> UnlimApiError
    with pytest.raises(UnlimApiError):
        _run({"only": "partial"}, {})
    with pytest.raises(UnlimApiError):
        _run({"used": "not-a-number", "limit": 10}, {})
