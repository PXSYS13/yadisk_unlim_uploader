"""Сбор безопасного ZIP-архива диагностики для отчётов тестеров (логи + support-info.json без секретов)."""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import secrets
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any

from uploader import APP_VERSION, paths
from uploader.state import UploadState
from uploader.utils import IS_WINDOWS, redact_urls
from uploader.webapp import config as cfg_mod
from uploader.webapp import manager as mgr_mod

log = logging.getLogger("unlim_uploader.webui")

_LOG_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+\.(?:log|txt)(?:\.\d+)?$")
_BUNDLE_PREFIX = "yadisk-unlim-logs-"
_MAX_LOG_BYTES_PER_FILE = 4 * 1024 * 1024  # до 4 МБ с хвоста каждого журнала
_BUNDLE_TTL_SEC = 3600

_URL_USERINFO_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@:]+:[^/\s@]+@")

_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\by0_[A-Za-z0-9_-]{8,}"), "y0_<REDACTED>"),
    (
        re.compile(
            r"""(["']?Authorization["']?\s*[:=]\s*["']?(?:OAuth|Bearer|Basic)\s+)[^"'\r\n,;}\]]+""",
            re.IGNORECASE,
        ),
        r"\1<REDACTED>",
    ),
    (
        re.compile(r"""(["']Cookie["']\s*:\s*["'])[^"'\r\n]+(["'])""", re.IGNORECASE),
        r"\1<REDACTED>\2",
    ),
    (re.compile(r"(Cookie\s*:\s*)[^\r\n]+", re.IGNORECASE), r"\1<REDACTED>"),
    (
        re.compile(
            r"""\b((?:Session_id|sessionid2|yandexuid|sk|yandex_login|mda2_beacon)\s*=\s*["']?)[^;\s"'&,}\]]+""",
            re.IGNORECASE,
        ),
        r"\1<REDACTED>",
    ),
    (
        re.compile(
            r"""(["'](?:Session_id|sessionid2|yandexuid|sk|uid|account_name|yandex_login|mda2_beacon|L)["']\s*:\s*["'])[^"']*(["'])""",
            re.IGNORECASE,
        ),
        r"\1<REDACTED>\2",
    ),
    (re.compile(r"""(["']uid["']\s*:\s*)\d+""", re.IGNORECASE), r"\g<1>0"),
    (re.compile(r"\b(uid=)\d+", re.IGNORECASE), r"\1<REDACTED>"),
    # Имя системного пользователя в путях Windows (JSON-экранированных и обычных) и POSIX
    # В шаблоне замены re.sub каждый обратный слеш должен быть экранирован.
    (re.compile(r"(?i)[A-Z]:\\\\Users\\\\[^\\/\r\n\"'<>|]+"), r"C:\\\\Users\\\\<USER>"),
    (re.compile(r"(?i)[A-Z]:\\Users\\[^\\/\r\n\"'<>|]+"), r"C:\\Users\\<USER>"),
    (re.compile(r"/(?:Users|home)/[^/\s\"'<>|]+"), "/home/<USER>"),
)


def scrub_support_text(text: str) -> str:
    """Убирает userinfo прокси, подписанные URL, куки, токены, sk/uid и имя пользователя ОС."""
    if not text:
        return ""
    out = _URL_USERINFO_RE.sub(r"\1<REDACTED>@", text)
    out = redact_urls(out)
    for pattern, repl in _SECRET_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def list_logs() -> list[dict[str, Any]]:
    """Возвращает разрешённые файлы журналов строго внутри paths.LOG_DIR (без обхода симлинков)."""
    out: list[dict[str, Any]] = []
    if not paths.LOG_DIR.is_dir():
        return out
    root = paths.LOG_DIR.resolve()
    try:
        entries = list(os.scandir(root))
    except OSError as e:
        log.warning("Не удалось прочитать каталог логов %s: %s", root, e)
        return out

    for entry in entries:
        if not _LOG_NAME_RE.match(entry.name):
            continue
        try:
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                continue
            resolved = Path(entry.path).resolve()
            if resolved.parent != root:
                continue
            st = entry.stat(follow_symlinks=False)
        except OSError as e:
            log.warning("Не удалось проверить журнал %s: %s", entry.name, e)
            continue
        out.append({"name": entry.name, "path": resolved, "size": st.st_size, "mtime": st.st_mtime})
    # Архивация webui.log последней: предупреждения при сборке попадут в него после flush
    out.sort(key=lambda item: (item["name"] == paths.WEBUI_LOG.name, -float(item["mtime"])))
    return out


def _sanitized_account(account: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(account, dict):
        return None
    keep = (
        "used",
        "disk",
        "limit",
        "free",
        "trash",
        "photounlim",
        "actual_photounlim_size",
        "filesize_limit",
        "is_overdrawn",
        "conversion_enabled",
        "has_pro_subscription",
        "has_family_subscription",
        "unlimited_free",
        "warning",
        "base_url",
    )
    out: dict[str, Any] = {}
    for k in keep:
        if k in account:
            val = account[k]
            out[k] = scrub_support_text(val) if isinstance(val, str) else val
    return out


def support_info(*, skipped_logs: list[str] | None = None) -> dict[str, Any]:
    """Собирает диагностическую сводку без кук, паролей, логинов и локальных путей."""
    cfg = cfg_mod.get_config()
    ck = mgr_mod.manager.check_cookies_file()
    status = mgr_mod.manager.status_dict()

    stats: dict[str, Any] = {}
    recent_errors: list[dict[str, Any]] = []
    db_error: str | None = None
    if paths.DB_FILE.exists():
        try:
            st = UploadState(paths.DB_FILE)
            stats = st.stats()
            failed_rows, _ = st.list_files(status="failed", offset=0, limit=20)
            for row in failed_rows:
                recent_errors.append(
                    {
                        "media_kind": row.get("media_kind"),
                        "size": int(row.get("size") or 0),
                        "attempts": int(row.get("attempts") or 0),
                        "error": scrub_support_text(str(row.get("error") or ""))[:300],
                    }
                )
        except Exception as e:  # noqa: BLE001
            db_error = scrub_support_text(f"{type(e).__name__}: {e}")[:300]
            log.warning("Не удалось прочитать статистику БД для отчёта: %s", db_error)

    scrubbed_events = [
        {
            "at": str(ev.get("at") or ""),
            "kind": str(ev.get("kind") or "info"),
            "text": scrub_support_text(str(ev.get("text") or ""))[:400],
        }
        for ev in (status.get("events") or [])[:60]
    ]

    info: dict[str, Any] = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "app_version": APP_VERSION,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "config": {
            "source_dir_set": bool(cfg.get("source_dir")),
            "max_workers": cfg.get("max_workers"),
            "chunk_mb": cfg.get("chunk_mb"),
            "strict_quota_guard": cfg.get("strict_quota_guard"),
            "watch_mode": cfg.get("watch_mode"),
            "watch_interval_sec": cfg.get("watch_interval_sec"),
        },
        "cookies": {
            "present": bool(ck.get("present")),
            "ok": bool(ck.get("ok")),
            "base_url": ck.get("base_url"),
            "error": scrub_support_text(str(ck.get("error") or "")) or None,
        },
        "account": _sanitized_account(status.get("account")),
        "runtime": {
            "running": bool(status.get("running")),
            "mode": status.get("mode"),
            "exit_code": status.get("exit_code"),
            "message": scrub_support_text(str(status.get("message") or ""))[:300],
            "phase": (status.get("live") or {}).get("phase"),
        },
        "stats": stats,
        "recent_errors": recent_errors,
        "events": scrubbed_events,
    }
    if db_error:
        info["db_error"] = db_error
    if skipped_logs:
        info["skipped_logs"] = list(skipped_logs)
    return info


def _read_scrubbed_tail(path: Path, arcname: str) -> tuple[zipfile.ZipInfo, bytes]:
    """Читает и очищает хвост журнала в память ДО записи в ZIP (исключает битые/обрезанные записи)."""
    entry = zipfile.ZipInfo.from_file(path, arcname, strict_timestamps=False)
    chunks: list[bytes] = []
    with open(path, "rb") as src:
        src.seek(0, os.SEEK_END)
        total = src.tell()
        if total > _MAX_LOG_BYTES_PER_FILE:
            tail_start = total - _MAX_LOG_BYTES_PER_FILE
            src.seek(tail_start)
            src.readline()  # пробуем выровняться по границе строки
            trimmed = src.tell()
            if trimmed >= total:
                # В хвосте нет переносов строк — возвращаемся к tail_start, чтобы не потерять хвост
                src.seek(tail_start)
                trimmed = tail_start
            chunks.append(
                f"... [обрезаны первые {trimmed} байт, оставлен хвост журнала] ...\n".encode(
                    "utf-8"
                )
            )
        else:
            src.seek(0)
        for raw_line in src:
            cleaned = scrub_support_text(raw_line.decode("utf-8", errors="replace"))
            chunks.append(cleaned.encode("utf-8"))
    return entry, b"".join(chunks)


def _scrub_obj(obj: Any) -> Any:
    """Рекурсивно очищает все строковые значения в структуре данных ДО сериализации в JSON."""
    if isinstance(obj, str):
        return scrub_support_text(obj)
    if isinstance(obj, dict):
        return {str(k): _scrub_obj(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_scrub_obj(v) for v in obj]
    if isinstance(obj, tuple):
        return [_scrub_obj(v) for v in obj]
    return obj


def _flush_log_handlers() -> None:
    for logger_name in ("unlim_uploader", "unlim_uploader.webui"):
        logger = logging.getLogger(logger_name)
        for handler in logger.handlers:
            try:
                handler.flush()
            except OSError:
                pass


def _prune_old_bundles() -> None:
    if not paths.LOG_DIR.is_dir():
        return
    now = time.time()
    for pattern in (f"{_BUNDLE_PREFIX}*.zip", ".bundle-*.tmp"):
        for old in paths.LOG_DIR.glob(pattern):
            try:
                if now - old.stat().st_mtime > _BUNDLE_TTL_SEC:
                    old.unlink()
            except OSError as e:
                log.debug("Не удалось удалить старый временный архив %s: %s", old.name, e)


def build_support_bundle() -> Path:
    """Собирает ZIP-архив `yadisk-unlim-logs-*.zip` атомарно через временный файл."""
    paths.LOG_DIR.mkdir(parents=True, exist_ok=True)
    if not IS_WINDOWS:
        try:
            os.chmod(paths.LOG_DIR, 0o700)
        except OSError as e:
            log.debug("Не удалось выставить права 0700 на %s: %s", paths.LOG_DIR, e)
    _prune_old_bundles()

    # Уникальный суффикс исключает коллизии имён при двойном клике в пределах одной секунды
    name = f"{_BUNDLE_PREFIX}{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}.zip"
    bundle = paths.LOG_DIR / name
    fd, tmp_name = tempfile.mkstemp(prefix=".bundle-", suffix=".tmp", dir=os.fspath(paths.LOG_DIR))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        if not IS_WINDOWS:
            try:
                os.chmod(tmp, 0o600)
            except OSError as e:
                log.debug("Не удалось выставить права 0600 на %s: %s", tmp.name, e)

        skipped_logs: list[str] = []
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            # 1. Сначала собираем support-info (если БД сбойнула, предупреждение успеет в webui.log)
            info = support_info()
            _flush_log_handlers()

            # 2. Читаем журналы в память до записи в ZIP — ошибка записи ZIP (ENOSPC) не маскируется
            for item in list_logs():
                try:
                    entry, payload = _read_scrubbed_tail(item["path"], item["name"])
                except OSError as e:
                    msg = f"{item['name']}: {scrub_support_text(str(e))[:160]}"
                    skipped_logs.append(msg)
                    log.warning("Пропущен журнал %s при сборке отчёта: %s", item["name"], e)
                    continue
                entry.compress_type = zf.compression
                zf.writestr(entry, payload)

            if skipped_logs:
                info["skipped_logs"] = skipped_logs
            clean_info = _scrub_obj(info)
            info_json = json.dumps(clean_info, ensure_ascii=False, indent=2, default=str)
            zf.writestr("support-info.json", info_json.encode("utf-8"))

        os.replace(tmp, bundle)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError as e:
                log.debug("Не удалось удалить временный файл архива %s: %s", tmp.name, e)
    log.info("Собран архив логов для поддержки: %s", name)
    return bundle
