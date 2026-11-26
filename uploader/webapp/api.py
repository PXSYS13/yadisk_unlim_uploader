"""FastAPI-приложение локального веб-интерфейса загрузчика с защитой localhost/CSRF/CSP."""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import secrets
import sqlite3
from contextlib import asynccontextmanager
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from uploader import APP_ID, APP_VERSION, paths
from uploader.cookies import (
    AuthExpiredError,
    CookiesFormatError,
    UnlimApiError,
    YandexUnavailableError,
    build_cookie_jar,
    filter_yandex_cookies,
    parse_cookies_text,
)
from uploader.state import UploadState
from uploader.utils import IS_WINDOWS, validate_source_dir_safe
from uploader.webapp import config as cfg_mod
from uploader.webapp import logs as logs_mod
from uploader.webapp import manager as mgr_mod
from uploader.webapp import ports as ports_mod

FileStatusFilter = Literal[
    "all",
    "pending",
    "uploading",
    "uploaded",
    "skipped",
    "skipped_remote",
    "skipped_dup_local",
    "skipped_limit",
    "skipped_unsupported",
    "failed",
]

_CSP_HEADER = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
)
log = logging.getLogger("unlim_uploader.webui")


class CookiesPayload(BaseModel):
    text: str = Field(..., min_length=5, max_length=250_000)


class SettingsPayload(BaseModel):
    source_dir: str | None = None
    max_workers: int | None = None
    chunk_mb: int | None = None
    strict_quota_guard: bool | None = None
    watch_mode: bool | None = None
    watch_interval_sec: int | None = None


class StartPayload(BaseModel):
    source_dir: str | None = None
    allow_quota_count: bool = False
    refresh_index: bool = False
    watch_mode: bool | None = None


class ScanPayload(BaseModel):
    source_dir: str | None = None


def _csv_safe_cell(val: object) -> str:
    """Нейтрализует формулы Excel (DDE/CSV Injection) в текстовых ячейках."""
    s = "" if val is None else str(val)
    stripped = s.lstrip(" \t\r\n")
    if stripped.startswith(("=", "+", "-", "@")) or s.startswith(("\t", "\r")):
        return "'" + s
    return s


def _write_private_json(target: os.PathLike, data: object) -> None:
    target_path = os.fspath(target)
    parent = os.path.dirname(os.path.abspath(target_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp_path = f"{target_path}.tmp.{os.getpid()}.{secrets.token_hex(4)}"
    payload = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    try:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload)
        finally:
            os.close(fd)
        if not IS_WINDOWS:
            try:
                os.chmod(tmp_path, 0o600)
            except OSError:
                pass
        os.replace(tmp_path, target_path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def create_app(*, allow_testserver: bool = False) -> FastAPI:
    csrf_token = secrets.token_urlsafe(32)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        mgr_mod.manager.shutdown(timeout=10.0)

    app = FastAPI(title="Загрузчик в Безлимит Яндекс.Диска", version=APP_VERSION, lifespan=lifespan)
    app.state.csrf_token = csrf_token

    static_dir = paths.ASSETS_DIR / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=os.fspath(static_dir)), name="static")
    else:
        log.error("Не найден каталог статических файлов интерфейса: %s", static_dir)

    @app.middleware("http")
    async def localhost_guard(request: Request, call_next):
        host = (request.headers.get("host") or "").strip().lower()
        if not host or host not in ports_mod.allowed_hosts(allow_testserver=allow_testserver):
            return JSONResponse(
                {"detail": "Доступ разрешён только с этого компьютера (localhost)"}, status_code=403
            )

        origin = (request.headers.get("origin") or "").strip().lower()
        if origin and origin not in ports_mod.allowed_origins(allow_testserver=allow_testserver):
            return JSONResponse({"detail": "Запрос с постороннего сайта отклонён"}, status_code=403)

        sec_fetch_site = (request.headers.get("sec-fetch-site") or "").strip().lower()
        is_root_nav = request.method in ("GET", "HEAD") and request.url.path == "/"
        if sec_fetch_site and sec_fetch_site not in ("same-origin", "none") and not is_root_nav:
            return JSONResponse({"detail": "Кросс-сайтовый запрос отклонён"}, status_code=403)
        if sec_fetch_site == "none" and request.url.path.startswith("/api/"):
            # Прямая навигация допустима только для GET /api/export.csv и GET /api/logs/bundle;
            # любые state-changing запросы без same-origin запрещены.
            if request.method not in ("GET", "HEAD"):
                return JSONResponse({"detail": "Кросс-сайтовый запрос отклонён"}, status_code=403)

        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            token_hdr = (request.headers.get("x-csrf-token") or "").strip()
            if not token_hdr or not secrets.compare_digest(token_hdr, csrf_token):
                return JSONResponse(
                    {"detail": "Отсутствует или неверен CSRF-токен сессии — обновите страницу"},
                    status_code=403,
                )

        response = await call_next(request)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Content-Security-Policy", _CSP_HEADER)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        elif request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-cache"
        return response

    @app.get("/", response_class=HTMLResponse)
    def index():
        html_path = paths.ASSETS_DIR / "index.html"
        if not html_path.exists():
            raise HTTPException(status_code=500, detail="Не найден шаблон интерфейса index.html")
        text = html_path.read_text(encoding="utf-8")
        rendered = text.replace("__APP_VERSION__", APP_VERSION).replace(
            "__CSRF_TOKEN__", csrf_token
        )
        return HTMLResponse(rendered)

    @app.get("/api/hello")
    def api_hello():
        return {
            "app_id": APP_ID,
            "version": APP_VERSION,
        }

    @app.get("/api/status")
    def api_status():
        return mgr_mod.manager.status_dict()

    @app.post("/api/cookies")
    def api_save_cookies(payload: CookiesPayload):
        if mgr_mod.manager.is_running():
            raise HTTPException(status_code=409, detail="Сначала остановите текущую загрузку")
        parsed = parse_cookies_text(payload.text)
        if not isinstance(parsed, list):
            raise HTTPException(
                status_code=400,
                detail="Не удалось распознать куки. Скопируйте экспорт из Cookie-Editor (JSON), DevTools или Copy as cURL.",
            )
        filtered = filter_yandex_cookies(parsed)
        try:
            jar = build_cookie_jar(filtered)
        except CookiesFormatError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e

        # Сначала проверяем куки в памяти, не перетирая рабочий cookies.json протухшим набором
        warning: str | None = None
        account = None
        try:
            account = mgr_mod.manager.verify_account_live(jar=jar)
        except (AuthExpiredError, CookiesFormatError) as e:
            raise HTTPException(status_code=401, detail=str(e)) from e
        except YandexUnavailableError as e:
            warning = f"Куки сохранены, но Яндекс временно не ответил: {e}"
        except (UnlimApiError, RuntimeError) as e:
            raise HTTPException(status_code=502, detail=str(e)) from e

        _write_private_json(paths.COOKIES_FILE, filtered)
        if warning is not None:
            mgr_mod.manager.set_account_cache(None, None)
            mgr_mod.manager.add_event("warn", warning)
            return {"ok": True, "account": None, "warning": warning}

        mgr_mod.manager.add_event("ok", "Данные входа сохранены и проверены в Яндексе")
        return {"ok": True, "account": account}

    @app.post("/api/cookies/check")
    def api_check_cookies():
        try:
            account = mgr_mod.manager.verify_account_live()
            return {"ok": True, "account": account}
        except (AuthExpiredError, CookiesFormatError) as e:
            mgr_mod.manager.set_account_cache(None, str(e))
            raise HTTPException(status_code=401, detail=str(e)) from e
        except YandexUnavailableError as e:
            raise HTTPException(status_code=503, detail=str(e)) from e
        except (UnlimApiError, RuntimeError) as e:
            raise HTTPException(status_code=502, detail=str(e)) from e

    @app.delete("/api/cookies")
    def api_delete_cookies():
        if mgr_mod.manager.is_running():
            raise HTTPException(status_code=409, detail="Сначала остановите загрузку")
        if paths.COOKIES_FILE.exists():
            paths.COOKIES_FILE.unlink()
        mgr_mod.manager.set_account_cache(None, None)
        mgr_mod.manager.add_event("info", "Данные входа (cookies.json) удалены")
        return {"ok": True}

    @app.post("/api/settings")
    def api_settings(payload: SettingsPayload):
        updates = payload.model_dump(exclude_none=True)
        if "source_dir" in updates:
            raw_src = str(updates["source_dir"]).strip()
            if raw_src:
                try:
                    clean_src = validate_source_dir_safe(raw_src)
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e)) from e
                if not os.path.isdir(clean_src):
                    raise HTTPException(status_code=400, detail=f"Папка не найдена: {clean_src}")
                updates["source_dir"] = clean_src
            else:
                updates["source_dir"] = ""
        saved = cfg_mod.save_config(updates)
        return {"ok": True, "config": saved}

    @app.post("/api/folder/pick")
    def api_pick_folder():
        if mgr_mod.manager.is_running():
            raise HTTPException(status_code=409, detail="Сначала остановите текущую загрузку")
        cur = cfg_mod.get_config().get("source_dir", "")
        chosen = mgr_mod.pick_folder_dialog(cur)
        if not chosen:
            return {"picked": False, "path": cur}
        try:
            clean = validate_source_dir_safe(chosen)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        cfg_mod.save_config({"source_dir": clean})
        return {"picked": True, "path": clean}

    @app.post("/api/scan")
    def api_scan(payload: ScanPayload):
        src = (payload.source_dir or "").strip() or cfg_mod.get_config().get("source_dir", "")
        try:
            clean = mgr_mod.manager.start_scan(src)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except RuntimeError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        cfg_mod.save_config({"source_dir": clean})
        return {"ok": True}

    @app.post("/api/start")
    def api_start(payload: StartPayload):
        src = (payload.source_dir or "").strip() or cfg_mod.get_config().get("source_dir", "")
        try:
            clean = mgr_mod.manager.start_upload(
                source_dir=src,
                allow_quota_count=payload.allow_quota_count,
                refresh_index=payload.refresh_index,
                watch_mode=payload.watch_mode,
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        except RuntimeError as e:
            raise HTTPException(status_code=409, detail=str(e)) from e
        cfg_mod.save_config({"source_dir": clean})
        return {"ok": True}

    @app.post("/api/stop")
    def api_stop():
        stopped = mgr_mod.manager.stop()
        return {"ok": True, "stopping": stopped}

    @app.post("/api/retry-failed")
    def api_retry_failed():
        if mgr_mod.manager.is_running():
            raise HTTPException(status_code=409, detail="Сначала остановите текущую загрузку")
        state = UploadState(paths.DB_FILE)
        count = state.retry_failed()
        mgr_mod.manager.add_event("info", f"Возвращено в очередь для повтора: {count}")
        return {"ok": True, "requeued": count}

    @app.post("/api/reset")
    def api_reset():
        if mgr_mod.manager.is_running():
            raise HTTPException(status_code=409, detail="Сначала остановите текущую загрузку")
        state = UploadState(paths.DB_FILE)
        state.clear_queue()
        mgr_mod.manager.add_event(
            "info", "Локальная очередь очищена (исходные файлы и облако не затронуты)"
        )
        return {"ok": True}

    @app.get("/api/files")
    def api_files(
        status: Annotated[FileStatusFilter, Query()] = "all",
        search: Annotated[str, Query()] = "",
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ):
        state = UploadState(paths.DB_FILE)
        items, total = state.list_files(
            status=status, search=search.strip() or None, offset=offset, limit=limit
        )
        return {"items": items, "total": total, "offset": offset, "limit": limit}

    @app.get("/api/export.csv")
    def api_export_csv(status: Annotated[FileStatusFilter, Query()] = "all"):
        try:
            state = UploadState(paths.DB_FILE)
            # Проверяем доступность БД до отправки заголовков HTTP 200
            state.stats()
        except sqlite3.Error as e:
            log.exception("Не удалось открыть базу очереди для экспорта CSV")
            raise HTTPException(
                status_code=500, detail=f"Не удалось прочитать базу очереди: {e}"
            ) from e

        def _gen():
            buf = io.StringIO()
            writer = csv.writer(buf, delimiter=";")
            yield "\ufeff"
            writer.writerow(
                [
                    "Относительный путь",
                    "Тип",
                    "Размер (байт)",
                    "Статус",
                    "Путь в Безлимите",
                    "Комментарий",
                ]
            )
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
            try:
                for row in state.iter_files_for_csv(status=status, batch_size=1000):
                    writer.writerow(
                        [
                            _csv_safe_cell(row.get("rel_path") or ""),
                            _csv_safe_cell(row.get("media_kind") or ""),
                            int(row.get("size") or 0),
                            _csv_safe_cell(row.get("status") or ""),
                            _csv_safe_cell(row.get("remote_id") or ""),
                            _csv_safe_cell(row.get("error") or ""),
                        ]
                    )
                    yield buf.getvalue()
                    buf.seek(0)
                    buf.truncate(0)
            except sqlite3.Error:
                log.exception("Ошибка SQLite во время потокового экспорта CSV")
                raise

        return StreamingResponse(
            _gen(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="yadisk_unlim_{status}.csv"'},
        )

    @app.get("/api/logs/bundle")
    def api_logs_bundle():
        try:
            bundle = logs_mod.build_support_bundle()
        except Exception as e:  # noqa: BLE001
            log.exception("Не удалось собрать архив логов для поддержки")
            raise HTTPException(
                status_code=500,
                detail=f"Не удалось собрать архив логов для поддержки: {type(e).__name__}",
            ) from e
        return FileResponse(
            os.fspath(bundle),
            media_type="application/zip",
            filename=bundle.name,
        )

    return app
