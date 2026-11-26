"""Консольный интерфейс (CLI) загрузчика фото и видео в безлимит Яндекс.Диска (/photounlim).

Примеры:
  uv run upload_unlim.py scan --source "D:/Фотоархив"
  uv run upload_unlim.py run --source "D:/Фотоархив"
  uv run upload_unlim.py run --source "D:/Фотоархив" --watch
  uv run upload_unlim.py status
  uv run upload_unlim.py retry-failed
  uv run upload_unlim.py probe
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sqlite3
import sys
import threading

from dotenv import load_dotenv

from uploader import APP_VERSION, paths
from uploader.engine import UploadEngine, scan_source_folder
from uploader.state import UploadState
from uploader.utils import (
    DEFAULT_CHUNK_MB,
    DEFAULT_WORKERS,
    EXIT_INTERRUPTED,
    EXIT_LOCAL_IO,
    EXIT_OK,
    EXIT_PARTIAL,
    IS_WINDOWS,
    MAX_WORKERS,
    WindowsSafeRotatingFileHandler,
    ensure_utf8_stdio,
    files_text,
    hhmm,
    human_bytes,
    validate_source_dir_safe,
)

log = logging.getLogger("unlim_uploader")


def _setup_logging() -> None:
    log.setLevel(logging.INFO)
    if not any(isinstance(h, logging.FileHandler) for h in log.handlers):
        try:
            os.makedirs(paths.LOG_DIR, exist_ok=True)
            if not IS_WINDOWS:
                try:
                    os.chmod(paths.LOG_DIR, 0o700)
                except OSError as chmod_err:
                    print(
                        f"Предупреждение: не удалось задать права 0700 на {paths.LOG_DIR}: {chmod_err}",
                        file=sys.stderr,
                    )
            fh = WindowsSafeRotatingFileHandler(
                paths.UPLOAD_LOG,
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
                delay=True,
            )
            fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            log.addHandler(fh)
        except OSError as e:
            print(
                f"Предупреждение: не удалось открыть журнал {paths.UPLOAD_LOG}: {e}",
                file=sys.stderr,
            )
            if not any(isinstance(h, logging.StreamHandler) for h in log.handlers):
                sh = logging.StreamHandler(sys.stderr)
                sh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
                log.addHandler(sh)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        msg = f"Некорректное число в {name}={raw!r} — использую {default}"
        log.warning(msg)
        print(f"Предупреждение: {msg}", file=sys.stderr)
        return default


def _resolve_source(arg_source: str | None, state: UploadState) -> str:
    src = (arg_source or "").strip() or os.getenv("SOURCE_DIR", "").strip()
    if not src:
        saved = state.get_meta("source_dir")
        if isinstance(saved, str):
            src = saved.strip()
    try:
        return validate_source_dir_safe(src)
    except ValueError as e:
        print(f'{e}. Передайте --source "D:/Фото" или задайте SOURCE_DIR в .env.', flush=True)
        raise SystemExit(EXIT_LOCAL_IO) from None


def _cmd_scan(args: argparse.Namespace) -> int:
    state = UploadState()
    source = _resolve_source(args.source, state)
    print(f"Сканирую папку (только чтение): {source}", flush=True)
    try:
        res = scan_source_folder(source, state)
    except OSError as e:
        print(f"Ошибка доступа к папке: {e}", flush=True)
        return EXIT_LOCAL_IO
    st = state.stats()
    print(f"\nГотово ({res.scanned_total} файлов проверено):", flush=True)
    print(f"  Фото:                {st['photos']} ({human_bytes(st['photos_bytes'])})", flush=True)
    print(f"  Видео:               {st['videos']} ({human_bytes(st['videos_bytes'])})", flush=True)
    print(
        f"  К загрузке сейчас:   {files_text(st['pending'])} ({human_bytes(st['pending_bytes'])})",
        flush=True,
    )
    print(f"  Уже загружено:       {files_text(st['uploaded'])}", flush=True)
    print(f"  Пропущено дублей:    {st['skipped_remote'] + st['skipped_dup_local']}", flush=True)
    print(f"  Не медиа / RAW DNG:  {st['skipped_unsupported']}", flush=True)
    if res.unreadable_dirs or res.unreadable_files:
        print(
            f"  Не прочитано:        папок {res.unreadable_dirs}, файлов {res.unreadable_files}",
            flush=True,
        )
        return EXIT_PARTIAL
    return EXIT_OK


def _cmd_run(args: argparse.Namespace) -> int:
    state = UploadState()
    source = _resolve_source(args.source, state)
    stop_event = threading.Event()

    def _handle_sig(_sig, _frame) -> None:
        # В обработчике сигналов только атомарный set(), без print() (защита от reentrant I/O)
        stop_event.set()

    prev_int = signal.signal(signal.SIGINT, _handle_sig)
    prev_term = signal.signal(signal.SIGTERM, _handle_sig) if hasattr(signal, "SIGTERM") else None

    def _on_event(kind: str, text: str) -> None:
        tag = {"ok": "OK  ", "warn": "WARN", "err": "ERR ", "run": "RUN "}.get(kind, "INFO")
        print(f"[{hhmm()}] {tag} | {text}", flush=True)

    engine = UploadEngine(
        state,
        workers=args.workers,
        chunk_mb=args.chunk_mb,
        strict_quota_guard=not args.no_quota_guard,
        allow_quota_count=args.allow_quota_count,
        refresh_remote_index=args.refresh_index,
        cookies_file=args.cookies,
        on_event=_on_event,
        stop_event=stop_event,
    )
    try:
        if args.watch:
            summary = engine.run_watch(source, interval_sec=args.watch_interval)
        else:
            summary = engine.run_once(source)
        return summary.exit_code
    finally:
        engine.close()
        signal.signal(signal.SIGINT, prev_int)
        if prev_term is not None and hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, prev_term)


def _cmd_status(_args: argparse.Namespace) -> int:
    state = UploadState()
    st = state.stats()
    src = state.get_meta("source_dir") or "(не выбрана)"
    print(f"Папка-источник:      {src}")
    print(
        f"Фото / Видео:        {st['photos']} фото ({human_bytes(st['photos_bytes'])}) / {st['videos']} видео ({human_bytes(st['videos_bytes'])})"
    )
    print(
        f"Загружено:           {files_text(st['uploaded'])} ({human_bytes(st['uploaded_bytes'])})"
    )
    print(f"В очереди:           {files_text(st['pending'])} ({human_bytes(st['pending_bytes'])})")
    print(f"Уже были в облаке:   {st['skipped_remote']}")
    print(f"Локальных дублей:    {st['skipped_dup_local']}")
    print(f"Пропущено (не медиа):{st['skipped_unsupported']}")
    print(f"Ошибок:              {st['failed']}")
    print(f"Известно в Безлимите:{st['remote_index_count']}")
    return EXIT_OK


def _cmd_retry_failed(_args: argparse.Namespace) -> int:
    state = UploadState()
    n = state.retry_failed()
    print(f"Возвращено в очередь: {files_text(n)}")
    return EXIT_OK


def _cmd_reset(_args: argparse.Namespace) -> int:
    state = UploadState()
    state.clear_queue()
    print("Локальная очередь очищена. Файлы на компьютере и в Яндекс.Диске не затронуты.")
    return EXIT_OK


def _cmd_probe(args: argparse.Namespace) -> int:
    from tools.probe_unlim_upload import run_probe

    return run_probe(cookies_file=args.cookies, keep_files=False)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="upload_unlim.py",
        description=f"Загрузчик фото и видео в безлимитное облако Яндекса (/photounlim) v{APP_VERSION}",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="Просканировать папку и показать сводку без загрузки")
    p_scan.add_argument("--source", help="Путь к папке с фото и видео на ПК")
    p_scan.set_defaults(func=_cmd_scan)

    p_run = sub.add_parser("run", help="Загрузить фото и видео из папки в /photounlim")
    p_run.add_argument("--source", help="Путь к папке с фото и видео на ПК")
    p_run.add_argument(
        "--workers",
        type=int,
        default=_env_int("MAX_WORKERS", DEFAULT_WORKERS),
        help=f"Потоков загрузки (1..{MAX_WORKERS})",
    )
    p_run.add_argument(
        "--chunk-mb",
        type=int,
        default=_env_int("CHUNK_MB", DEFAULT_CHUNK_MB),
        help="Размер чанка для больших видео в МБ",
    )
    p_run.add_argument("--cookies", help="Путь к cookies.json")
    p_run.add_argument(
        "--refresh-index", action="store_true", help="Пересобрать список /photounlim заново"
    )
    p_run.add_argument(
        "--allow-quota-count",
        action="store_true",
        help="Разрешить загрузку в /photounlim даже без активной подписки Яндекс 360",
    )
    p_run.add_argument(
        "--no-quota-guard",
        action="store_true",
        help="Отключить автоматическую паузу при росте обычного занятого места",
    )
    p_run.add_argument(
        "--watch", action="store_true", help="Следить за папкой и подгружать новые файлы"
    )
    p_run.add_argument(
        "--watch-interval",
        type=int,
        default=_env_int("WATCH_INTERVAL_SEC", 60),
        help="Интервал проверки папки в режиме --watch (сек)",
    )
    p_run.set_defaults(func=_cmd_run)

    p_st = sub.add_parser("status", help="Показать текущую статистику очереди")
    p_st.set_defaults(func=_cmd_status)

    p_rf = sub.add_parser("retry-failed", help="Вернуть упавшие файлы в очередь")
    p_rf.set_defaults(func=_cmd_retry_failed)

    p_rs = sub.add_parser("reset", help="Сбросить локальную БД очереди (файлы не удаляются)")
    p_rs.set_defaults(func=_cmd_reset)

    p_pr = sub.add_parser(
        "probe",
        help="Проверить доступ и сделать тестовую загрузку 1 фото + 1 видео с автоудалением",
    )
    p_pr.add_argument("--cookies", help="Путь к cookies.json")
    p_pr.set_defaults(func=_cmd_probe)
    return p


def main(argv: list[str] | None = None) -> int:
    ensure_utf8_stdio()
    load_dotenv(paths.ENV_FILE)
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging()
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        return EXIT_INTERRUPTED
    except sqlite3.Error as e:
        log.exception("Ошибка SQLite в CLI")
        print(f"Ошибка базы состояния SQLite: {e}", flush=True)
        return EXIT_LOCAL_IO
    except Exception as e:  # noqa: BLE001
        log.exception("Непредвиденная ошибка в CLI")
        print(f"Ошибка: {e}", flush=True)
        return EXIT_PARTIAL


if __name__ == "__main__":
    raise SystemExit(main())
