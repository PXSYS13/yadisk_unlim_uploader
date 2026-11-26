"""Точка входа локального веб-интерфейса загрузчика фото и видео в Безлимит Яндекс.Диска."""

from __future__ import annotations

import logging
import os
import sys
import threading
import webbrowser

import uvicorn

from uploader import APP_VERSION, paths
from uploader.utils import IS_WINDOWS, WindowsSafeRotatingFileHandler, ensure_utf8_stdio
from uploader.webapp import manager as mgr_mod
from uploader.webapp.api import create_app
from uploader.webapp.ports import choose_port

app = create_app()


def _setup_logging() -> None:
    logger = logging.getLogger("unlim_uploader")
    logger.setLevel(logging.INFO)
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
        if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
            fh = WindowsSafeRotatingFileHandler(
                paths.WEBUI_LOG,
                maxBytes=5 * 1024 * 1024,
                backupCount=3,
                encoding="utf-8",
                delay=True,
            )
            fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            logger.addHandler(fh)
    except OSError as e:
        print(f"Предупреждение: не удалось открыть журнал {paths.WEBUI_LOG}: {e}", file=sys.stderr)
        if not any(isinstance(h, logging.StreamHandler) for h in logger.handlers):
            sh = logging.StreamHandler(sys.stderr)
            sh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
            logger.addHandler(sh)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)


def main() -> int:
    ensure_utf8_stdio()
    _setup_logging()
    sock, port = choose_port()
    stop_open = threading.Event()
    try:
        url = f"http://127.0.0.1:{port}"
        print(f"Загрузчик в Безлимит Яндекс.Диска v{APP_VERSION}", flush=True)
        print(f"Откройте в браузере: {url}", flush=True)
        print("Не закрывайте это окно, пока идёт загрузка.", flush=True)

        if os.environ.get("YADISK_NO_BROWSER", "").strip() not in ("1", "true", "yes"):

            def _open() -> None:
                if not stop_open.wait(0.8):
                    try:
                        if not webbrowser.open(url):
                            logging.getLogger("unlim_uploader.webui").warning(
                                "Браузер не открылся автоматически — откройте %s вручную", url
                            )
                    except Exception as e:  # noqa: BLE001
                        logging.getLogger("unlim_uploader.webui").warning(
                            "Не удалось открыть браузер: %s", e
                        )

            threading.Thread(target=_open, daemon=True).start()

        config = uvicorn.Config(app, log_level="warning")
        server = uvicorn.Server(config)
        server.run(sockets=[sock])
    finally:
        stop_open.set()
        try:
            mgr_mod.manager.shutdown(timeout=10.0)
        except Exception:  # noqa: BLE001
            logging.getLogger("unlim_uploader.webui").exception(
                "Ошибка при остановке фоновой задачи Web UI"
            )
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
