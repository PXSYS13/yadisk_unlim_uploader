"""Выбор свободного локального порта и защита Host/Origin (только localhost)."""

from __future__ import annotations

import logging
import os
import socket

from uploader.utils import IS_WINDOWS

log = logging.getLogger("unlim_uploader")

DEFAULT_PORT = 8001  # 8001, чтобы не пересекаться с yadisk_backup на 8000
PORT_TRIES = 20

_active_port: int = DEFAULT_PORT


def use_port(port: int) -> None:
    global _active_port
    _active_port = int(port)


def allowed_hosts(port: int | None = None, *, allow_testserver: bool = False) -> set[str]:
    p = _active_port if port is None else int(port)
    hosts = {f"127.0.0.1:{p}", f"localhost:{p}", f"[::1]:{p}"}
    if p == 80:
        hosts.update({"127.0.0.1", "localhost", "[::1]"})
    if allow_testserver:
        hosts.add("testserver")
    return hosts


def allowed_origins(port: int | None = None, *, allow_testserver: bool = False) -> set[str]:
    p = _active_port if port is None else int(port)
    origins = {
        f"http://127.0.0.1:{p}",
        f"http://localhost:{p}",
        f"http://[::1]:{p}",
    }
    if p == 80:
        origins.update({"http://127.0.0.1", "http://localhost", "http://[::1]"})
    if allow_testserver:
        origins.add("http://testserver")
    return origins


def choose_port(explicit_port: int | None = None) -> tuple[socket.socket, int]:
    """Привязывает TCP-сокет на 127.0.0.1 и возвращает (socket, actual_port)."""
    env_raw = os.environ.get("YADISK_UPLOADER_PORT", "").strip()
    if explicit_port is not None:
        start = int(explicit_port)
        attempts = 1
    elif env_raw:
        try:
            start = int(env_raw)
        except ValueError as e:
            raise ValueError(f"Некорректный порт в YADISK_UPLOADER_PORT={env_raw!r}") from e
        attempts = 1
    else:
        start = DEFAULT_PORT
        attempts = PORT_TRIES

    if not (0 <= start <= 65535):
        raise ValueError(f"Порт должен быть в диапазоне 0..65535 (получено {start})")

    last_err: OSError | None = None
    for port in range(start, min(65536, start + attempts)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if IS_WINDOWS:
                excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
                if excl is not None:
                    sock.setsockopt(socket.SOL_SOCKET, excl, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(128)
            actual_port = int(sock.getsockname()[1])
            use_port(actual_port)
            return sock, actual_port
        except OSError as e:
            sock.close()
            last_err = e
    raise RuntimeError(
        f"Не удалось занять локальный порт ({start}..{start + attempts - 1}): {last_err}"
    )
