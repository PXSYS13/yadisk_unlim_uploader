# Для разработчиков

Спасибо, что хотите помочь проекту. Ниже — как устроен код, как запустить тесты и что проверить перед pull request.

## Окружение

Проект использует [uv](https://docs.astral.sh/uv/) (Python 3.10+, зависимости зафиксированы в `uv.lock`).

```bash
uv sync                                           # установка зависимостей разработки (pytest, pytest-cov, ruff)
uv run webui.py                                   # веб-интерфейс на http://127.0.0.1:8001
uv run ruff check . && uv run ruff format --check .
uv run python -X warn_default_encoding -m pytest -v --cov=uploader --cov=upload_unlim --cov=webui --cov-fail-under=80
```

Полезные переменные окружения:

- `YADISK_NO_BROWSER=1` — не открывать браузер при старте `webui.py`;
- `YADISK_UPLOADER_PORT=8011` — указать порт вручную.

## Карта модулей

```text
upload_unlim.py          CLI: scan / run [--watch] / status / retry-failed / reset / probe
webui.py                 Точка входа локального веб-интерфейса (FastAPI + uvicorn)
uploader/
  paths.py               Единые пути проекта (подменяются в тестах через conftest.py)
  utils.py               Потоковое хеширование MD5+SHA256, длинные пути, SQLite-транзакции, коды выхода
  cookies.py             Парсер cookies (6 форматов), домены disk.yandex.*, получение sk/uid, вызовы models-v2
  media.py               Фильтр фото/видео (без RAW/DNG), проверка сигнатур (magic bytes), EXIF и MP4 mvhd
  state.py               SQLite WAL база upload_state.db: очередь, дедупликация, статусы
  remote_index.py        Постраничная индексация /photounlim через mpfs/list
  quota_guard.py         Проверка квоты (mpfs/space, mpfs/get-user-info), лимит размера, защита used_space
  transport_base.py      Контракт транспорта загрузки
  transport_web.py       Прямой транспорт models-v2 (mpfs/store -> hardlink / RFC Content-Range PUT -> poll)
  engine.py              Сканирование папки (read-only), очередь воркеров, паузы 429/капчи, режим --watch
  webapp/
    api.py               FastAPI-маршруты и middleware (Host, Origin, Sec-Fetch-Site, CSRF, CSP)
    config.py            Потокобезопасное чтение/запись .env с правами 0600
    logs.py              Безопасный ZIP-архив диагностики для поддержки без секретов
    manager.py           Менеджер фоновых задач сканирования/загрузки и диалог выбора папки
    ports.py             Выбор свободного локального порта (8001..8020)
webui_assets/            HTML, CSS и чистый JS без сборки (без innerHTML)
tools/probe_unlim_upload.py  Диагностический зонд (1 тестовое фото + 1 видео с автоудалением)
tests/                   Юнит- и интеграционные тесты (pytest)
```

## Правила проекта

- Тексты интерфейса, журналы и документация — на русском, простыми словами для нетехнических пользователей.
- Исходная папка пользователя на ПК открывается строго на чтение.
- Все файловые `open()` в коде и тестах указывают `encoding="utf-8"` (проверяется `PYTHONWARNDEFAULTENCODING=1`).
- Новые или изменённые пути в `uploader/paths.py` обязательно изолировать в `tests/conftest.py`.
- `webui.bat` хранится в чистом ASCII с CRLF, без запуска скачанных скриптов `.ps1`; `webui.sh` и `webui.command` — с LF и битом исполнения `100755` в Git.
- Версии в `uploader/__init__.py`, `pyproject.toml` и `uv.lock`, а также версия `uv` в `webui.bat`, `webui.sh` и `.github/workflows/ci.yml` должны совпадать (проверяется автотестами).
