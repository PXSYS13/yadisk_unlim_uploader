"""Тесты фильтрации форматов (без DNG/RAW), проверки сигнатур и парсеров EXIF/MP4."""

from __future__ import annotations

import calendar
import os

from tools.probe_unlim_upload import make_test_jpeg, make_test_mp4
from uploader.media import (
    classify_local_file,
    extract_shot_time,
    guess_mime,
    plausible_ts,
    should_skip_dir,
)


def test_accepts_valid_jpeg_and_mp4(tmp_path):
    jpg = tmp_path / "Отпуск_фото.jpg"
    jpg.write_bytes(make_test_jpeg("2023:05:15 12:34:56", b"test1"))
    mp4 = tmp_path / "Ролик_море.mp4"
    mp4.write_bytes(make_test_mp4(1684154096, b"test2"))

    v_jpg = classify_local_file(str(jpg), jpg.stat().st_size)
    v_mp4 = classify_local_file(str(mp4), mp4.stat().st_size)

    assert v_jpg.accepted and v_jpg.media_kind == "photo" and v_jpg.mime == "image/jpeg"
    assert v_mp4.accepted and v_mp4.media_kind == "video" and v_mp4.mime == "video/mp4"


def test_rejects_raw_dng_documents_empty_and_corrupt_magic(tmp_path):
    dng = tmp_path / "IMG_1001.DNG"
    dng.write_bytes(b"II\x2a\x00" + b"\x00" * 64)
    txt = tmp_path / "notes.txt"
    txt.write_text("hello", encoding="utf-8")
    empty = tmp_path / "empty.jpg"
    empty.write_bytes(b"")
    fake_jpg = tmp_path / "renamed.jpg"
    fake_jpg.write_text("this is not a jpeg", encoding="utf-8")
    part = tmp_path / "video.mp4.part"
    part.write_bytes(make_test_mp4())

    v_dng = classify_local_file(str(dng), dng.stat().st_size)
    assert not v_dng.accepted and "RAW" in (v_dng.reason or "")

    assert not classify_local_file(str(txt), txt.stat().st_size).accepted
    assert not classify_local_file(str(empty), 0).accepted

    v_fake = classify_local_file(str(fake_jpg), fake_jpg.stat().st_size)
    assert not v_fake.accepted and "формату" in (v_fake.reason or "")

    assert not classify_local_file(str(part), part.stat().st_size).accepted


def test_extract_shot_time_exif_mp4_filename_and_mtime(tmp_path):
    jpg = tmp_path / "random_name.jpg"
    jpg.write_bytes(make_test_jpeg("2022:08:19 14:25:30", b"exif"))
    expected_jpg = float(calendar.timegm((2022, 8, 19, 14, 25, 30)))
    assert extract_shot_time(str(jpg), "photo", fallback_mtime=1_700_000_000.0) == expected_jpg

    mp4_ts = 1650000000
    mp4 = tmp_path / "clip.mp4"
    mp4.write_bytes(make_test_mp4(mp4_ts, b"mp4"))
    assert extract_shot_time(str(mp4), "video", fallback_mtime=1_700_000_000.0) == float(mp4_ts)

    named = tmp_path / "IMG_20210704_091500.png"
    named.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    expected_named = float(calendar.timegm((2021, 7, 4, 9, 15, 0)))
    assert extract_shot_time(str(named), "photo", fallback_mtime=1_700_000_000.0) == expected_named

    plain = tmp_path / "picture.png"
    plain.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    fallback = 1_600_000_000.0
    os.utime(plain, (fallback, fallback))
    assert extract_shot_time(str(plain), "photo", fallback_mtime=fallback) == fallback


def test_plausible_ts_bounds():
    assert plausible_ts(100.0) is None
    assert plausible_ts(10**12) is None
    assert plausible_ts("not-a-number") is None  # type: ignore[arg-type]
    assert plausible_ts(float("nan")) is None
    assert plausible_ts(1_700_000_000.0, now=1_710_000_000.0) == 1_700_000_000.0


def test_magic_signatures_for_all_supported_formats_and_io_error(tmp_path):
    samples = [
        ("a.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, "photo"),
        ("a.gif", b"GIF89a" + b"\x00" * 16, "photo"),
        ("a.bmp", b"BM" + b"\x00" * 16, "photo"),
        ("a.webp", b"RIFF\x10\x00\x00\x00WEBP" + b"\x00" * 12, "photo"),
        ("a.tiff", b"II\x2a\x00" + b"\x00" * 16, "photo"),
        ("a.heic", b"\x00\x00\x00\x18ftypheic" + b"\x00" * 16, "photo"),
        ("a.mkv", b"\x1a\x45\xdf\xa3" + b"\x00" * 16, "video"),
        ("a.avi", b"RIFF\x10\x00\x00\x00AVI " + b"\x00" * 12, "video"),
        ("a.wmv", b"\x30\x26\xb2\x75" + b"\x00" * 16, "video"),
        ("a.flv", b"FLV\x01" + b"\x00" * 16, "video"),
        ("a.mpg", b"\x00\x00\x01\xba" + b"\x00" * 16, "video"),
        ("a.mts", b"\x47\x00\x00\x00" + b"\x00" * 16, "video"),
    ]
    for fname, payload, kind in samples:
        p = tmp_path / fname
        p.write_bytes(payload)
        v = classify_local_file(str(p), len(payload))
        assert v.accepted and v.media_kind == kind, f"Не распознан {fname}: {v}"

    # Слишком короткий заголовок (<4 байт) отбрасывается
    tiny = tmp_path / "tiny.jpg"
    tiny.write_bytes(b"\xff\xd8")
    assert not classify_local_file(str(tiny), 2).accepted

    # Отсутствующий файл даёт io_error=True
    missing = classify_local_file(str(tmp_path / "missing.jpg"), 100)
    assert not missing.accepted and missing.io_error is True

    # Вспомогательные функции
    assert should_skip_dir("$RECYCLE.BIN") is True
    assert should_skip_dir("Отпуск 2026") is False
    assert guess_mime("x.unknown", "video") == "video/mp4"
    assert guess_mime("x.unknown", "photo") == "image/jpeg"

    # Повреждённый JPEG/MP4 не падает при извлечении даты и берёт дату из имени файла
    bad_jpg = tmp_path / "2020-03-14_10-20-30.jpg"
    bad_jpg.write_bytes(b"\xff\xd8\xff\xe1\x00\x04BAD!")
    ts = extract_shot_time(str(bad_jpg), "photo", fallback_mtime=1_650_000_000.0)
    assert ts == float(calendar.timegm((2020, 3, 14, 10, 20, 30)))
