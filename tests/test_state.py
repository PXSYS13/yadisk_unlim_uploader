"""Тесты SQLite WAL состояния очереди, дедупликации и восстановления после обрыва."""

from __future__ import annotations

from uploader.state import UploadState


def _rec(
    path: str,
    rel: str,
    name: str,
    size: int = 100,
    mtime: int = 1000,
    accepted: bool = True,
    kind: str = "photo",
):
    return {
        "local_path": path,
        "rel_path": rel,
        "name": name,
        "accepted": accepted,
        "media_kind": kind if accepted else None,
        "mime": "image/jpeg" if accepted else None,
        "reason": None if accepted else "RAW",
        "size": size,
        "mtime_ns": mtime,
        "shot_time": 1_700_000_000.0 if accepted else None,
    }


def test_upsert_unique_remote_names_and_rescan_modified(tmp_path):
    st = UploadState(tmp_path / "u.db")
    p1 = str(tmp_path / "2023" / "IMG_0001.JPG")
    p2 = str(tmp_path / "2024" / "IMG_0001.JPG")
    diff = st.upsert_scanned_files(
        [
            _rec(p1, "2023/IMG_0001.JPG", "IMG_0001.JPG"),
            _rec(p2, "2024/IMG_0001.JPG", "IMG_0001.JPG"),
        ],
        str(tmp_path),
    )
    assert diff["added"] == 2

    row1 = st.take_next_pending()
    row2 = st.take_next_pending()
    assert row1 is not None and row2 is not None
    # Два файла с одинаковым именем из разных подпапок получают уникальные имена в плоском /photounlim
    assert row1.remote_name != row2.remote_name

    st.mark_uploaded(row1.id, f"/photounlim/{row1.remote_name}", row1.remote_name)
    # Аварийный перезапуск: row2 завис в uploading -> должен вернуться в pending
    assert st.release_in_progress() == 1

    # Повторный скан: row1 не изменился (остаётся uploaded), row2 изменил размер (перезагрузится)
    diff2 = st.upsert_scanned_files(
        [
            _rec(p1, "2023/IMG_0001.JPG", "IMG_0001.JPG", size=100, mtime=1000),
            _rec(p2, "2024/IMG_0001.JPG", "IMG_0001.JPG", size=200, mtime=2000),
        ],
        str(tmp_path),
    )
    assert diff2["unchanged"] == 1 and diff2["updated"] == 1
    counts = st.stats()
    assert counts["uploaded"] == 1 and counts["pending"] == 1


def test_remote_and_local_dedup(tmp_path):
    st = UploadState(tmp_path / "u.db")
    st.replace_remote_index(
        [("/photounlim/existing.jpg", "existing.jpg", 123, "aaa111", 1_700_000_000.0)]
    )
    st.upsert_scanned_files(
        [
            _rec(str(tmp_path / "a.jpg"), "a.jpg", "a.jpg", size=123),
            _rec(str(tmp_path / "b.jpg"), "b.jpg", "b.jpg", size=456),
            _rec(str(tmp_path / "c.jpg"), "c.jpg", "c.jpg", size=456),
        ],
        str(tmp_path),
    )

    r1 = st.take_next_pending()
    r2 = st.take_next_pending()
    r3 = st.take_next_pending()
    assert r1 and r2 and r3

    v1, ref1 = st.mark_hashes_and_check_dup(r1.id, "AAA111", "sha1", 123)
    assert v1 == "skipped_remote" and ref1 == "/photounlim/existing.jpg"

    v2, _ = st.mark_hashes_and_check_dup(r2.id, "bbb222", "sha2", 456)
    assert v2 == "ok"
    st.mark_uploaded(r2.id, "/photounlim/b.jpg", "b.jpg")

    v3, ref3 = st.mark_hashes_and_check_dup(r3.id, "bbb222", "sha2", 456)
    assert v3 == "skipped_dup_local" and ref3 == "b.jpg"
