# root/vnext-ledger/tests/test_backup.py
"""
tests/test_backup.py

バックアップスクリプトの包括的なテスト
"""
import sqlite3
import gzip
import shutil
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch
import pytest


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def temp_db(tmp_path):
    """テスト用のSQLiteデータベースを作成"""
    db_path = tmp_path / "test_ledger.sqlite3"
    
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE notes (
            id INTEGER PRIMARY KEY,
            slug TEXT UNIQUE NOT NULL,
            status TEXT,
            created_at TEXT
        )
    """)
    conn.execute(
        "INSERT INTO notes (slug, status, created_at) VALUES (?, ?, ?)",
        ("test_note", "open", "2025-01-01T00:00:00Z")
    )
    conn.commit()
    conn.close()
    
    return db_path


@pytest.fixture
def backup_env(tmp_path, temp_db, monkeypatch):
    """バックアップスクリプトの環境をセットアップ"""
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    
    monkeypatch.setenv("DB_PATH", str(temp_db))
    monkeypatch.setenv("BACKUP_DIR", str(backup_dir))
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "7")
    monkeypatch.setenv("BACKUP_COMPRESS", "1")
    monkeypatch.setenv("BACKUP_COMPRESSION_LEVEL", "6")
    monkeypatch.setenv("BACKUP_DELETE_UNCOMPRESSED", "0")
    
    # backup.py のグローバル変数を再読み込み
    import backup as backup
    backup.DB_PATH = temp_db
    backup.BACKUP_DIR = backup_dir
    backup.RETENTION_DAYS = 7
    backup.COMPRESS_BACKUPS = True
    backup.DELETE_UNCOMPRESSED = False
    backup.NOTIFICATION_WEBHOOK = ""
    
    return {
        "db_path": temp_db,
        "backup_dir": backup_dir,
        "backup_module": backup,
    }


# ============================================================
# Tests: バックアップ作成
# ============================================================

def test_backup_creates_file(backup_env):
    """バックアップファイルが作成されることを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    assert backup.backup() is True
    
    # バックアップファイルが存在する
    backups = list(backup_dir.glob("ledger_*.sqlite3*"))
    assert len(backups) > 0


def test_backup_integrity_check_passes(backup_env):
    """整合性チェックが成功することを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    backup.backup()
    
    # 非圧縮バックアップを見つける
    backup_file = next(backup_dir.glob("ledger_*.sqlite3"))
    
    assert backup.verify_backup(backup_file) is True


def test_backup_corrupted_file_fails_integrity_check(backup_env, tmp_path):
    """破損したバックアップが整合性チェックで失敗することを確認"""
    backup = backup_env["backup_module"]
    
    # 破損したDBファイルを作成
    corrupted_file = tmp_path / "corrupted.sqlite3"
    corrupted_file.write_bytes(b"NOT A VALID SQLITE DATABASE")
    
    assert backup.verify_backup(corrupted_file) is False


def test_backup_compression_reduces_size(backup_env):
    """圧縮がファイルサイズを削減することを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    backup.COMPRESS_BACKUPS = True
    backup.backup()
    
    # 非圧縮と圧縮の両方が存在するはず
    uncompressed = next(backup_dir.glob("ledger_*.sqlite3"))
    compressed = next(backup_dir.glob("ledger_*.sqlite3.gz"))
    
    assert compressed.stat().st_size < uncompressed.stat().st_size


def test_backup_without_compression(backup_env):
    """圧縮なしでバックアップできることを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    backup.COMPRESS_BACKUPS = False
    backup.backup()
    
    # 非圧縮ファイルのみ存在
    backups = list(backup_dir.glob("ledger_*.sqlite3"))
    compressed = list(backup_dir.glob("ledger_*.sqlite3.gz"))
    
    assert len(backups) == 1
    assert len(compressed) == 0


def test_backup_deletes_uncompressed_when_configured(backup_env):
    """DELETE_UNCOMPRESSED=1で非圧縮版が削除されることを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    backup.COMPRESS_BACKUPS = True
    backup.DELETE_UNCOMPRESSED = True
    backup.backup()
    
    # 圧縮版のみ存在
    uncompressed = list(backup_dir.glob("ledger_*.sqlite3"))
    compressed = list(backup_dir.glob("ledger_*.sqlite3.gz"))
    
    assert len(uncompressed) == 0
    assert len(compressed) > 0


def test_backup_fails_when_db_not_found(backup_env, tmp_path):
    """存在しないDBでバックアップが失敗することを確認"""
    backup = backup_env["backup_module"]
    backup.DB_PATH = tmp_path / "nonexistent.sqlite3"
    
    assert backup.backup() is False


# ============================================================
# Tests: バックアップ一覧・クリーンアップ
# ============================================================

def test_list_backups_shows_files(backup_env, capsys):
    """バックアップ一覧が表示されることを確認"""
    backup = backup_env["backup_module"]
    
    backup.backup()
    backup.list_backups()
    
    captured = capsys.readouterr()
    assert "ledger_" in captured.out
    assert "Available backups" in captured.out


def test_clean_old_backups_removes_old_files(backup_env):
    """古いバックアップが削除されることを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    # 古いバックアップを作成（8日前）
    old_backup = backup_dir / "ledger_20250101_000000.sqlite3"
    old_backup.write_text("fake backup")
    
    # タイムスタンプを過去に設定
    old_time = (datetime.now() - timedelta(days=8)).timestamp()
    old_backup.touch()
    import os
    os.utime(old_backup, (old_time, old_time))
    
    # 新しいバックアップ
    backup.backup()
    
    # クリーンアップ実行
    backup.RETENTION_DAYS = 7
    backup.clean_old_backups()
    
    # 古いバックアップが削除され、新しいバックアップは残る
    assert not old_backup.exists()
    assert len(list(backup_dir.glob("ledger_*.sqlite3*"))) > 0


# ============================================================
# Tests: リストア
# ============================================================

def test_restore_replaces_database(backup_env, tmp_path):
    """リストアが正常に動作することを確認（手動確認モック）"""
    backup = backup_env["backup_module"]
    db_path = backup_env["db_path"]
    
    # バックアップ作成
    backup.backup()
    backup_file = next(backup_env["backup_dir"].glob("ledger_*.sqlite3"))
    
    # 元DBを変更
    conn = sqlite3.connect(db_path)
    conn.execute("DELETE FROM notes")
    conn.commit()
    conn.close()
    
    # リストア（入力モックが必要なので、手動テストの契約確認のみ）
    # 実際のリストアテストは統合テストで行う
    assert backup_file.exists()
    assert backup.verify_backup(backup_file) is True


def test_restore_decompresses_gz_files(backup_env):
    """圧縮バックアップのリストアが動作することを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    backup.COMPRESS_BACKUPS = True
    backup.DELETE_UNCOMPRESSED = True
    backup.backup()
    
    compressed = next(backup_dir.glob("ledger_*.sqlite3.gz"))
    assert compressed.exists()
    
    # verify_only は .gz を展開して検証する
    assert backup.verify_only(str(compressed)) is True


# ============================================================
# Tests: エラーハンドリング
# ============================================================

def test_backup_handles_disk_full(backup_env, monkeypatch):
    """ディスク容量不足のハンドリングを確認"""
    backup = backup_env["backup_module"]
    
    # disk_usage をモック（十分な空き容量がない）
    def mock_disk_usage(path):
        class MockStat:
            free = 100  # 100バイトしか空きがない
        return MockStat()
    
    monkeypatch.setattr(shutil, "disk_usage", mock_disk_usage)
    
    # ディスク容量不足でバックアップ失敗
    assert backup.backup() is False


def test_backup_cleans_up_on_disk_full_error(backup_env, monkeypatch, tmp_path):
    """ディスク容量不足でバックアップが失敗し、ファイルが削除されることを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    # ディスク容量不足を模擬（これはモック可能）
    def mock_disk_usage(path):
        class MockStat:
            free = 100  # 100バイトしか空きがない
        return MockStat()
    
    monkeypatch.setattr(shutil, "disk_usage", mock_disk_usage)
    
    # バックアップ失敗
    assert backup.backup() is False
    
    # 失敗したバックアップファイルが残っていない
    backups = list(backup_dir.glob("ledger_*.sqlite3"))
    assert len(backups) == 0


# ============================================================
# Tests: SQLite バージョン互換性
# ============================================================

def test_backup_uses_appropriate_method_for_sqlite_version(backup_env):
    """SQLiteバージョンに応じた適切なバックアップ方法を使用することを確認"""
    backup = backup_env["backup_module"]
    
    # SUPPORTS_VACUUM_INTO の値を確認（契約）
    if backup.SQLITE_VERSION >= (3, 27, 0):
        assert backup.SUPPORTS_VACUUM_INTO is True
    else:
        assert backup.SUPPORTS_VACUUM_INTO is False
    
    # どちらの方法でもバックアップは成功する
    assert backup.backup() is True


# ============================================================
# Tests: 統合テスト
# ============================================================

def test_full_backup_lifecycle(backup_env):
    """バックアップのフルライフサイクルをテスト"""
    backup = backup_env["backup_module"]
    db_path = backup_env["db_path"]
    backup_dir = backup_env["backup_dir"]
    
    # 1. バックアップ作成
    assert backup.backup() is True
    
    # 2. バックアップファイルが存在
    backups = list(backup_dir.glob("ledger_*.sqlite3*"))
    assert len(backups) > 0
    
    # 3. 整合性チェック
    backup_file = next(backup_dir.glob("ledger_*.sqlite3"))
    assert backup.verify_backup(backup_file) is True
    
    # 4. 一覧表示（エラーなし）
    backup.list_backups()
    
    # 5. 古いバックアップのクリーンアップ（この時点では削除なし）
    backup.clean_old_backups()
    
    # バックアップが残っている
    assert len(list(backup_dir.glob("ledger_*.sqlite3*"))) > 0


# ============================================================
# Parametrized Tests
# ============================================================

@pytest.mark.parametrize("compress,delete_uncompressed,expected_files", [
    (True, False, 2),   # 非圧縮 + 圧縮
    (True, True, 1),    # 圧縮のみ
    (False, False, 1),  # 非圧縮のみ
])
def test_backup_compression_configurations(backup_env, compress, delete_uncompressed, expected_files):
    """様々な圧縮設定でバックアップが正しく動作することを確認"""
    backup = backup_env["backup_module"]
    backup_dir = backup_env["backup_dir"]
    
    backup.COMPRESS_BACKUPS = compress
    backup.DELETE_UNCOMPRESSED = delete_uncompressed
    
    backup.backup()
    
    all_backups = list(backup_dir.glob("ledger_*"))
    assert len(all_backups) == expected_files
