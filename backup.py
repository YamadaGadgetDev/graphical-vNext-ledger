# root/vnext-ledger/backup.py

"""
vNext Ledger バックアップスクリプト（改善版）

主な改善点:
- SQLite推奨のVACUUM INTOまたは.backup() APIを使用（ファイルコピーの問題を回避）
- PRAGMA integrity_checkによる整合性検証
- gzip圧縮でストレージ節約
- .envファイルとの統合
- ディスク容量チェック
- 通知機能（オプション）
- 失敗したバックアップの自動削除

使い方:
    python backup.py                    # バックアップ実行
    python backup.py --list             # バックアップ一覧
    python backup.py --clean            # 古いバックアップ削除
    python backup.py --restore <file>   # リストア
    python backup.py --verify <file>    # 整合性検証のみ
"""
import os
import sys
import gzip
import shutil
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

# .env統合
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# 色付き出力（オプション）
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    CYAN = Fore.CYAN
    RESET = Style.RESET_ALL
except ImportError:
    GREEN = YELLOW = RED = CYAN = RESET = ""

# ============================================================
# 設定（環境変数または引数で上書き可能）
# ============================================================
DB_PATH = Path(os.getenv("DB_PATH", "ledger.sqlite3"))
BACKUP_DIR = Path(os.getenv("BACKUP_DIR", "backups"))
RETENTION_DAYS = int(os.getenv("BACKUP_RETENTION_DAYS", "7"))
COMPRESSION_LEVEL = int(os.getenv("BACKUP_COMPRESSION_LEVEL", "6"))  # 1-9
COMPRESS_BACKUPS = os.getenv("BACKUP_COMPRESS", "1").lower() in {"1", "true", "yes"}
DELETE_UNCOMPRESSED = os.getenv("BACKUP_DELETE_UNCOMPRESSED", "0").lower() in {"1", "true", "yes"}
NOTIFICATION_WEBHOOK = os.getenv("BACKUP_NOTIFICATION_WEBHOOK", "")

# SQLite バージョンチェック用
SQLITE_VERSION = tuple(map(int, sqlite3.sqlite_version.split(".")))
SUPPORTS_VACUUM_INTO = SQLITE_VERSION >= (3, 27, 0)


def log(msg: str, color: str = "") -> None:
    """ログ出力"""
    print(f"{color}{msg}{RESET}")


def ensure_backup_dir() -> None:
    """バックアップディレクトリ作成"""
    BACKUP_DIR.mkdir(exist_ok=True)


def check_disk_space(required_bytes: int) -> bool:
    """ディスク容量チェック（1.5倍の余裕を確保）"""
    try:
        stat = shutil.disk_usage(BACKUP_DIR)
        required_with_margin = required_bytes * 1.5
        
        if stat.free < required_with_margin:
            log(f"❌ Insufficient disk space", RED)
            log(f"   Required: {required_with_margin/(1024**2):.2f} MB", RED)
            log(f"   Available: {stat.free/(1024**2):.2f} MB", RED)
            return False
        return True
    except Exception as e:
        log(f"⚠️  Disk space check failed (continuing): {e}", YELLOW)
        return True  # エラー時は続行（保守的）


def verify_backup(backup_file: Path) -> bool:
    """バックアップの整合性チェック（PRAGMA integrity_check）"""
    try:
        conn = sqlite3.connect(backup_file)
        cursor = conn.execute("PRAGMA integrity_check")
        result = cursor.fetchone()[0]
        conn.close()
        
        if result == "ok":
            log(f"   ✅ Integrity check: OK", GREEN)
            return True
        else:
            log(f"❌ Integrity check failed: {backup_file.name}", RED)
            log(f"   Result: {result}", RED)
            return False
    
    except Exception as e:
        log(f"❌ Integrity check error: {e}", RED)
        return False


def compress_backup(source: Path) -> Optional[Path]:
    """バックアップファイルをgzip圧縮"""
    if not COMPRESS_BACKUPS:
        return None
    
    compressed_file = source.with_suffix('.sqlite3.gz')
    
    try:
        with open(source, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb', compresslevel=COMPRESSION_LEVEL) as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        original_size = source.stat().st_size / (1024 * 1024)
        compressed_size = compressed_file.stat().st_size / (1024 * 1024)
        ratio = (1 - compressed_size/original_size) * 100
        
        log(f"   ✅ Compressed: {compressed_file.name}", GREEN)
        log(f"   Original: {original_size:.2f} MB → Compressed: {compressed_size:.2f} MB ({ratio:.1f}% saved)", CYAN)
        
        # オプション: 非圧縮版を削除してスペース節約
        if DELETE_UNCOMPRESSED:
            source.unlink()
            log(f"   🗑️  Deleted uncompressed file", CYAN)
        
        return compressed_file
    
    except Exception as e:
        log(f"⚠️  Compression failed (keeping uncompressed): {e}", YELLOW)
        if compressed_file.exists():
            compressed_file.unlink()
        return None


def notify(subject: str, message: str) -> None:
    """バックアップ結果を通知（例: Slack、Discord、メール）"""
    if not NOTIFICATION_WEBHOOK:
        return
    
    try:
        import requests
        payload = {
            "text": f"**{subject}**\n{message}",
            "username": "vNext Ledger Backup",
        }
        response = requests.post(NOTIFICATION_WEBHOOK, json=payload, timeout=10)
        
        if response.status_code == 200:
            log(f"   📬 Notification sent", CYAN)
        else:
            log(f"⚠️  Notification failed: {response.status_code}", YELLOW)
    
    except Exception as e:
        log(f"⚠️  Notification failed: {e}", YELLOW)


def backup() -> bool:
    """
    バックアップ実行（SQLite推奨方式）
    
    使用する方式:
    1. VACUUM INTO（SQLite 3.27+、最も推奨）
    2. .backup() API（古いSQLiteでも動作）
    """
    if not DB_PATH.exists():
        log(f"❌ Database not found: {DB_PATH}", RED)
        notify("❌ Backup Failed", f"Database not found: {DB_PATH}")
        return False
    
    ensure_backup_dir()
    
    # ディスク容量チェック
    db_size = DB_PATH.stat().st_size
    if not check_disk_space(db_size):
        notify("❌ Backup Failed", "Insufficient disk space")
        return False
    
    # バックアップファイル名
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = BACKUP_DIR / f"ledger_{timestamp}.sqlite3"
    
    try:
        log(f"🗄️  Creating backup...", CYAN)
        log(f"   Source: {DB_PATH}", CYAN)
        log(f"   Destination: {backup_file}", CYAN)
        
        conn = sqlite3.connect(DB_PATH)
        
        if SUPPORTS_VACUUM_INTO:
            # 方法1: VACUUM INTO（最も推奨、トランザクション安全）
            log(f"   Using VACUUM INTO (SQLite {sqlite3.sqlite_version})", CYAN)
            conn.execute(f"VACUUM INTO '{backup_file}'")
        else:
            # 方法2: .backup() API（古いSQLiteでも動作）
            log(f"   Using .backup() API (SQLite {sqlite3.sqlite_version})", CYAN)
            backup_conn = sqlite3.connect(backup_file)
            conn.backup(backup_conn)
            backup_conn.close()
        
        conn.close()
        
        # サイズ確認
        size_mb = backup_file.stat().st_size / (1024 * 1024)
        log(f"✅ Backup created: {backup_file.name}", GREEN)
        log(f"   Size: {size_mb:.2f} MB", CYAN)
        
        # 整合性チェック
        if not verify_backup(backup_file):
            log(f"❌ Backup integrity check failed, deleting corrupted file", RED)
            backup_file.unlink()
            notify("❌ Backup Failed", "Integrity check failed")
            return False
        
        # 圧縮（オプション）
        compressed = compress_backup(backup_file)
        
        # 通知
        final_file = compressed if compressed else backup_file
        notify("✅ Backup Success", f"File: {final_file.name}\nSize: {size_mb:.2f} MB")
        
        return True
    
    except Exception as e:
        log(f"❌ Backup failed: {e}", RED)
        
        # 失敗したバックアップファイルを削除
        if backup_file.exists():
            backup_file.unlink()
            log(f"   🗑️  Cleaned up failed backup", YELLOW)
        
        notify("❌ Backup Failed", str(e))
        return False


def list_backups() -> None:
    """バックアップ一覧表示"""
    ensure_backup_dir()
    
    # .sqlite3 と .sqlite3.gz の両方を取得
    backups = sorted(
        list(BACKUP_DIR.glob("ledger_*.sqlite3")) + list(BACKUP_DIR.glob("ledger_*.sqlite3.gz")),
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    
    if not backups:
        log("📁 No backups found", YELLOW)
        return
    
    log(f"\n📁 Available backups ({len(backups)}):\n", CYAN)
    log(f"{'Filename':<35} {'Size':>10} {'Created':>20}", YELLOW)
    log("-" * 70, YELLOW)
    
    for backup_file in backups:
        size_mb = backup_file.stat().st_size / (1024 * 1024)
        mtime = datetime.fromtimestamp(backup_file.stat().st_mtime)
        mtime_str = mtime.strftime("%Y-%m-%d %H:%M:%S")
        
        # 圧縮マーク
        compressed_mark = "📦" if backup_file.suffix == ".gz" else "  "
        
        log(f"{compressed_mark} {backup_file.name:<32} {size_mb:>9.2f}M {mtime_str:>20}")
    
    log("")


def clean_old_backups() -> None:
    """古いバックアップ削除（保持日数以上前のもの）"""
    ensure_backup_dir()
    
    cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
    deleted = 0
    
    for pattern in ["ledger_*.sqlite3", "ledger_*.sqlite3.gz"]:
        for backup_file in BACKUP_DIR.glob(pattern):
            mtime = datetime.fromtimestamp(backup_file.stat().st_mtime)
            
            if mtime < cutoff:
                try:
                    backup_file.unlink()
                    log(f"🗑️  Deleted: {backup_file.name}", YELLOW)
                    deleted += 1
                except Exception as e:
                    log(f"❌ Failed to delete {backup_file.name}: {e}", RED)
    
    if deleted == 0:
        log(f"✅ No backups older than {RETENTION_DAYS} days", GREEN)
    else:
        log(f"✅ Deleted {deleted} old backup(s)", GREEN)


def restore(backup_file_path: str) -> bool:
    """バックアップからリストア"""
    backup_file = Path(backup_file_path)
    
    if not backup_file.exists():
        log(f"❌ Backup file not found: {backup_file}", RED)
        return False
    
    # .gz の場合は展開が必要
    if backup_file.suffix == ".gz":
        log(f"📦 Decompressing backup...", CYAN)
        temp_file = backup_file.with_suffix('')
        
        try:
            with gzip.open(backup_file, 'rb') as f_in:
                with open(temp_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            backup_file = temp_file
            log(f"   ✅ Decompressed", GREEN)
        except Exception as e:
            log(f"❌ Decompression failed: {e}", RED)
            return False
    
    # 整合性チェック
    log(f"🔍 Verifying backup integrity...", CYAN)
    if not verify_backup(backup_file):
        log(f"❌ Backup file is corrupted, aborting restore", RED)
        return False
    
    # 確認
    log(f"\n⚠️  WARNING: This will replace current database", YELLOW)
    log(f"Backup file: {backup_file}", CYAN)
    log(f"Target: {DB_PATH}", CYAN)
    
    response = input(f"\n{RED}Continue? (yes/no): {RESET}").strip().lower()
    
    if response != "yes":
        log("❌ Cancelled", YELLOW)
        return False
    
    try:
        # 現在のDBを退避
        if DB_PATH.exists():
            broken_name = f"{DB_PATH}.broken.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            shutil.move(str(DB_PATH), broken_name)
            log(f"✅ Current DB backed up as: {broken_name}", GREEN)
        
        # リストア
        shutil.copy2(backup_file, DB_PATH)
        log(f"✅ Restore complete: {DB_PATH}", GREEN)
        log(f"\n{CYAN}Please restart the app and check /healthz{RESET}\n")
        
        notify("✅ Restore Complete", f"Restored from: {backup_file.name}")
        
        return True
    
    except Exception as e:
        log(f"❌ Restore failed: {e}", RED)
        notify("❌ Restore Failed", str(e))
        return False


def verify_only(backup_file_path: str) -> bool:
    """整合性検証のみ（リストアなし）"""
    backup_file = Path(backup_file_path)
    
    if not backup_file.exists():
        log(f"❌ Backup file not found: {backup_file}", RED)
        return False
    
    # .gz の場合は一時展開
    if backup_file.suffix == ".gz":
        log(f"📦 Decompressing for verification...", CYAN)
        temp_file = backup_file.with_suffix('')
        
        try:
            with gzip.open(backup_file, 'rb') as f_in:
                with open(temp_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            backup_file = temp_file
            log(f"   ✅ Decompressed", GREEN)
        except Exception as e:
            log(f"❌ Decompression failed: {e}", RED)
            return False
    
    log(f"🔍 Verifying: {backup_file}", CYAN)
    result = verify_backup(backup_file)
    
    # 一時ファイル削除
    if backup_file.name.startswith("ledger_") and not backup_file_path.endswith(".gz"):
        backup_file.unlink()
    
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="vNext Ledger バックアップ管理（改善版）")
    parser.add_argument("--list", action="store_true", help="バックアップ一覧表示")
    parser.add_argument("--clean", action="store_true", help="古いバックアップ削除")
    parser.add_argument("--restore", metavar="FILE", help="バックアップからリストア")
    parser.add_argument("--verify", metavar="FILE", help="整合性検証のみ")
    parser.add_argument("--db", help="データベースファイルパス")
    parser.add_argument("--backup-dir", help="バックアップディレクトリ")
    parser.add_argument("--retention-days", type=int, help="保持日数")
    parser.add_argument("--no-compress", action="store_true", help="圧縮しない")
    parser.add_argument("--notify-webhook", help="通知用WebhookURL")
    
    args = parser.parse_args()
    
    # グローバル設定を上書き
    global DB_PATH, BACKUP_DIR, RETENTION_DAYS, COMPRESS_BACKUPS, NOTIFICATION_WEBHOOK
    
    if args.db:
        DB_PATH = Path(args.db)
    if args.backup_dir:
        BACKUP_DIR = Path(args.backup_dir)
    if args.retention_days is not None:
        RETENTION_DAYS = args.retention_days
    if args.no_compress:
        COMPRESS_BACKUPS = False
    if args.notify_webhook:
        NOTIFICATION_WEBHOOK = args.notify_webhook
    
    # コマンド実行
    if args.list:
        list_backups()
    
    elif args.clean:
        clean_old_backups()
    
    elif args.restore:
        success = restore(args.restore)
        sys.exit(0 if success else 1)
    
    elif args.verify:
        success = verify_only(args.verify)
        sys.exit(0 if success else 1)
    
    else:
        # デフォルト: バックアップ実行
        log("🗄️  vNext Ledger Backup", CYAN)
        log(f"   SQLite version: {sqlite3.sqlite_version}", CYAN)
        log(f"   VACUUM INTO support: {'Yes' if SUPPORTS_VACUUM_INTO else 'No (using .backup() API)'}", CYAN)
        log("")
        
        if backup():
            # 自動クリーンアップ
            clean_old_backups()
            sys.exit(0)
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()
