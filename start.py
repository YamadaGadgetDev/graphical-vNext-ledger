#!/usr/bin/env python3
"""
vNext Ledger 起動スクリプト（Windows/Linux/macOS / nginx前提 / ngrokは“失敗したら落ちる”）

方針:
- Windowsは入口固定のため nginx を前提（fail closed）
- ngrok はデフォルトで strict（起動できない/途中で落ちたら全停止）
  - ローカルだけで良い時は: --no-ngrok
  - “とりあえず動けばOK”に戻したい時は: --soft-ngrok

============================================================
NOTE(vNext): Windows の前提（重要）

- Nginx 本体一式（nginx.exe / conf / html / logs / temp etc）は
  必ず  C:\\nginx\\  の直下に「丸ごと」置くこと。

- プロジェクトROOT直下に以下の PS1 を置く（この start.py はそれを呼ぶだけ）:
    - nginx_start.ps1
    - nginx_stop.ps1
    - nginx_reset.ps1

- PS1 が署名エラーで弾かれる場合（初回のみ）:
    Unblock-File .\\nginx_start.ps1
    Unblock-File .\\nginx_stop.ps1
    Unblock-File .\\nginx_reset.ps1

- ngrok (MS Store版推奨):
    winget install ngrok -s msstore
    ngrok config add-authtoken <token>

  ※ Windows Store 版 ngrok の設定ファイルは “場所がブレる” ので、
     本スクリプトは候補パスを探索し、見つかったら --config を付けて起動します。

- 大体この二択

    notepad "$env:LOCALAPPDATA/ngrok/ngrok.yml"
    notepad "$env:LOCALAPPDATA/Packages/ngrok.ngrok_1g87z0zv29zzc/LocalCache/Local/ngrok/ngrok.yml"



============================================================

使い方:
    python start_strict_ngrok.py                # 全部起動（ngrokも必須）
    python start_strict_ngrok.py --no-ngrok     # ローカルだけ（ngrok無し）
    python start_strict_ngrok.py --soft-ngrok   # ngrok失敗しても落ちない（旧quick挙動）
    python start_strict_ngrok.py --show-direct  # 127.0.0.1:8000 も表示
    python start_strict_ngrok.py --no-health    # ヘルスチェックをスキップ
    python start_strict_ngrok.py --no-reload    # uvicorn --reload 無効（安定運用向け）
"""

from __future__ import annotations

import argparse
import os
import platform
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, TextIO

# Ensure CWD is the repository root (same directory as this file).
# This makes relative paths and .env loading consistent across launch methods.
PROJECT_ROOT = Path(__file__).resolve().parent
os.chdir(PROJECT_ROOT)



# 色付き出力（任意）
try:
    from colorama import init, Fore, Style  # type: ignore
    init(autoreset=True)
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RED = Fore.RED
    CYAN = Fore.CYAN
    RESET = Style.RESET_ALL
except Exception:
    GREEN = YELLOW = RED = CYAN = RESET = ""


def detect_os() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    if system == "linux":
        return "linux"
    if system == "darwin":
        return "macos"
    return "unknown"


def log(msg: str, color: str = "") -> None:
    print(f"{color}{msg}{RESET}")


def run_ps1(ps1_path: Path, args: Optional[list[str]] = None) -> int:
    args = args or []
    cmd = ["powershell", "-ExecutionPolicy", "Bypass", "-File", str(ps1_path.resolve())] + args
    completed = subprocess.run(cmd, check=False)
    return completed.returncode


def start_nginx_windows() -> bool:
    ps1 = Path("nginx_start.ps1")
    if not ps1.exists():
        log(f"❌ Missing {ps1} (place nginx_start.ps1 in project ROOT)", RED)
        log("   Hint: Unblock-File .\\nginx_start.ps1", CYAN)
        return False

    rc = run_ps1(ps1)
    if rc == 0:
        log("✅ Nginx started (Windows via ps1)", GREEN)
        return True

    log(f"❌ Failed to start Nginx via ps1 (exit={rc})", RED)
    return False


def stop_nginx_windows(force_kill: bool = False) -> None:
    ps1 = Path("nginx_reset.ps1") if force_kill else Path("nginx_stop.ps1")
    if not ps1.exists():
        log(f"⚠️  Missing {ps1}. Skipping nginx stop.", YELLOW)
        return

    args: list[str] = ["-ForceKill"] if (force_kill and ps1.name == "nginx_reset.ps1") else []
    run_ps1(ps1, args=args)


def start_nginx(os_type: str) -> bool:
    log("📦 Starting Nginx...", YELLOW)

    if os_type == "windows":
        return start_nginx_windows()

    if os_type == "linux":
        try:
            r = subprocess.run(["sudo", "systemctl", "start", "nginx"], capture_output=True, text=True)
            if r.returncode == 0:
                log("✅ Nginx started (systemd)", GREEN)
                return True
        except FileNotFoundError:
            pass
        try:
            r = subprocess.run(["sudo", "service", "nginx", "start"], capture_output=True, text=True)
            if r.returncode == 0:
                log("✅ Nginx started (service)", GREEN)
                return True
        except FileNotFoundError:
            pass

        log("❌ Failed to start Nginx (not found / not installed)", RED)
        log("   Install: sudo apt install nginx", CYAN)
        return False

    if os_type == "macos":
        try:
            subprocess.run(["brew", "services", "start", "nginx"], check=True, capture_output=True)
            log("✅ Nginx started (brew)", GREEN)
            return True
        except Exception:
            log("❌ Failed to start Nginx (brew)", RED)
            log("   Install: brew install nginx", CYAN)
            return False

    log("❌ Unknown OS: cannot start Nginx automatically", RED)
    return False


def stop_nginx(os_type: str, force_kill: bool = False) -> None:
    log("🛑 Stopping Nginx...", YELLOW)

    if os_type == "windows":
        stop_nginx_windows(force_kill=force_kill)
        return

    try:
        if os_type == "linux":
            subprocess.run(["sudo", "systemctl", "stop", "nginx"], check=False)
        elif os_type == "macos":
            subprocess.run(["brew", "services", "stop", "nginx"], check=False)
    except Exception:
        pass


def start_uvicorn(reload: bool = True) -> Optional[subprocess.Popen]:
    log("🐍 Starting FastAPI (uvicorn)...", YELLOW)
    argv = [
        sys.executable, "-m", "uvicorn",
        "app:app",
        "--host", "127.0.0.1",
        "--port", "8000",
    ]
    if reload:
        argv.append("--reload")

    try:
        proc = subprocess.Popen(argv)
        for _ in range(10):  # max 5s
            if proc.poll() is not None:
                log("❌ FastAPI failed to start", RED)
                return None
            time.sleep(0.5)

        log("✅ FastAPI started (internal): http://127.0.0.1:8000", GREEN)
        return proc
    except Exception as e:
        log(f"❌ Failed to start uvicorn: {e}", RED)
        return None


def kill_process_tree_windows(pid: int) -> None:
    try:
        subprocess.run(
            ["taskkill", "/PID", str(pid), "/T", "/F"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        pass


def find_ngrok_config_windows() -> Optional[Path]:
    """
    Windows: ngrok 設定ファイル候補を探索して「存在するもの」を返す。
    （MS Store 版の Packages 配下を優先）
    """
    localapp = Path(os.environ.get("LOCALAPPDATA", ""))
    userprofile = Path(os.environ.get("USERPROFILE", ""))

    candidates: list[Path] = []

    if localapp.exists():
        candidates += list(localapp.glob(r"Packages/ngrok.ngrok_*/LocalCache/Local/ngrok/ngrok.yml"))
        candidates.append(localapp / "ngrok" / "ngrok.yml")

    if userprofile.exists():
        candidates.append(userprofile / ".ngrok2" / "ngrok.yml")
        candidates.append(userprofile / ".config" / "ngrok" / "ngrok.yml")

    for p in candidates:
        try:
            if p.exists() and p.is_file():
                return p
        except Exception:
            continue
    return None


def try_get_ngrok_public_url() -> Optional[str]:
    try:
        import json
        import urllib.request

        with urllib.request.urlopen("http://127.0.0.1:4040/api/tunnels", timeout=1.5) as r:
            data = json.loads(r.read().decode("utf-8", errors="replace"))
        for t in data.get("tunnels", []):
            url = t.get("public_url")
            if isinstance(url, str) and url.startswith("http"):
                return url
    except Exception:
        return None
    return None


def start_ngrok(os_type: str, log_dir: Path) -> tuple[Optional[subprocess.Popen], Optional[TextIO], Optional[str]]:
    log("🌐 Starting ngrok...", YELLOW)

    log_dir.mkdir(parents=True, exist_ok=True)
    ngrok_log_path = log_dir / "ngrok.log"
    f = ngrok_log_path.open("a", encoding="utf-8")

    cmd = ["ngrok", "http", "http://127.0.0.1:8080", "--log=stdout"]

    if os_type == "windows":
        cfg = find_ngrok_config_windows()
        if cfg:
            cmd += ["--config", str(cfg)]
            log(f"   using config: {cfg}", CYAN)
        else:
            log("⚠️  ngrok config not found; will use default search path", YELLOW)

    try:
        proc = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT)
        time.sleep(1.2)

        if proc.poll() is not None:
            f.flush()
            try:
                tail = ngrok_log_path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                tail = ""
            log("❌ ngrok exited immediately.", RED)
            if tail.strip():
                log("---- ngrok.log (tail) ----\n" + tail[-3500:] + "\n--------------------------", RED)
            else:
                log(f"(no log output) path={ngrok_log_path}", RED)
            try:
                f.close()
            except Exception:
                pass
            return None, None, None

        log("✅ ngrok started", GREEN)
        log(f"   log: {ngrok_log_path}", CYAN)

        public_url = try_get_ngrok_public_url()
        if public_url:
            log(f"   public: {public_url}", CYAN)
        return proc, f, public_url

    except FileNotFoundError:
        log("❌ ngrok not found in PATH", RED)
    except Exception as e:
        log(f"❌ Failed to start ngrok: {e}", RED)

    try:
        f.close()
    except Exception:
        pass
    return None, None, None


def check_health(show_direct: bool = False) -> None:
    log("\n🔍 Checking services (best-effort)...", YELLOW)
    try:
        import urllib.request

        try:
            urllib.request.urlopen("http://127.0.0.1:8080/healthz", timeout=2)
            log("✅ Nginx → FastAPI: OK", GREEN)
        except Exception:
            log("⚠️  Nginx → FastAPI: Failed (nginx upstream / /healthz route?)", YELLOW)

        if show_direct:
            try:
                urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=2)
                log("✅ FastAPI (direct/internal): OK", GREEN)
            except Exception:
                log("⚠️  FastAPI (direct/internal): Failed (/healthz route?)", YELLOW)
    except Exception:
        log("⚠️  health check skipped", YELLOW)


def main() -> None:
    parser = argparse.ArgumentParser(description="vNext Ledger起動スクリプト（ngrok strict 既定）")
    parser.add_argument("--no-nginx", action="store_true", help="Nginxを起動しない（Windowsでは禁止）")
    parser.add_argument("--no-ngrok", action="store_true", help="ngrokを起動しない（ローカル運用）")
    parser.add_argument("--soft-ngrok", action="store_true", help="ngrok失敗しても落ちない（fail open）")
    parser.add_argument("--no-health", action="store_true", help="ヘルスチェックをスキップ")
    parser.add_argument("--show-direct", action="store_true", help="内部URL (127.0.0.1:8000) を表示/health check する")
    parser.add_argument("--no-reload", action="store_true", help="uvicorn の --reload を無効化（安定運用向け）")
    args = parser.parse_args()

    os_type = detect_os()
    log(f"\n🚀 Starting vNext Ledger on {os_type}...\n", CYAN)

    if args.no_nginx and os_type == "windows":
        log("\n❌ Windows mode requires Nginx. Remove --no-nginx.\n", RED)
        sys.exit(2)

    strict_ngrok = (not args.no_ngrok) and (not args.soft_ngrok)

    processes_essential: list[subprocess.Popen] = []
    processes_optional: list[subprocess.Popen] = []
    ngrok_log_handle: Optional[TextIO] = None
    ngrok_public_url: Optional[str] = None

    def shutdown(force_kill: bool = False) -> None:
        log("\n🛑 Stopping services...", YELLOW)

        for proc in reversed(processes_optional):
            try:
                if os_type == "windows":
                    kill_process_tree_windows(proc.pid)
                else:
                    proc.terminate()
                    proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        for proc in reversed(processes_essential):
            try:
                if os_type == "windows":
                    kill_process_tree_windows(proc.pid)
                else:
                    proc.terminate()
                    proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        if not args.no_nginx:
            stop_nginx(os_type, force_kill=force_kill)

        try:
            if ngrok_log_handle:
                ngrok_log_handle.close()
        except Exception:
            pass

        log("✅ All services stopped", GREEN)

    # nginx
    if not args.no_nginx:
        if not start_nginx(os_type):
            log("\n❌ Nginx failed to start. Exiting (fail closed).\n", RED)
            sys.exit(2)

    # uvicorn（必須）
    uvicorn_proc = start_uvicorn(reload=not args.no_reload)
    if uvicorn_proc is None:
        log("\n❌ Cannot start without uvicorn. Exiting.\n", RED)
        if not args.no_nginx:
            stop_nginx(os_type, force_kill=True)
        sys.exit(1)
    processes_essential.append(uvicorn_proc)

    # health check（任意）
    if not args.no_health:
        time.sleep(1.5)
        check_health(show_direct=args.show_direct)

    # ngrok（既定：必須）
    if not args.no_ngrok:
        os.environ["PUBLIC_TUNNEL"] = "1"
        os.environ.pop("DEV_PASSWORD", None)
        ngrok_proc, ngrok_log_handle, ngrok_public_url = start_ngrok(os_type, log_dir=Path(".local"))
        if ngrok_proc:
            processes_optional.append(ngrok_proc)
        else:
            if strict_ngrok:
                log("\n❌ ngrok is required but failed to start. Shutting down (fail closed).\n", RED)
                shutdown(force_kill=False)
                sys.exit(3)
            log("⚠️  ngrok failed, but continuing because --soft-ngrok is set.", YELLOW)

    # 完了メッセージ
    log("\n" + "=" * 50, GREEN)
    log("✅ Services started!", GREEN)
    log("=" * 50, GREEN)

    if args.show_direct:
        log("Local (direct/internal): http://127.0.0.1:8000", CYAN)
    log("Local (nginx/public):    http://127.0.0.1:8080", CYAN)
    if not args.no_ngrok:
        log("ngrok dashboard:         http://127.0.0.1:4040", CYAN)
        if ngrok_public_url:
            log(f"ngrok public url:        {ngrok_public_url}", CYAN)

    log("\nStop: Ctrl+C\n", YELLOW)

    def signal_handler(sig, frame) -> None:
        shutdown(force_kill=False)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    # 監視ループ：必須プロセスが落ちたら全停止。ngrokも strict なら落ちたら全停止。
    try:
        while True:
            for proc in processes_essential:
                if proc.poll() is not None:
                    log("❌ uvicorn exited. Shutting down...", RED)
                    shutdown(force_kill=True)
                    return

            if strict_ngrok:
                for proc in processes_optional:
                    if proc.poll() is not None:
                        log("❌ ngrok exited (strict). Shutting down...", RED)
                        shutdown(force_kill=False)
                        return

            time.sleep(0.5)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()