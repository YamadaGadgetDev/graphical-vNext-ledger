# nginx_stop.ps1
<#
============================================================
NOTE(vNext): 使用上の注意
- Nginx 本体一式は必ず C:\nginx\ に置くこと（相対パス前提が残る）。
- この stop は "graceful quit" だけ投げる。残骸掃除は reset に任せる。
============================================================
#>

param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$NGINX_HOME = "C:\nginx"
$NGINX_EXE  = Join-Path $NGINX_HOME "nginx.exe"

function Info($m){ Write-Host "[nginx-stop] $m" }
function Warn($m){ Write-Host "[nginx-stop] WARN: $m" -ForegroundColor Yellow }

$running = Get-Process nginx -ErrorAction SilentlyContinue
if (!$running) {
  Info "nginx is not running."
  exit 0
}

if (Test-Path $NGINX_EXE) {
  Info "Stopping nginx (graceful quit)..."
  Push-Location $NGINX_HOME
  try { & $NGINX_EXE -s quit | Out-Null } catch { Warn "Failed to send quit: $($_.Exception.Message)" } finally { Pop-Location }
  Start-Sleep -Milliseconds 900
} else {
  Warn "nginx.exe not found at $NGINX_EXE; cannot send -s quit. Run nginx_reset.ps1 if needed."
}

$running = Get-Process nginx -ErrorAction SilentlyContinue
if ($running) {
  Warn "nginx still running (count=$($running.Count)). If this persists, run nginx_reset.ps1 -ForceKill"
} else {
  Info "DONE. nginx stopped."
}
