# nginx_reset.ps1
<#
============================================================
NOTE(vNext): 使用上の注意
- Nginx 本体一式は必ず C:\nginx\ に置くこと。
- まず quit を投げ、それでも残るなら -ForceKill で taskkill する。
============================================================
#>

param(
  [switch]$ForceKill
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$NGINX_HOME = "C:\nginx"
$NGINX_EXE  = Join-Path $NGINX_HOME "nginx.exe"

function Info($m){ Write-Host "[nginx-reset] $m" }
function Warn($m){ Write-Host "[nginx-reset] WARN: $m" -ForegroundColor Yellow }

$running = Get-Process nginx -ErrorAction SilentlyContinue
if (!$running) {
  Info "nginx is not running. Nothing to reset."
  exit 0
}

if (Test-Path $NGINX_EXE) {
  Info "Attempting graceful quit..."
  Push-Location $NGINX_HOME
  try { & $NGINX_EXE -s quit | Out-Null } catch { Warn "Failed to send quit: $($_.Exception.Message)" } finally { Pop-Location }
  Start-Sleep -Milliseconds 900
} else {
  Warn "nginx.exe not found at $NGINX_EXE; skip graceful quit."
}

$running = Get-Process nginx -ErrorAction SilentlyContinue
if ($running) {
  if ($ForceKill) {
    Info "Force killing nginx.exe..."
    taskkill /F /IM nginx.exe | Out-Null
    Start-Sleep -Milliseconds 300
  } else {
    Warn "nginx still running (count=$($running.Count)). Re-run with -ForceKill to taskkill."
  }
}

$running = Get-Process nginx -ErrorAction SilentlyContinue
if ($running) {
  Warn "nginx still running after reset attempt (count=$($running.Count)). Check manually."
} else {
  Info "DONE. nginx reset completed (stopped)."
}
