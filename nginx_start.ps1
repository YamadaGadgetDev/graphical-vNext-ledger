# nginx_start.ps1
<#
============================================================
NOTE(vNext): 使用上の注意
- Nginx 本体一式（nginx.exe / conf / html / logs / temp etc）は
  必ず  C:\nginx\  の直下に「丸ごと」置くこと。
- このスクリプトは vNext-ledger の ROOT 直下に置く前提。
- ここを守らないと nginx が logs/error.log を相対パスで探して死ぬ。
============================================================
#>

param(
  [switch]$TestOnly,
  [switch]$Reload
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ====== 固定：nginx は C:\nginx に置く ======
$NGINX_HOME = "C:\nginx"
$NGINX_EXE  = Join-Path $NGINX_HOME "nginx.exe"
$NGINX_CONF = Join-Path $NGINX_HOME "conf\nginx.conf"

function Info($m){ Write-Host "[nginx-start] $m" }
function Warn($m){ Write-Host "[nginx-start] WARN: $m" -ForegroundColor Yellow }

if (!(Test-Path $NGINX_EXE))  { throw "nginx.exe not found: $NGINX_EXE  (C:\nginx に一式置け)" }
if (!(Test-Path $NGINX_CONF)) { throw "nginx.conf not found: $NGINX_CONF  (C:\nginx\conf\nginx.conf を確認)" }

$running = Get-Process nginx -ErrorAction SilentlyContinue

if ($Reload) {
  if (!$running) { throw "nginx is not running; cannot reload." }
  Info "Reloading nginx..."
  Push-Location $NGINX_HOME
  try { & $NGINX_EXE -s reload | Out-Null } finally { Pop-Location }
  Info "DONE (reload)."
  exit 0
}

if ($running) {
  Info "nginx already running (count=$($running.Count)). Nothing to do."
  exit 0
}

Info "Testing config..."
Push-Location $NGINX_HOME
try {
  & $NGINX_EXE -t | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "nginx -t failed (exit=$LASTEXITCODE). Check $NGINX_HOME\logs\error.log" }
} finally {
  Pop-Location
}

if ($TestOnly) {
  Info "DONE (test only)."
  exit 0
}

Info "Starting nginx..."
Start-Process -FilePath $NGINX_EXE -WorkingDirectory $NGINX_HOME | Out-Null
Start-Sleep -Milliseconds 700

$running = Get-Process nginx -ErrorAction SilentlyContinue
if (!$running) { throw "nginx failed to start. Check $NGINX_HOME\logs\error.log" }

Info "DONE. nginx running (count=$($running.Count))."
