[CmdletBinding()]
param(
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $Python)) {
    throw "Missing .venv. Run: python -m venv .venv; .\.venv\Scripts\python -m pip install -r requirements.txt"
}

$env:SENTRY_X_MANAGEMENT_HOST = "127.0.0.1"
$env:SENTRY_X_MANAGEMENT_PORT = "$Port"
$logDirectory = Join-Path $ProjectRoot "data"
New-Item -ItemType Directory -Force -Path $logDirectory | Out-Null
$stdout = Join-Path $logDirectory "management-api.out.log"
$stderr = Join-Path $logDirectory "management-api.err.log"
$process = Start-Process -FilePath $Python -ArgumentList "-m", "app.api.run_management" -WorkingDirectory $ProjectRoot -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru

$healthUrl = "http://127.0.0.1:$Port/api/health"
for ($attempt = 1; $attempt -le 20; $attempt++) {
    try {
        $health = Invoke-RestMethod -Uri $healthUrl -TimeoutSec 2
        if ($health.status -eq "ok") {
            Write-Host "AIRLOCK console: http://127.0.0.1:$Port/"
            Write-Host "Health check passed. Process ID: $($process.Id)"
            exit 0
        }
    } catch {
        Start-Sleep -Milliseconds 500
    }
}

Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
throw "Management API failed its health check. See $stdout and $stderr"
