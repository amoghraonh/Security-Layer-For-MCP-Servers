[CmdletBinding()]
param(
    [int]$Port = 8000
)

# AIRLOCK launcher. The delegated script retains legacy environment-variable
# names so existing local configuration continues to work during the rebrand.
& "$PSScriptRoot\start_sentry_x.ps1" -Port $Port
exit $LASTEXITCODE
