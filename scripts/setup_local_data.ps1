[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$FixtureRoot = Join-Path $ProjectRoot "data\local_mcp_fixture"
$RepositoryPath = Join-Path $FixtureRoot "github-gitignore"
$RepositoryUrl = "https://github.com/github/gitignore.git"

if (Test-Path -LiteralPath $RepositoryPath) {
    Write-Host "Local Git fixture already exists: $RepositoryPath"
    exit 0
}

New-Item -ItemType Directory -Force -Path $FixtureRoot | Out-Null
git clone --depth 1 $RepositoryUrl $RepositoryPath
if ($LASTEXITCODE -ne 0) {
    throw "Could not clone the public Git fixture. Check Git/network access and retry."
}

Write-Host "Created harmless local Git fixture: $RepositoryPath"
