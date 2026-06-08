# Setup script for logos-blockchain-circuits (Windows / PowerShell).
#
# Usage:
#   .\setup-logos-blockchain-circuits.ps1 [-Version <ver>] [-InstallDir <path>]
#
# Defaults:
#   Version    : v0.4.2
#   InstallDir : $env:LOCALAPPDATA\logos-blockchain-circuits\cache\<Version>
#
# Examples:
#   .\setup-logos-blockchain-circuits.ps1
#   .\setup-logos-blockchain-circuits.ps1 -Version v0.4.2
#   .\setup-logos-blockchain-circuits.ps1 -Version v0.4.2 -InstallDir C:\circuits

[CmdletBinding()]
param(
    [string]$Version = "v0.4.2",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

$Repo = "logos-blockchain/logos-blockchain-circuits"

function Get-DefaultInstallDir {
    param([string]$Version)
    $cacheRoot = $env:LOCALAPPDATA
    if (-not $cacheRoot) {
        throw "LOCALAPPDATA environment variable is not set; supply -InstallDir explicitly."
    }
    return (Join-Path -Path $cacheRoot -ChildPath "logos-blockchain-circuits\cache\$Version")
}

function Get-Platform {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        "AMD64" { return "windows-x86_64" }
        "ARM64" { return "windows-aarch64" }
        default { throw "Unsupported architecture: $arch" }
    }
}

function Write-Info    ([string]$m) { Write-Host "i $m" -ForegroundColor Cyan }
function Write-Success ([string]$m) { Write-Host "+ $m" -ForegroundColor Green }
function Write-Warn    ([string]$m) { Write-Host "! $m" -ForegroundColor Yellow }
function Write-Fail    ([string]$m) { Write-Host "x $m" -ForegroundColor Red }

if (-not $InstallDir) {
    $InstallDir = Get-DefaultInstallDir -Version $Version
}

$Platform = Get-Platform
$Artifact = "logos-blockchain-circuits-$Version-$Platform.tar.gz"
$Url      = "https://github.com/$Repo/releases/download/$Version/$Artifact"

Write-Info "Setting up logos-blockchain-circuits $Version"
Write-Info "Platform: $Platform"
Write-Info "Install directory: $InstallDir"

# Idempotency: skip download if the target dir already has a matching VERSION stamp.
$VersionFile = Join-Path -Path $InstallDir -ChildPath "VERSION"
if ((Test-Path -Path $VersionFile) -and ((Get-Content -Path $VersionFile -Raw).Trim() -eq $Version)) {
    Write-Info "logos-blockchain-circuits $Version already present at $InstallDir"
    exit 0
}

if (Test-Path -Path $InstallDir) {
    Write-Warn "Removing existing installation at $InstallDir"
    Remove-Item -Path $InstallDir -Recurse -Force
}

$TempDir = New-Item -ItemType Directory -Path ([System.IO.Path]::GetTempPath()) `
                    -Name ("lbc-" + [System.Guid]::NewGuid().ToString("N"))
$TempFile = Join-Path -Path $TempDir.FullName -ChildPath $Artifact

try {
    Write-Info "Downloading: $Url"
    $headers = @{}
    if ($env:GITHUB_TOKEN) {
        $headers["Authorization"] = "Bearer $env:GITHUB_TOKEN"
    }
    Invoke-WebRequest -Uri $Url -OutFile $TempFile -Headers $headers -UseBasicParsing

    Write-Info "Extracting to $InstallDir"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    # tar is available on Windows 10+ (1803+) and Windows Server 2019+.
    tar -xzf $TempFile -C $InstallDir --strip-components=1
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed" }

    Write-Success "Installation complete!"
    Write-Info "logos-blockchain-circuits $Version is now installed at: $InstallDir"
}
finally {
    Remove-Item -Path $TempDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
