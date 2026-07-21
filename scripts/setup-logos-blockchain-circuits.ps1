# Setup script for logos-blockchain-circuits (Windows / PowerShell).
#
# Usage:
#   .\setup-logos-blockchain-circuits.ps1 [-Version <ver>] [-InstallDir <path>]
#
# Defaults:
#   Version    : v0.5.3
#   InstallDir : $env:APPDATA\logos-blockchain-circuits\<Version>
#
# Examples:
#   .\setup-logos-blockchain-circuits.ps1
#   .\setup-logos-blockchain-circuits.ps1 -Version v0.5.3
#   .\setup-logos-blockchain-circuits.ps1 -Version v0.5.3 -InstallDir C:\circuits

[CmdletBinding()]
param(
    [string]$Version = "v0.5.3",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

$Repo = "logos-blockchain/logos-blockchain-circuits"

function Get-DefaultInstallDir {
    param([string]$Version)
    # Matches std/os.getDataDir on Windows: %APPDATA% (Roaming).
    $dataRoot = $env:APPDATA
    if (-not $dataRoot) {
        throw "APPDATA environment variable is not set; supply -InstallDir explicitly."
    }
    return (Join-Path -Path $dataRoot -ChildPath "logos-blockchain-circuits\$Version")
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
    # Use the Windows built-in curl by absolute path (`%SYSTEMROOT%\System32\curl.exe`,
    # Windows 10 1803+ / Server 2019+). Resolving `curl` through PATH may pick
    # up MSYS/Git Bash curl, whose flags or path handling differ.
    $WindowsCurl = Join-Path -Path $env:SYSTEMROOT -ChildPath "System32\curl.exe"
    if (-not (Test-Path -LiteralPath $WindowsCurl)) {
        throw "Windows curl not found at $WindowsCurl (requires Windows 10 1803+ / Server 2019+)"
    }
    $curlArgs = @('-L', '--retry', '3', '--retry-all-errors', '-fsS', '-o', $TempFile, $Url)
    if ($env:GITHUB_TOKEN) {
        $curlArgs += @('-H', "Authorization: Bearer $env:GITHUB_TOKEN")
    }
    & $WindowsCurl @curlArgs
    if ($LASTEXITCODE -ne 0) { throw "curl download failed (exit $LASTEXITCODE)" }

    Write-Info "Extracting to $InstallDir"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    # Use the Windows built-in tar (bsdtar) by absolute path. If `tar` is
    # resolved through $env:Path and Git Bash is installed, MSYS tar wins
    # and treats Windows paths like `C:\...` as `host:path` rsh syntax
    # ("Cannot connect to C: resolve failed"). Available on Windows 10
    # 1803+ and Windows Server 2019+.
    $WindowsTar = Join-Path -Path $env:SYSTEMROOT -ChildPath "System32\tar.exe"
    if (-not (Test-Path -LiteralPath $WindowsTar)) {
        throw "Windows tar not found at $WindowsTar (requires Windows 10 1803+ / Server 2019+)"
    }
    & $WindowsTar -xzf $TempFile -C $InstallDir --strip-components=1
    if ($LASTEXITCODE -ne 0) { throw "tar extraction failed" }

    Write-Success "Installation complete!"
    Write-Info "logos-blockchain-circuits $Version is now installed at: $InstallDir"
}
finally {
    Remove-Item -Path $TempDir.FullName -Recurse -Force -ErrorAction SilentlyContinue
}
