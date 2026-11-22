<#
.SYNOPSIS
Packages Windows release archive (nexus.exe, optional nexus-desktop.exe, sample config, SHA-256).
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$CoreBinary,
    [string]$DesktopBinary = "",
    [string]$Version = "dev",
    [string]$OutputDir = "dist"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")

if (-not (Test-Path $CoreBinary -PathType Leaf)) {
    throw "nexus.exe not found at $CoreBinary"
}

$PkgName = "nexus-$Version-windows-amd64"
$StageRoot = Join-Path $RepoRoot "target/pkg-win/$PkgName"
if (Test-Path $StageRoot) { Remove-Item -Recurse -Force $StageRoot }
New-Item -ItemType Directory -Force -Path $StageRoot | Out-Null

Copy-Item $CoreBinary (Join-Path $StageRoot "nexus.exe")
if ($DesktopBinary -and (Test-Path $DesktopBinary -PathType Leaf)) {
    Copy-Item $DesktopBinary (Join-Path $StageRoot "nexus-desktop.exe")
}

$SampleCfg = Join-Path $RepoRoot "docs/configuration/examples/paired/client.kdl"
if (Test-Path $SampleCfg) {
    Copy-Item $SampleCfg (Join-Path $StageRoot "client.example.kdl")
}
$Readme = Join-Path $RepoRoot "packaging/README.md"
if (Test-Path $Readme) {
    Copy-Item $Readme (Join-Path $StageRoot "README.md")
}

$OutFull = if ([System.IO.Path]::IsPathRooted($OutputDir)) { $OutputDir } else { Join-Path $RepoRoot $OutputDir }
New-Item -ItemType Directory -Force -Path $OutFull | Out-Null
$ZipPath = Join-Path $OutFull "$PkgName.zip"
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path "$StageRoot/*" -DestinationPath $ZipPath
$Hash = (Get-FileHash $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -Path "$ZipPath.sha256" -Value "$Hash  $PkgName.zip" -Encoding Ascii
Write-Host "Packaged $ZipPath (sha256=$Hash)"
