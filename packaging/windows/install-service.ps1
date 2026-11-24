<#
.SYNOPSIS
Installs, uninstalls, or queries the Nexus Windows Service (SCM).
#>
param(
    [Parameter(Position = 0)]
    [ValidateSet("install", "uninstall", "status")]
    [string]$Action = "install",
    [string]$Name = "nexus",
    [string]$BinaryPath = (Join-Path $PSScriptRoot "nexus.exe"),
    [string]$ConfigPath = (Join-Path $PSScriptRoot "config.kdl")
)

$ErrorActionPreference = "Stop"

switch ($Action) {
    "install" {
        if (-not (Test-Path $BinaryPath -PathType Leaf)) { throw "nexus.exe not found: $BinaryPath" }
        if (-not (Test-Path $ConfigPath -PathType Leaf)) { throw "config.kdl not found: $ConfigPath" }
        & $BinaryPath service install --name $Name --binary $BinaryPath --config $ConfigPath
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        & $BinaryPath service start --name $Name
        exit $LASTEXITCODE
    }
    "uninstall" {
        if (Test-Path $BinaryPath -PathType Leaf) {
            & $BinaryPath service stop --name $Name 2>$null
            & $BinaryPath service uninstall --name $Name
            exit $LASTEXITCODE
        } else {
            sc.exe delete $Name
            exit $LASTEXITCODE
        }
    }
    "status" {
        Get-Service -Name $Name -ErrorAction SilentlyContinue | Format-Table -AutoSize
    }
}
