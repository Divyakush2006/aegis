<#
.SYNOPSIS
    Add Prahari IDE to the Start menu, so it launches like any other application.

.DESCRIPTION
    The desktop application normally starts through `npm run start:desktop`,
    which is a developer's entry point: it needs a terminal, and the terminal
    has to stay open. This creates a shortcut to the same application that can
    be launched, searched for and pinned like any installed program.

    The shortcut runs Electron directly on the built application rather than
    going through npm, so no console window appears behind it. Its working
    directory is the application folder, which is also what lets the window
    find its icon.

    Nothing is installed, copied or written outside the shortcut itself: it
    points at the build in this repository. Moving or deleting the repository
    breaks the shortcut, and `-Remove` deletes it.

.PARAMETER Desktop
    Also place a shortcut on the Desktop.

.PARAMETER Remove
    Delete the shortcuts this script creates.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File scripts\Install-Shortcut.ps1 -Desktop

.NOTES
    Build the application first: npm run build:desktop
#>
[CmdletBinding()]
param(
    [switch] $Desktop,
    [switch] $Remove
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$name = 'Prahari IDE'
$ide = Split-Path -Parent $PSScriptRoot
$app = Join-Path $ide 'electron-app'
$electron = Join-Path $ide 'node_modules\electron\dist\electron.exe'
$icon = Join-Path $app 'resources\prahari.ico'

$targets = @(
    (Join-Path ([Environment]::GetFolderPath('Programs')) "$name.lnk")
)
if ($Desktop) {
    $targets += (Join-Path ([Environment]::GetFolderPath('Desktop')) "$name.lnk")
}

if ($Remove) {
    foreach ($target in $targets) {
        if (Test-Path $target) {
            Remove-Item $target
            Write-Host "Removed $target"
        }
    }
    return
}

# Fail with the reason rather than producing a shortcut that does nothing.
if (-not (Test-Path $electron)) {
    throw "Electron is not installed yet. Run 'npm run build:desktop' in $ide first; it downloads Electron."
}
if (-not (Test-Path (Join-Path $app 'lib\backend\electron-main.js'))) {
    throw "The desktop application is not built yet. Run 'npm run build:desktop' in $ide first."
}

$shell = New-Object -ComObject WScript.Shell
try {
    foreach ($target in $targets) {
        $shortcut = $shell.CreateShortcut($target)
        $shortcut.TargetPath = $electron
        # Electron takes the application directory; package.json names the entry point.
        $shortcut.Arguments = "`"$app`""
        $shortcut.WorkingDirectory = $app
        $shortcut.IconLocation = "$icon,0"
        $shortcut.Description = 'Prahari IDE - the security-aware C compiler and its development environment'
        $shortcut.Save()
        Write-Host "Created $target"
    }
} finally {
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($shell)
}

Write-Host ''
Write-Host "$name is now in the Start menu. Search for it, or pin it to the taskbar."
Write-Host "To remove it again: powershell -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Remove"
