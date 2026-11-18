<#
.SYNOPSIS
  Install ThreatDesk on this Windows machine (single user, localhost only).

.DESCRIPTION
  Run from the root of a ThreatDesk checkout (or the extracted GitHub zip):

      .\install.cmd -Demo                 # typical demo machine
      .\install.cmd -Demo -InstallPrereqs # also winget-install missing Python / jq / Node + Claude Code

  Steps: checks Python 3.11+, creates .venv and installs ThreatDesk into it,
  checks the prebuilt UI (web-dist/), checks the Claude Code CLI and jq,
  creates .env, writes Start-ThreatDesk.cmd plus a desktop shortcut, then
  starts ThreatDesk and opens the browser.

  Re-running is safe; it updates the install in place (use after git pull).

.PARAMETER Demo
  Point the inventory at the bundled synthetic Fortune-50 sample
  (samples/meridian-global.csv) so the Vulns tab is populated immediately.

.PARAMETER InstallPrereqs
  Use winget (and npm) to install anything missing: Python 3.12, jq,
  Node LTS, Claude Code CLI. Without it, missing items are reported with
  the command to run.

.PARAMETER Port
  Port to serve on (default 8444).

.PARAMETER NoLaunch
  Install only; don't start ThreatDesk at the end.

.PARAMETER NoShortcut
  Don't create the desktop shortcut.
#>
[CmdletBinding()]
param(
    [switch]$Demo,
    [switch]$InstallPrereqs,
    [int]$Port = 8444,
    [switch]$NoLaunch,
    [switch]$NoShortcut
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
Set-Location $Root

function Write-Step([string]$msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "    ok  $msg" -ForegroundColor Green }
function Write-Warn2([string]$msg) { Write-Host "    !!  $msg" -ForegroundColor Yellow }
function Stop-Install([string]$msg) { Write-Host "`nInstall stopped: $msg" -ForegroundColor Red; exit 1 }

function Update-SessionPath {
    $machine = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $user = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machine;$user"
}

function Test-Winget { return [bool](Get-Command winget -ErrorAction SilentlyContinue) }

function Install-WithWinget([string]$id, [string]$label) {
    if (-not (Test-Winget)) { Stop-Install "winget is not available; install $label manually." }
    Write-Host "    installing $label via winget ($id)..."
    winget install --id $id -e --accept-package-agreements --accept-source-agreements --silent | Out-Host
    Update-SessionPath
}

# ── 1. Python 3.11+ ──────────────────────────────────────────────────
Write-Step 'Python 3.11+'
function Find-Python {
    $candidates = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        foreach ($v in @('3.13', '3.12', '3.11')) { $candidates += , @('py', "-$v") }
    }
    if (Get-Command python -ErrorAction SilentlyContinue) { $candidates += , @('python') }
    foreach ($c in $candidates) {
        try {
            $exe = $c[0]; $pre = @(); if ($c.Count -gt 1) { $pre = $c[1..($c.Count - 1)] }
            $ver = & $exe @pre -c "import sys; print('%d.%d' % sys.version_info[:2])" 2>$null
            if ($LASTEXITCODE -eq 0 -and $ver) {
                $parts = $ver.Trim().Split('.')
                if ([int]$parts[0] -eq 3 -and [int]$parts[1] -ge 11) {
                    $path = & $exe @pre -c "import sys; print(sys.executable)"
                    return $path.Trim()
                }
            }
        } catch { }
    }
    return $null
}
$py = Find-Python
if (-not $py) {
    if ($InstallPrereqs) { Install-WithWinget 'Python.Python.3.12' 'Python 3.12'; $py = Find-Python }
    if (-not $py) { Stop-Install 'Python 3.11+ not found. Install it (winget install Python.Python.3.12) or re-run with -InstallPrereqs.' }
}
Write-Ok $py

# ── 2. Virtual environment + package ─────────────────────────────────
Write-Step 'Python environment (.venv)'
$venvPy = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $venvPy)) {
    & $py -m venv (Join-Path $Root '.venv')
    if ($LASTEXITCODE -ne 0) { Stop-Install 'could not create .venv' }
}
& $venvPy -m pip install --quiet --disable-pip-version-check --upgrade pip
& $venvPy -m pip install --quiet --disable-pip-version-check -e $Root
if ($LASTEXITCODE -ne 0) { Stop-Install 'pip install failed (see output above). Behind a proxy? Set HTTPS_PROXY and re-run.' }
Write-Ok 'threatdesk installed into .venv'

# ── 3. UI bundle ─────────────────────────────────────────────────────
Write-Step 'Web UI'
if (Test-Path (Join-Path $Root 'web-dist\index.html')) {
    Write-Ok 'prebuilt UI present (web-dist/)'
} elseif (Get-Command npm -ErrorAction SilentlyContinue) {
    Push-Location (Join-Path $Root 'web')
    npm install --no-audit --no-fund | Out-Host
    npm run build | Out-Host
    Pop-Location
    if (-not (Test-Path (Join-Path $Root 'web-dist\index.html'))) { Stop-Install 'UI build failed' }
    Write-Ok 'UI built'
} else {
    Stop-Install 'web-dist/ is missing and Node is not installed. Use a full checkout (web-dist is committed) or install Node.'
}

# ── 4. Agent prerequisites: Claude Code CLI, jq ──────────────────────
Write-Step 'Claude Code CLI (runs the triage agent)'
function Find-Claude {
    $c = Get-Command claude -ErrorAction SilentlyContinue
    if ($c) { return $c.Source }
    foreach ($p in @("$env:APPDATA\npm\claude.cmd", "$env:USERPROFILE\.local\bin\claude.exe")) {
        if (Test-Path $p) { return $p }
    }
    return $null
}
$claude = Find-Claude
if (-not $claude -and $InstallPrereqs) {
    if (-not (Get-Command npm -ErrorAction SilentlyContinue)) { Install-WithWinget 'OpenJS.NodeJS.LTS' 'Node.js LTS' }
    Write-Host '    installing Claude Code CLI (npm i -g @anthropic-ai/claude-code)...'
    npm install -g @anthropic-ai/claude-code | Out-Host
    Update-SessionPath
    $claude = Find-Claude
}
$claudeOk = [bool]$claude
if ($claudeOk) {
    Write-Ok $claude
} else {
    Write-Warn2 'Claude Code CLI not found. Vulns, Intel and the threat feed work without it; Triage needs it.'
    Write-Warn2 'Install: npm i -g @anthropic-ai/claude-code   (or re-run with -InstallPrereqs)'
}

Write-Step 'jq (used by the triage agent)'
if (-not (Get-Command jq -ErrorAction SilentlyContinue)) {
    if ($InstallPrereqs) { Install-WithWinget 'jqlang.jq' 'jq' }
}
if (Get-Command jq -ErrorAction SilentlyContinue) { Write-Ok (Get-Command jq).Source }
else { Write-Warn2 'jq not found. Install: winget install jqlang.jq   (or re-run with -InstallPrereqs)' }
if (Get-Command curl.exe -ErrorAction SilentlyContinue) { Write-Ok 'curl present' }
else { Write-Warn2 'curl.exe not found (ships with Windows 10 1803+).' }

# ── 5. Configuration (.env) ──────────────────────────────────────────
Write-Step 'Configuration (.env)'
$envPath = Join-Path $Root '.env'
if (-not (Test-Path $envPath)) {
    Copy-Item (Join-Path $Root '.env.example') $envPath
    Write-Ok 'created .env from .env.example'
} else {
    Write-Ok '.env already exists (left as is)'
}
$envText = Get-Content $envPath -Raw
$envText = [regex]::Replace($envText, '(?m)^THREATDESK_PORT=.*$', "THREATDESK_PORT=$Port")
if ($Demo) {
    $envText = [regex]::Replace($envText, '(?m)^THREATDESK_TECH_STACK_CSV=.*$', 'THREATDESK_TECH_STACK_CSV=samples/meridian-global.csv')
    Write-Ok 'demo inventory: samples/meridian-global.csv (285 products, fictional "Meridian Global")'
}
[IO.File]::WriteAllText($envPath, $envText, (New-Object Text.UTF8Encoding($false)))

# ── 6. Launcher + shortcut ───────────────────────────────────────────
Write-Step 'Launcher'
$launcher = Join-Path $Root 'Start-ThreatDesk.cmd'
$cmd = "@echo off`r`ncd /d `"%~dp0`"`r`n`".venv\Scripts\python.exe`" -m threatdesk.serve --port $Port --open`r`n"
[IO.File]::WriteAllText($launcher, $cmd, (New-Object Text.ASCIIEncoding))
Write-Ok $launcher
if (-not $NoShortcut) {
    try {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $ws = New-Object -ComObject WScript.Shell
        $lnk = $ws.CreateShortcut((Join-Path $desktop 'ThreatDesk.lnk'))
        $lnk.TargetPath = $launcher
        $lnk.WorkingDirectory = $Root
        $lnk.Description = 'ThreatDesk: threat triage + vulnerability dashboard'
        $lnk.Save()
        Write-Ok 'desktop shortcut: ThreatDesk'
    } catch { Write-Warn2 "could not create the desktop shortcut: $($_.Exception.Message)" }
}

# ── 7. Smoke check ───────────────────────────────────────────────────
Write-Step 'Self-check'
& $venvPy -c "import api.main, threatdesk.inventory as i; print('    ok  API imports; inventory assets:', len(i.load_assets()))"
if ($LASTEXITCODE -ne 0) { Stop-Install 'ThreatDesk failed to import (see the traceback above).' }

Write-Host ''
Write-Host 'ThreatDesk is installed.' -ForegroundColor Green
Write-Host "  Start:   Start-ThreatDesk.cmd  (or the ThreatDesk desktop shortcut)  ->  http://127.0.0.1:$Port"
if ($claudeOk) {
    Write-Host '  Triage:  sign the agent in once: run  claude  in a terminal and log in,'
    Write-Host '           or add an Anthropic API key in Settings -> AI providers.'
}
Write-Host '  Inventory: Settings -> Technology inventory -> Upload tech-stack CSV (template there).'

if (-not $NoLaunch) {
    Write-Host "`nStarting ThreatDesk (Ctrl+C to stop)..."
    & $launcher
}
