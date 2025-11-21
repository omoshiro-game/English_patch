#!/usr/bin/env pwsh
# Requires: PowerShell 5+ and internet access
$ErrorActionPreference = 'Stop'

# --- Config ---
$PyVer      = '3.8.10'
$Arch       = 'win32'  # 'amd64' for 64-bit
$BaseUrl    = "https://www.python.org/ftp/python/$PyVer"
$ZipName    = "python-$PyVer-embed-$Arch.zip"
$ZipUrl     = "$BaseUrl/$ZipName"

$Root       = (Get-Location).Path
$PyDir      = Join-Path $Root 'python'
$PythonExe  = Join-Path $PyDir 'python.exe'
$GetPipUrl  = 'https://bootstrap.pypa.io/pip/3.8/get-pip.py'
$GetPip     = Join-Path $PyDir 'get-pip.py'

# Your sources
$AgentUrlPrimary   = 'https://raw.githubusercontent.com/omoshiro-game/English_patch/refs/heads/main/editor4/agent.js'
$AgentUrlFallback  = 'https://raw.githubusercontent.com/omoshiro-game/English_patch/main/editor4/agent.js'
$MainUrlPrimary    = 'https://raw.githubusercontent.com/omoshiro-game/English_patch/refs/heads/main/editor4/main.py'
$MainUrlFallback   = 'https://raw.githubusercontent.com/omoshiro-game/English_patch/main/editor4/main.py'

$AgentLocal = Join-Path $Root 'agent.js'
$MainLocal  = Join-Path $Root 'main.py'

$ForceReinstall = $false

# --- Detect existing Python ---
$NeedPythonSetup = $true
if (-not $ForceReinstall -and (Test-Path $PythonExe)) {
    try {
        # Capture stdout AND stderr (python -V writes to stderr!)
        $pyVersionOutput = & $PythonExe -V 2>&1 | Out-String
        if ($pyVersionOutput -match 'Python\s+3\.8\.10') {
            Write-Host "==> Existing Python found: $pyVersionOutput (reusing)" -ForegroundColor Green
            $NeedPythonSetup = $false
        } else {
            Write-Host "==> Existing Python version is '$pyVersionOutput', expected 3.8.10 – will reinstall." -ForegroundColor Yellow
        }
    } catch {
        Write-Warning "Failed to query existing Python version: $_ – will reinstall."
    }
}

if ($NeedPythonSetup) {
    Write-Host "==> Creating portable Python in $PyDir"

    # --- Prep dirs ---
    if (Test-Path $PyDir) {
        Write-Host "==> Removing existing $PyDir"
        Remove-Item -Recurse -Force $PyDir
    }
    New-Item -Type Directory -Force -Path $PyDir | Out-Null

    # --- Download embeddable ZIP ---
    $zipPath = Join-Path $Root $ZipName
    if (-not (Test-Path $zipPath)) {
        Write-Host "==> Downloading $ZipUrl"
        Invoke-WebRequest -Uri $ZipUrl -OutFile $zipPath
    } else {
        Write-Host "==> Using existing $zipPath"
    }

    # --- Extract ZIP ---
    Write-Host "==> Extracting $ZipName"
    Expand-Archive -Path $zipPath -DestinationPath $PyDir -Force

    # --- Ensure Lib and site-packages exist ---
    $LibDir = Join-Path $PyDir 'Lib'
    $SitePk = Join-Path $LibDir 'site-packages'
    New-Item -Type Directory -Force -Path $LibDir, $SitePk | Out-Null

    # --- Enable site + add search paths in python38._pth ---
    $pth = Get-ChildItem -Path $PyDir -Filter 'python38._pth' | Select-Object -First 1
    if (-not $pth) {
        throw "Could not find python38._pth in $PyDir"
    }
    $pthPath = $pth.FullName

    $pthLines = @()
    if (Test-Path $pthPath) {
        $pthLines = Get-Content -Path $pthPath -Encoding UTF8
    }

    $need = @(
        'python38.zip',
        '.\Lib',
        '.\Lib\site-packages',
        'import site'
    )

    foreach ($line in $need) {
        if ($pthLines -notcontains $line) {
            Add-Content -Path $pthPath -Encoding UTF8 -Value $line
        }
    }
    Write-Host "==> Patched $(Split-Path -Leaf $pthPath) for site + paths" -ForegroundColor Green

    # --- Bootstrap pip (3.8-compatible script) ---
    Write-Host "==> Downloading get-pip.py for Python 3.8"
    Invoke-WebRequest -Uri $GetPipUrl -OutFile $GetPip

    Write-Host "==> Installing pip with embedded Python"
    & $PythonExe $GetPip
} else {
    Write-Host "==> Skipping Python creation; using existing portable Python in $PyDir"
}


# --- Upgrade pip (optional but recommended) ---
Write-Host "==> Upgrading pip"
& $PythonExe -m pip install --upgrade pip

# --- Install Frida + tools into local site-packages ---
Write-Host "==> Installing frida and frida-tools"
& $PythonExe -m pip install --no-warn-script-location frida frida-tools

# --- Fetch agent.js and main.py (always do, to ensure latest) ---
function Download-With-Fallback($primary, $fallback, $dest) {
    try {
        Write-Verbose "Trying primary: $primary"
        Invoke-WebRequest -Uri $primary -OutFile $dest -UseBasicParsing
        Write-Host "✓ Downloaded from primary source"
    } catch {
        Write-Warning "Primary failed for $dest, trying fallback..."
        try {
            Invoke-WebRequest -Uri $fallback -OutFile $dest -UseBasicParsing
            Write-Host "✓ Downloaded from fallback source"
        } catch {
            throw "Failed to download $dest from both sources: $_"
        }
    }
}

Write-Host "==> Downloading agent.js"
Download-With-Fallback $AgentUrlPrimary $AgentUrlFallback $AgentLocal

Write-Host "==> Downloading main.py"
Download-With-Fallback $MainUrlPrimary $MainUrlFallback $MainLocal

# --- Create run.bat (uses embedded Python) ---
$RunBat = @"
@echo off
pushd "%~dp0"
python\python.exe "%~dp0\main.py"
popd
"@
Set-Content -Path (Join-Path $Root 'run.bat') -Value $RunBat -Encoding ASCII

# --- Create recovery-run.bat (uses frida CLI directly) ---
$RecoveryBat = @"
@echo off
pushd "%~dp0"
python\Scripts\frida.exe -f Editor_v1020.exe -l agent.js
popd
"@
Set-Content -Path (Join-Path $Root 'recovery-run.bat') -Value $RecoveryBat -Encoding ASCII

Write-Host ""
Write-Host "==> Done."
Write-Host "Portable Python dir: $PyDir"
Write-Host "Run normally:   .\run.bat"
Write-Host "Recovery mode:  .\recovery-run.bat  (uses frida.exe CLI)"
Write-Host ""
Write-Host "Need help? Join our Discord: https://discord.gg/ZQtYrzXPZ6"
