# Windows PowerShell Setup Script
# Voor Youssef's Secure Transfer client

Write-Host "🔐 Secure Transfer - Windows Setup" -ForegroundColor Cyan
Write-Host "====================================" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✅ Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Python not found!" -ForegroundColor Red
    Write-Host "   Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "   Make sure to check 'Add Python to PATH'" -ForegroundColor Yellow
    exit 1
}

# Check pip
Write-Host "Checking pip..." -ForegroundColor Yellow
try {
    $pipVersion = pip --version 2>&1
    Write-Host "✅ pip found: $pipVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ pip not found!" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host ""
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pip install cryptography requests

if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Dependencies installed" -ForegroundColor Green
} else {
    Write-Host "❌ Installation failed" -ForegroundColor Red
    exit 1
}

# Create tools directory
$toolsDir = "$env:USERPROFILE\Tools\secure-transfer"
Write-Host ""
Write-Host "Creating tools directory: $toolsDir" -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $toolsDir | Out-Null
Write-Host "✅ Directory created" -ForegroundColor Green

# Check if client.py exists in current directory
if (Test-Path "client.py") {
    Write-Host ""
    Write-Host "Copying client.py to tools directory..." -ForegroundColor Yellow
    Copy-Item "client.py" -Destination "$toolsDir\client.py"
    Write-Host "✅ Client copied" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "⚠️  client.py not found in current directory" -ForegroundColor Yellow
    Write-Host "   Please copy client.py to: $toolsDir" -ForegroundColor Yellow
}

# Setup PowerShell profile
Write-Host ""
Write-Host "Setting up PowerShell profile..." -ForegroundColor Yellow

$profileContent = @"

# === Secure Transfer Shortcuts ===
`$env:TRANSFER_SERVER = "http://daggertooth-daggertooth.ts.net:8080"

function tsend {
    param([string]`$file)
    python "$toolsDir\client.py" send `$file
}

function trecv {
    param(
        [string]`$code,
        [string]`$output = "."
    )
    python "$toolsDir\client.py" receive `$code --output `$output
}

# Aliases
Set-Alias transfer "$toolsDir\client.py"

Write-Host "✅ Secure Transfer loaded" -ForegroundColor Green
Write-Host "   Server: `$env:TRANSFER_SERVER" -ForegroundColor Cyan
Write-Host "   Commands: tsend, trecv" -ForegroundColor Cyan
# === End Secure Transfer ===

"@

# Check if profile exists
if (!(Test-Path $PROFILE)) {
    New-Item -ItemType File -Path $PROFILE -Force | Out-Null
}

# Read existing profile
$existingProfile = Get-Content $PROFILE -Raw -ErrorAction SilentlyContinue

# Check if already configured
if ($existingProfile -notmatch "Secure Transfer") {
    Add-Content -Path $PROFILE -Value $profileContent
    Write-Host "✅ PowerShell profile configured" -ForegroundColor Green
} else {
    Write-Host "ℹ️  PowerShell profile already configured" -ForegroundColor Cyan
}

# Check Tailscale
Write-Host ""
Write-Host "Checking Tailscale..." -ForegroundColor Yellow
if (Get-Command "tailscale" -ErrorAction SilentlyContinue) {
    $tsStatus = tailscale status 2>&1
    Write-Host "✅ Tailscale installed" -ForegroundColor Green
    Write-Host ""
    Write-Host "Tailscale Status:" -ForegroundColor Cyan
    Write-Host $tsStatus
} else {
    Write-Host "⚠️  Tailscale not installed" -ForegroundColor Yellow
    Write-Host "   Download from: https://tailscale.com/download/windows" -ForegroundColor Yellow
}

# Final instructions
Write-Host ""
Write-Host "🎉 Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Next Steps:" -ForegroundColor Cyan
Write-Host "   1. Restart PowerShell (or run: . `$PROFILE)" -ForegroundColor White
Write-Host "   2. Install Tailscale if not already: https://tailscale.com/download/windows" -ForegroundColor White
Write-Host "   3. Connect to Tailscale" -ForegroundColor White
Write-Host ""
Write-Host "🚀 Usage:" -ForegroundColor Cyan
Write-Host "   tsend C:\Users\Youssef\Documents\file.pdf" -ForegroundColor White
Write-Host "   trecv 123456" -ForegroundColor White
Write-Host "   trecv 123456 -output C:\Downloads" -ForegroundColor White
Write-Host ""
Write-Host "🌐 Server URL:" -ForegroundColor Cyan
Write-Host "   http://daggertooth-daggertooth.ts.net:8080" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to reload profile and test..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Reload profile
. $PROFILE
