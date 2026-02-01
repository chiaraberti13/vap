<# 
VULNERABILITY ASSESSMENT PLATFORM - WINDOWS INSTALLER
Provides a best-effort setup for Windows using PowerShell.
Requires PowerShell 5+ and internet access for dependency downloads.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "installer_$Timestamp.log"

function Write-Log {
    param(
        [Parameter(Mandatory=$true)][string]$Message,
        [ValidateSet("INFO","SUCCESS","WARN","ERROR")][string]$Level = "INFO"
    )
    $prefix = switch ($Level) {
        "INFO" { "[INFO]" }
        "SUCCESS" { "[+]" }
        "WARN" { "[!]" }
        "ERROR" { "[X]" }
    }
    $line = "{0} {1}" -f $prefix, $Message
    Write-Host $line
    Add-Content -Path $LogFile -Value ("[{0}] {1}" -f (Get-Date -Format "s"), $line)
}

function Handle-Error {
    param([string]$Context)
    Write-Log "Installation failed: $Context" "ERROR"
    Write-Log "Check the log file for details: $LogFile" "ERROR"
    exit 1
}

# -----------------------------------------------------------------------------
# Validation helpers
# -----------------------------------------------------------------------------
function Test-RequiredFiles {
    Write-Log "Validating required project files..."
    $requiredFiles = @(
        "app.py",
        "config.py",
        "database.py",
        "scanner_engine.py",
        "report_generator.py",
        "requirements.txt",
        "templates/index.html",
        "templates/scan_detail.html",
        "templates/scans_list.html"
    )

    $missing = @()
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path -Path $file)) {
            $missing += "$file (missing)"
        } elseif ((Get-Item -Path $file).Length -eq 0) {
            $missing += "$file (empty)"
        } else {
            Write-Log "File OK: $file" "SUCCESS"
        }
    }

    if ($missing.Count -gt 0) {
        Write-Log "Missing or incomplete files detected:" "ERROR"
        $missing | ForEach-Object { Write-Log " - $_" "ERROR" }
        throw "Required files are missing or incomplete."
    }
}

function Assert-PythonVersion {
    param([string]$PythonCommand = "python")
    Write-Log "Checking Python version..."
    $versionOutput = & $PythonCommand -c @"
import sys
min_v = (3, 10)
max_v = (3, 12)
current = sys.version_info[:3]
if current < min_v or current > max_v:
    print(
        f"Unsupported Python {current[0]}.{current[1]}.{current[2]} detected. "
        "Supported versions: 3.10 - 3.12."
    )
    raise SystemExit(1)
print(f"Python {current[0]}.{current[1]}.{current[2]} detected (OK).")
"@

    if ($LASTEXITCODE -ne 0) {
        throw $versionOutput
    }

    Write-Log $versionOutput "SUCCESS"
}

# -----------------------------------------------------------------------------
# Dependency installers (best effort)
# -----------------------------------------------------------------------------
function Install-WithWinget {
    param([string]$Id, [string]$Name)
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        Write-Log "Installing $Name via winget..."
        winget install --id $Id --silent --accept-source-agreements --accept-package-agreements
        Write-Log "$Name installed" "SUCCESS"
    } else {
        Write-Log "winget not found. Please install $Name manually." "WARN"
    }
}

function Ensure-Command {
    param([string]$Command, [string]$Name, [string]$WingetId)
    if (-not (Get-Command $Command -ErrorAction SilentlyContinue)) {
        Write-Log "$Name not found." "WARN"
        if ($WingetId) {
            Install-WithWinget -Id $WingetId -Name $Name
        }
    } else {
        Write-Log "$Name already available." "SUCCESS"
    }
}

# -----------------------------------------------------------------------------
# Main execution
# -----------------------------------------------------------------------------
try {
    Write-Log "Starting Windows installation..."

    Test-RequiredFiles

    # Ensure core tools
    Ensure-Command -Command "python" -Name "Python 3" -WingetId "Python.Python.3.11"
    Ensure-Command -Command "git" -Name "Git" -WingetId "Git.Git"
    Ensure-Command -Command "go" -Name "Go" -WingetId "GoLang.Go"

    Assert-PythonVersion -PythonCommand "python"

    # Optional security tools
    Ensure-Command -Command "nmap" -Name "Nmap" -WingetId "Insecure.Nmap"
    Ensure-Command -Command "nikto" -Name "Nikto" -WingetId ""
    Ensure-Command -Command "whatweb" -Name "WhatWeb" -WingetId ""

    # Configure Go environment for Go-installed tools
    if (-not $env:GOPATH) {
        $env:GOPATH = Join-Path $HOME "go"
        $env:Path = "$env:Path;$env:GOPATH\bin"
        Write-Log "Configured GOPATH at $env:GOPATH" "SUCCESS"
    }

    # Install Go-based tools (best effort)
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Log "Installing Go-based security tools..."
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install github.com/tomnomnom/assetfinder@latest
        Write-Log "Go-based tools installed" "SUCCESS"
    } else {
        Write-Log "Go not available. Skipping Go-based tools." "WARN"
    }

    # Create virtual environment
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        throw "Python is required but was not found after installation attempts."
    }

    Write-Log "Creating Python virtual environment..."
    python -m venv venv
    $venvPython = Join-Path $PWD "venv\Scripts\python.exe"

    Write-Log "Upgrading pip..."
    & $venvPython -m pip install --upgrade pip setuptools wheel

    Write-Log "Installing Python dependencies..."
    & $venvPython -m pip install -r requirements.txt

    Write-Log "Initializing database..."
    & $venvPython -c "from database import init_db; init_db()"

    Write-Log "Installation completed successfully!" "SUCCESS"
    Write-Log "Activate the environment with: .\venv\Scripts\Activate.ps1" "INFO"
    Write-Log "Start the server with: python app.py" "INFO"
} catch {
    Handle-Error $_.Exception.Message
}
