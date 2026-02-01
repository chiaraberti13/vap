#!/bin/bash

##############################################################################
# VULNERABILITY ASSESSMENT PLATFORM - AUTO INSTALLER
# Cross-platform installer for Linux (Ubuntu/Debian), macOS, and Windows.
# Author: DevSecOps Team
# Version: 2.0
##############################################################################

set -Eeuo pipefail  # Fail fast, catch errors in pipelines, and treat unset vars as errors.
IFS=$'\n\t'

# Ensure the installer runs from the repository root.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Output colors (ANSI). Use tput if available for better compatibility.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ASCII logo for the installer UI.
print_logo() {
    echo -e "${BLUE}"
    cat << "EOF"
╦  ╦┬ ┬┬  ┌┐┌  ╔═╗┌─┐┌─┐┌─┐┌─┐┌─┐┌┬┐┌─┐┌┐┌┌┬┐
╚╗╔╝│ ││  │││  ╠═╣└─┐└─┐├┤ └─┐└─┐│││├┤ │││ │ 
 ╚╝ └─┘┴─┘┘└┘  ╩ ╩└─┘└─┘└─┘└─┘└─┘┴ ┴└─┘┘└┘ ┴ 
    Professional Security Scanner Platform
EOF
    echo -e "${NC}"
}

# Logging helpers with consistent prefixes.
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Path for installer logs to support error analysis.
LOG_FILE="installer_$(date +%Y%m%d_%H%M%S).log"

# Log to file as well to make troubleshooting easier.
log_to_file() {
    echo "[$(date +%Y-%m-%dT%H:%M:%S%z)] $1" >> "$LOG_FILE"
}

# Ensure ~/.local/bin is in PATH and persisted for future shells.
ensure_local_bin_path() {
    if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
        export PATH="$HOME/.local/bin:$PATH"
        if [ -f "$HOME/.bashrc" ]; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        fi
        if [ -f "$HOME/.zshrc" ]; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc"
        fi
    fi
}

# Check if script is run as root to avoid permission mistakes.
check_root() {
    if [ "$EUID" -eq 0 ]; then 
        log_warning "Do not run this script as root. We will use sudo when needed."
        exit 1
    fi
}

# Detect OS and distribution to drive dependency installation.
detect_platform() {
    log_info "Detecting operating system..."

    OS_NAME="$(uname -s)"
    case "$OS_NAME" in
        Linux*)
            PLATFORM="linux"
            if [ -f /etc/os-release ]; then
                . /etc/os-release
                DISTRO="${ID:-unknown}"
                VERSION="${VERSION_ID:-unknown}"
                log_success "Detected Linux distribution: ${NAME:-$DISTRO} ${VERSION}"
            else
                log_error "Unable to detect Linux distribution (/etc/os-release missing)."
                exit 1
            fi
            ;;
        Darwin*)
            PLATFORM="macos"
            log_success "Detected macOS."
            ;;
        CYGWIN*|MINGW*|MSYS*)
            PLATFORM="windows"
            log_success "Detected Windows (Git Bash/Cygwin/MSYS)."
            ;;
        *)
            log_error "Unsupported OS: $OS_NAME"
            exit 1
            ;;
    esac
}

# Validate required project files and detect incomplete/empty files early.
check_required_files() {
    log_info "Validating required project files..."
    local required_files=(
        "app.py"
        "config.py"
        "database.py"
        "scanner_engine.py"
        "report_generator.py"
        "requirements.txt"
        "templates/index.html"
        "templates/scan_detail.html"
        "templates/scans_list.html"
    )

    local missing=0
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            log_error "Missing required file: $file"
            log_to_file "Missing required file: $file"
            ((missing++))
        elif [ ! -s "$file" ]; then
            log_error "Incomplete file detected (empty): $file"
            log_to_file "Incomplete file detected (empty): $file"
            ((missing++))
        else
            log_success "File OK: $file"
        fi
    done

    if [ "$missing" -ne 0 ]; then
        log_error "One or more required files are missing or incomplete."
        log_error "Restore the project files and re-run the installer."
        exit 1
    fi
}

# Install system dependencies based on platform.
install_system_dependencies() {
    log_info "Installing system dependencies..."

    case "$PLATFORM" in
        linux)
            case "$DISTRO" in
                ubuntu|debian|kali)
                    log_info "Updating apt repositories..."
                    sudo apt-get update -qq

                    log_info "Installing base packages..."
                    sudo apt-get install -y \
                        python3 \
                        python3-pip \
                        python3-venv \
                        git \
                        wget \
                        curl \
                        nmap \
                        nikto \
                        golang-go \
                        build-essential \
                        libssl-dev \
                        libffi-dev \
                        python3-dev \
                        sqlite3 \
                        libsqlite3-dev \
                        wkhtmltopdf \
                        xvfb \
                        fonts-liberation
                    ;;
                *)
                    log_error "Unsupported Linux distribution: $DISTRO"
                    log_warning "Manual installation is required for this distro."
                    exit 1
                    ;;
            esac
            ;;
        macos)
            if ! command -v brew &> /dev/null; then
                log_error "Homebrew is required but not installed."
                log_error "Install Homebrew from https://brew.sh and re-run the installer."
                exit 1
            fi

            log_info "Installing packages with Homebrew..."
            brew update
            brew install \
                python \
                git \
                wget \
                curl \
                nmap \
                nikto \
                go \
                sqlite

            if brew info --cask wkhtmltopdf &> /dev/null; then
                log_info "Installing wkhtmltopdf (cask)..."
                brew install --cask wkhtmltopdf
            else
                log_warning "wkhtmltopdf not available via Homebrew. Skipping installation."
                log_warning "Install wkhtmltopdf manually if you need HTML-to-PDF features."
            fi
            ;;
        windows)
            log_warning "Windows detected. System dependencies must be installed manually."
            log_warning "Use PowerShell and run installer.ps1 for automated setup."
            ;;
        *)
            log_error "Unsupported platform: $PLATFORM"
            exit 1
            ;;
    esac

    log_success "System dependencies installation completed"
}

# Configure Go environment variables and persist them for future shells.
setup_go_environment() {
    log_info "Configuring Go environment..."

    # Ensure Go is installed and available in PATH.
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed or not available in PATH."
        exit 1
    fi

    # Configure GOPATH if missing.
    if [ -z "${GOPATH:-}" ]; then
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin

        # Persist environment for future shells.
        if [ -f "$HOME/.bashrc" ]; then
            echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
            echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"
        fi
        if [ -f "$HOME/.zshrc" ]; then
            echo 'export GOPATH=$HOME/go' >> "$HOME/.zshrc"
            echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.zshrc"
        fi
    fi
    
    log_success "Go environment configured"
}

# Install external security tools used by the scanners.
install_security_tools() {
    log_info "Installing external security tools..."

    # Create a dedicated directory to keep third-party tools together.
    mkdir -p ~/security-tools
    cd ~/security-tools

    # Install Nuclei via Go if missing.
    log_info "Installing Nuclei..."
    if ! command -v nuclei &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        log_success "Nuclei installed"
    else
        log_success "Nuclei already installed"
    fi

    # Update Nuclei templates (best-effort).
    log_info "Updating Nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null || true

    # Install Subfinder.
    log_info "Installing Subfinder..."
    if ! command -v subfinder &> /dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        log_success "Subfinder installed"
    else
        log_success "Subfinder already installed"
    fi

    # Install Assetfinder.
    log_info "Installing Assetfinder..."
    if ! command -v assetfinder &> /dev/null; then
        go install github.com/tomnomnom/assetfinder@latest
        log_success "Assetfinder installed"
    else
        log_success "Assetfinder already installed"
    fi

    # Install WhatWeb when missing.
    log_info "Checking WhatWeb..."
    if ! command -v whatweb &> /dev/null; then
        local whatweb_dir="$HOME/security-tools/WhatWeb"
        log_info "Installing WhatWeb from GitHub..."

        if [ -d "$whatweb_dir" ]; then
            log_warning "WhatWeb directory already exists. Trying to update it..."
            if git -C "$whatweb_dir" rev-parse --is-inside-work-tree &> /dev/null; then
                git -C "$whatweb_dir" fetch --all --prune || log_warning "WhatWeb update failed. Using existing files."
            else
                log_warning "Existing WhatWeb directory is not a git repo. Skipping update."
            fi
        else
            if ! git clone https://github.com/urbanadventurer/WhatWeb.git "$whatweb_dir"; then
                log_warning "WhatWeb clone failed. Skipping installation."
            else
                log_success "WhatWeb repository cloned"
            fi
        fi

        if [ -d "$whatweb_dir" ]; then
            cd "$whatweb_dir"
            ensure_local_bin_path
            if make install PREFIX="$HOME/.local"; then
                log_success "WhatWeb installed to ~/.local"
            else
                log_warning "WhatWeb make install failed. Falling back to local wrapper."
                mkdir -p "$HOME/.local/bin"
                cat << 'EOF' > "$HOME/.local/bin/whatweb"
#!/bin/bash
WHATWEB_HOME="$HOME/security-tools/WhatWeb"
exec "$WHATWEB_HOME/whatweb" "$@"
EOF
                chmod +x "$HOME/.local/bin/whatweb"
                log_success "WhatWeb wrapper installed to ~/.local/bin"
            fi
            cd ..
        else
            log_warning "WhatWeb directory not available. Continuing without WhatWeb."
        fi
    else
        log_success "WhatWeb already installed"
    fi

    # Install Dirsearch for content discovery.
    log_info "Installing Dirsearch..."
    if [ ! -d "$HOME/security-tools/dirsearch" ]; then
        git clone https://github.com/maurosoria/dirsearch.git
        cd dirsearch
        pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
        cd ..
        log_success "Dirsearch installed"
    else
        log_success "Dirsearch already installed"
    fi

    cd - > /dev/null
    log_success "Security tools installed successfully"
}

# Create and activate the Python virtual environment.
create_python_venv() {
    log_info "Creating Python virtual environment..."

    # Remove old venv to ensure a clean state.
    if [ -d "venv" ]; then
        log_warning "Removing existing virtual environment..."
        rm -rf venv
    fi

    # Create venv using python3.
    python3 -m venv venv
    log_success "Virtual environment created"

    # Activate venv for dependency installation.
    source venv/bin/activate

    # Upgrade pip tooling for a clean install.
    log_info "Upgrading pip..."
    pip install --upgrade pip setuptools wheel

    log_success "Virtual environment configured"
}

# Install Python dependencies from requirements.txt.
install_python_dependencies() {
    log_info "Installing Python dependencies..."

    # Ensure venv is active.
    source venv/bin/activate

    # Resolve requirements path from the repository root.
    local requirements_file="${SCRIPT_DIR}/requirements.txt"

    # Install dependencies.
    if [ -f "$requirements_file" ]; then
        pip install -r "$requirements_file"
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found at: $requirements_file"
        log_error "Current working directory: $(pwd)"
        log_error "Ensure you run the installer from the repository root."
        exit 1
    fi
}

# Create the directory structure used by the application.
create_directory_structure() {
    log_info "Creating directory structure..."

    mkdir -p reports logs scans static/css static/js templates scanners

    # Ensure scanners package is importable.
    touch scanners/__init__.py

    log_success "Directory structure created"
}

# Initialize the database schema.
initialize_database() {
    log_info "Initializing database..."

    source venv/bin/activate
    python3 -c "from database import init_db; init_db()"

    log_success "Database initialized"
}

# Set safe permissions for runtime directories and scripts.
set_permissions() {
    log_info "Setting permissions..."

    chmod +x app.py
    chmod 755 reports logs scans

    log_success "Permissions configured"
}

# Verify installation completeness and report missing dependencies.
verify_installation() {
    log_info "Verifying installation..."

    local errors=0

    # Validate external tools.
    commands=("nmap" "nikto" "nuclei" "subfinder" "assetfinder" "whatweb")
    for cmd in "${commands[@]}"; do
        if command -v $cmd &> /dev/null; then
            log_success "$cmd: OK"
        else
            log_error "$cmd: NOT FOUND"
            ((errors++))
        fi
    done

    # Validate core Python packages.
    source venv/bin/activate
    python3 << EOF
import sys
packages = ['fastapi', 'uvicorn', 'reportlab', 'sqlalchemy', 'aiohttp']
errors = 0
for pkg in packages:
    try:
        __import__(pkg)
        print(f"✓ {pkg}: OK")
    except ImportError:
        print(f"✗ {pkg}: NOT FOUND")
        errors += 1
sys.exit(errors)
EOF

    if [ $? -ne 0 ]; then
        ((errors++))
    fi

    if [ $errors -eq 0 ]; then
        log_success "Verification completed successfully!"
        return 0
    else
        log_error "Verification failed with $errors error(s)"
        return 1
    fi
}

# Print final instructions for the user.
print_final_instructions() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                  INSTALLATION COMPLETE!                    ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}📋 NEXT STEPS:${NC}"
    echo ""
    echo -e "1️⃣  Activate the virtual environment:"
    echo -e "   ${YELLOW}source venv/bin/activate${NC}"
    echo ""
    echo -e "2️⃣  Start the server:"
    echo -e "   ${YELLOW}python3 app.py${NC}"
    echo ""
    echo -e "3️⃣  Open your browser at:"
    echo -e "   ${YELLOW}http://localhost:8000${NC}"
    echo ""
    echo -e "${BLUE}📚 USEFUL COMMANDS:${NC}"
    echo -e "   • Start with verbose logs: ${YELLOW}python3 app.py --debug${NC}"
    echo -e "   • Run a CLI scan: ${YELLOW}python3 scanner_engine.py --target <URL>${NC}"
    echo ""
    echo -e "${RED}⚠️  DISCLAIMER:${NC}"
    echo -e "   This tool is intended ONLY for authorized testing."
    echo -e "   Unauthorized usage may violate local and international laws."
    echo ""
}

# Error analysis handler with context-rich logs.
on_error() {
    local exit_code=$?
    local line_number=$1
    local command=$2
    log_error "Installation failed (exit code: ${exit_code})."
    log_error "Command: ${command}"
    log_error "Line: ${line_number}"
    log_error "Check the log file for details: ${LOG_FILE}"
    log_to_file "ERROR: exit_code=${exit_code} line=${line_number} command=${command}"
    exit "$exit_code"
}

trap 'on_error ${LINENO} "$BASH_COMMAND"' ERR

# Main execution flow.
main() {
    clear
    print_logo

    log_info "Starting Vulnerability Assessment Platform installation..."
    echo ""

    check_required_files
    check_root
    detect_platform
    install_system_dependencies

    if [ "$PLATFORM" != "windows" ]; then
        setup_go_environment
        install_security_tools
        create_directory_structure
        create_python_venv
        install_python_dependencies
        initialize_database
        set_permissions
    else
        log_warning "Skipping Unix-specific steps. Use installer.ps1 on Windows."
    fi

    echo ""
    if [ "$PLATFORM" = "windows" ]; then
        log_warning "Verification skipped on Windows. Use installer.ps1 for validation."
        log_info "Windows setup guide: powershell -ExecutionPolicy Bypass -File installer.ps1"
        exit 0
    fi

    if verify_installation; then
        print_final_instructions
    else
        log_error "Installation completed with errors. Review the messages above."
        exit 1
    fi
}

# Run the installer.
main "$@"
