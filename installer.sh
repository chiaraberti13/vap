#!/bin/bash

##############################################################################
# VULNERABILITY ASSESSMENT PLATFORM - AUTO INSTALLER
# Script di installazione automatico per distribuzioni Linux
# Autore: DevSecOps Team
# Versione: 1.0
##############################################################################

set -e  # Exit on error

# Colori per output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logo ASCII
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

# Funzione di logging
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

# Verifica se lo script è eseguito come root
check_root() {
    if [ "$EUID" -eq 0 ]; then 
        log_warning "Non eseguire questo script come root. Useremo sudo quando necessario."
        exit 1
    fi
}

# Rileva la distribuzione Linux
detect_distro() {
    log_info "Rilevamento distribuzione Linux in corso..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        log_success "Distribuzione rilevata: $NAME $VERSION"
    else
        log_error "Impossibile rilevare la distribuzione Linux"
        exit 1
    fi
}

# Installa dipendenze di sistema in base alla distribuzione
install_system_dependencies() {
    log_info "Installazione dipendenze di sistema..."
    
    case $DISTRO in
        ubuntu|debian|kali)
            log_info "Aggiornamento repository apt..."
            sudo apt-get update -qq
            
            log_info "Installazione pacchetti base..."
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
            
        arch|manjaro)
            log_info "Installazione pacchetti con pacman..."
            sudo pacman -Syu --noconfirm
            sudo pacman -S --noconfirm \
                python \
                python-pip \
                git \
                wget \
                curl \
                nmap \
                nikto \
                go \
                base-devel \
                openssl \
                sqlite \
                wkhtmltopdf
            ;;
            
        fedora|rhel|centos)
            log_info "Installazione pacchetti con dnf/yum..."
            sudo dnf install -y \
                python3 \
                python3-pip \
                python3-devel \
                git \
                wget \
                curl \
                nmap \
                nikto \
                golang \
                gcc \
                gcc-c++ \
                make \
                openssl-devel \
                sqlite \
                sqlite-devel \
                wkhtmltopdf
            ;;
            
        *)
            log_error "Distribuzione non supportata: $DISTRO"
            log_warning "Installazione manuale richiesta"
            exit 1
            ;;
    esac
    
    log_success "Dipendenze di sistema installate con successo"
}

# Configura Go environment
setup_go_environment() {
    log_info "Configurazione ambiente Go..."
    
    # Verifica se Go è installato
    if ! command -v go &> /dev/null; then
        log_error "Go non è installato correttamente"
        exit 1
    fi
    
    # Configura GOPATH se non esiste
    if [ -z "$GOPATH" ]; then
        export GOPATH=$HOME/go
        export PATH=$PATH:$GOPATH/bin
        
        # Aggiungi al bashrc/zshrc
        if [ -f "$HOME/.bashrc" ]; then
            echo 'export GOPATH=$HOME/go' >> "$HOME/.bashrc"
            echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.bashrc"
        fi
        if [ -f "$HOME/.zshrc" ]; then
            echo 'export GOPATH=$HOME/go' >> "$HOME/.zshrc"
            echo 'export PATH=$PATH:$GOPATH/bin' >> "$HOME/.zshrc"
        fi
    fi
    
    log_success "Ambiente Go configurato"
}

# Installa tool di sicurezza esterni
install_security_tools() {
    log_info "Installazione tool di sicurezza esterni..."
    
    # Crea directory per i tool
    mkdir -p ~/security-tools
    cd ~/security-tools
    
    # Installa Nuclei
    log_info "Installazione Nuclei..."
    if ! command -v nuclei &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        log_success "Nuclei installato"
    else
        log_success "Nuclei già installato"
    fi
    
    # Aggiorna template Nuclei
    log_info "Aggiornamento template Nuclei..."
    nuclei -update-templates -silent 2>/dev/null || true
    
    # Installa Subfinder
    log_info "Installazione Subfinder..."
    if ! command -v subfinder &> /dev/null; then
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        log_success "Subfinder installato"
    else
        log_success "Subfinder già installato"
    fi
    
    # Installa Assetfinder
    log_info "Installazione Assetfinder..."
    if ! command -v assetfinder &> /dev/null; then
        go install github.com/tomnomnom/assetfinder@latest
        log_success "Assetfinder installato"
    else
        log_success "Assetfinder già installato"
    fi
    
    # Installa WhatWeb (se non presente)
    log_info "Verifica WhatWeb..."
    if ! command -v whatweb &> /dev/null; then
        log_info "Installazione WhatWeb da GitHub..."
        git clone https://github.com/urbanadventurer/WhatWeb.git
        cd WhatWeb
        sudo make install
        cd ..
        log_success "WhatWeb installato"
    else
        log_success "WhatWeb già installato"
    fi
    
    # Installa Dirsearch
    log_info "Installazione Dirsearch..."
    if [ ! -d "$HOME/security-tools/dirsearch" ]; then
        git clone https://github.com/maurosoria/dirsearch.git
        cd dirsearch
        pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
        cd ..
        log_success "Dirsearch installato"
    else
        log_success "Dirsearch già installato"
    fi
    
    cd - > /dev/null
    log_success "Tool di sicurezza installati con successo"
}

# Crea ambiente virtuale Python
create_python_venv() {
    log_info "Creazione ambiente virtuale Python..."
    
    # Rimuovi vecchio venv se esiste
    if [ -d "venv" ]; then
        log_warning "Rimozione vecchio ambiente virtuale..."
        rm -rf venv
    fi
    
    # Crea nuovo venv
    python3 -m venv venv
    log_success "Ambiente virtuale creato"
    
    # Attiva venv
    source venv/bin/activate
    
    # Aggiorna pip
    log_info "Aggiornamento pip..."
    pip install --upgrade pip setuptools wheel
    
    log_success "Ambiente virtuale configurato"
}

# Installa dipendenze Python
install_python_dependencies() {
    log_info "Installazione dipendenze Python..."
    
    # Assicurati che venv sia attivo
    source venv/bin/activate
    
    # Installa da requirements.txt
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        log_success "Dipendenze Python installate"
    else
        log_error "File requirements.txt non trovato"
        exit 1
    fi
}

# Crea struttura directory
create_directory_structure() {
    log_info "Creazione struttura directory..."
    
    mkdir -p reports logs scans static/css static/js templates scanners
    
    # Crea file __init__.py per scanners
    touch scanners/__init__.py
    
    log_success "Struttura directory creata"
}

# Inizializza database
initialize_database() {
    log_info "Inizializzazione database..."
    
    source venv/bin/activate
    python3 -c "from database import init_db; init_db()"
    
    log_success "Database inizializzato"
}

# Configura permessi
set_permissions() {
    log_info "Configurazione permessi..."
    
    chmod +x app.py
    chmod 755 reports logs scans
    
    log_success "Permessi configurati"
}

# Verifica installazione
verify_installation() {
    log_info "Verifica installazione..."
    
    local errors=0
    
    # Verifica tool esterni
    commands=("nmap" "nikto" "nuclei" "subfinder" "assetfinder" "whatweb")
    for cmd in "${commands[@]}"; do
        if command -v $cmd &> /dev/null; then
            log_success "$cmd: OK"
        else
            log_error "$cmd: NON TROVATO"
            ((errors++))
        fi
    done
    
    # Verifica Python packages
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
        print(f"✗ {pkg}: NON TROVATO")
        errors += 1
sys.exit(errors)
EOF
    
    if [ $? -ne 0 ]; then
        ((errors++))
    fi
    
    if [ $errors -eq 0 ]; then
        log_success "Verifica completata con successo!"
        return 0
    else
        log_error "Verifica fallita con $errors errori"
        return 1
    fi
}

# Stampa istruzioni finali
print_final_instructions() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                INSTALLAZIONE COMPLETATA!                   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}📋 PROSSIMI PASSI:${NC}"
    echo ""
    echo -e "1️⃣  Attiva l'ambiente virtuale:"
    echo -e "   ${YELLOW}source venv/bin/activate${NC}"
    echo ""
    echo -e "2️⃣  Avvia il server:"
    echo -e "   ${YELLOW}python3 app.py${NC}"
    echo ""
    echo -e "3️⃣  Apri il browser su:"
    echo -e "   ${YELLOW}http://localhost:8000${NC}"
    echo ""
    echo -e "${BLUE}📚 COMANDI UTILI:${NC}"
    echo -e "   • Avvia con log dettagliati: ${YELLOW}python3 app.py --debug${NC}"
    echo -e "   • Esegui scansione da CLI: ${YELLOW}python3 scanner_engine.py --target <URL>${NC}"
    echo ""
    echo -e "${RED}⚠️  DISCLAIMER:${NC}"
    echo -e "   Questo tool è destinato SOLO a test autorizzati."
    echo -e "   L'uso non autorizzato può violare leggi locali e internazionali."
    echo ""
}

# Gestione errori
trap 'log_error "Errore durante l installazione. Controllare i log."; exit 1' ERR

# Main execution
main() {
    clear
    print_logo
    
    log_info "Inizio installazione Vulnerability Assessment Platform..."
    echo ""
    
    check_root
    detect_distro
    install_system_dependencies
    setup_go_environment
    install_security_tools
    create_directory_structure
    create_python_venv
    install_python_dependencies
    initialize_database
    set_permissions
    
    echo ""
    if verify_installation; then
        print_final_instructions
    else
        log_error "Installazione completata con errori. Rivedere i messaggi sopra."
        exit 1
    fi
}

# Esegui script
main "$@"
