# 🚀 Complete Installation Guide

## 📦 Package Contents

This archive includes:
- ✅ Complete directory structure
- ✅ Configuration files (`installer.sh`, `requirements.txt`, `.env.example`)
- ✅ CSS assets and web structure
- ✅ README and documentation

## ⚠️ Important: Validate Required Files

Before installing, ensure all required Python and template files are present
and non-empty. The installer now checks for missing or empty files and
will stop with an actionable error message if the project is incomplete.

### Required Files

#### 1. **config.py** (Configuration)
Contains application settings and defaults.

#### 2. **database.py** (Database ORM)
Defines SQLAlchemy models and database initialization.

#### 3. **scanner_engine.py** (Scan Orchestrator)
Main asynchronous scan orchestration engine.

#### 4. **report_generator.py** (PDF Report Generator)
Builds PDF reports from scan results.

#### 5. **app.py** (FastAPI Server)
API and web server entry point.

#### 6. Scanner Modules (`scanners/`)
- `nuclei_scanner.py`
- `nmap_scanner.py`
- `whatweb_scanner.py`
- `subfinder_scanner.py`
- `nikto_scanner.py`

#### 7. HTML Templates (`templates/`)
- `index.html`
- `scan_detail.html`
- `scans_list.html`

## 🐍 Python Version Compatibility

This project currently supports **Python 3.10 - 3.12**. Newer versions (3.13+)
can fail during dependency builds (e.g., `pydantic-core`). Install a supported
Python version before running the installer.

## 🔧 Installation Steps (Linux/macOS)

### Step 1: Extract the Archive
```bash
tar -xzf vulnerability-assessment-platform-COMPLETE.tar.gz
cd vulnerability-assessment-platform
```

### Step 2: Run the Installer
```bash
chmod +x installer.sh
./installer.sh
```

The installer will:
- Detect the OS platform
- Install system dependencies (Ubuntu/Debian or macOS)
- Install external security tools (Nuclei, Subfinder, etc.)
- Create a Python virtual environment
- Install Python dependencies
- Initialize the database

### Step 3: Start the Platform
```bash
source venv/bin/activate
python3 app.py
```

### Step 4: Open the Dashboard
Open your browser at: `http://localhost:8000`

## 🪟 Installation Steps (Windows)

Open PowerShell and run:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\installer.ps1
```

Then start the server:
```powershell
.\venv\Scripts\Activate.ps1
python app.py
```

## ✅ Post-Install Verification

After installation, verify core functionality:

```bash
# 1. Verify Python imports
python3 -c "from scanner_engine import ScannerEngine; print('✓ OK')"

# 2. Verify database initialization
python3 -c "from database import init_db; init_db(); print('✓ OK')"

# 3. Verify external tools
nuclei -version
nmap --version
```

## 🐛 Troubleshooting

### macOS 11/12 (Big Sur/Monterey) + Homebrew install failures
Homebrew support for macOS 11/12 can be limited, so package installs
(including Python) may fail. Use one of the following supported paths:

**Option A: Upgrade macOS**  
Upgrade to macOS 13+ and re-run `installer.sh`.

**Option B: Use MacPorts (macOS 11/12 supported)**  
Install MacPorts and use it to install Python 3.12 and required tools, then
run `installer.sh`.

**Option C: Install Python 3.12 from python.org**  
Download Python 3.12 for macOS from the official website, ensure `pip`
is available, then run:
```bash
python3 -m ensurepip --upgrade
python3 -m pip install -r requirements.txt
```

### Error: "No module named pip.__main__"
This means `pip` is missing from the selected Python interpreter.
Run:
```bash
python3 -m ensurepip --upgrade
```
Then retry the install steps.

### Error: "Module not found"
```bash
source venv/bin/activate
pip install -r requirements.txt
```
