# Installation Guide

Complete installation instructions for Security Header Analyzer across different environments and platforms.

## Table of Contents

- [Quick Install](#quick-install)
- [Installation Methods](#installation-methods)
- [Platform-Specific Instructions](#platform-specific-instructions)
- [Development Installation](#development-installation)
- [Troubleshooting](#troubleshooting)

## Quick Install

For most users, the recommended installation method is via pip:

```bash
pip install security-header-analyzer
```

Verify installation:

```bash
sha --version
```

## Installation Methods

### Method 1: Install via pip (Recommended)

Install the latest stable version from PyPI:

```bash
pip install security-header-analyzer
```

Install a specific version:

```bash
pip install security-header-analyzer==1.0.0
```

Upgrade to the latest version:

```bash
pip install --upgrade security-header-analyzer
```

### Method 2: Install via pipx (Isolated Environment)

[pipx](https://pipx.pypa.io/) installs Python applications in isolated environments, preventing dependency conflicts.

**Install pipx** (if not already installed):

```bash
# On macOS/Linux
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# On Windows
py -m pip install --user pipx
py -m pipx ensurepath
```

**Install security-header-analyzer with pipx**:

```bash
pipx install security-header-analyzer
```

**Advantages of pipx**:
- Isolated environment per application
- No dependency conflicts with other Python tools
- Automatic PATH configuration
- Easy upgrades: `pipx upgrade security-header-analyzer`

### Method 3: Install from Source

Clone the repository and install:

```bash
# Clone the repository
git clone https://github.com/yourusername/security-header-analyzer.git
cd security-header-analyzer

# Install in editable mode
pip install -e .
```

**Use case**: Development, contributing, or testing unreleased features.

### Method 4: Install in Virtual Environment

Create an isolated Python environment:

```bash
# Create virtual environment
python3 -m venv sha-env

# Activate virtual environment
# On macOS/Linux:
source sha-env/bin/activate

# On Windows:
sha-env\Scripts\activate

# Install security-header-analyzer
pip install security-header-analyzer
```

**Use case**: Testing, isolated project dependencies, or avoiding global package installations.

## Platform-Specific Instructions

### Linux

**Debian/Ubuntu**:

```bash
# Update package list
sudo apt update

# Install Python 3 and pip (if not installed)
sudo apt install python3 python3-pip

# Install security-header-analyzer
pip3 install security-header-analyzer

# Add to PATH (if pip warns about location)
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Fedora/RHEL/CentOS**:

```bash
# Install Python 3 and pip
sudo dnf install python3 python3-pip

# Install security-header-analyzer
pip3 install security-header-analyzer
```

**Arch Linux**:

```bash
# Install Python and pip
sudo pacman -S python python-pip

# Install security-header-analyzer
pip install security-header-analyzer
```

### macOS

**Using Homebrew Python** (Recommended):

```bash
# Install Python via Homebrew (if not installed)
brew install python3

# Install security-header-analyzer
pip3 install security-header-analyzer
```

**Using system Python**:

```bash
# Install security-header-analyzer with user flag
pip3 install --user security-header-analyzer

# Add to PATH
echo 'export PATH="$HOME/Library/Python/3.x/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Replace `3.x` with your Python version (e.g., `3.9`, `3.10`).

### Windows

**Using Command Prompt**:

```cmd
REM Install security-header-analyzer
py -m pip install security-header-analyzer

REM Verify installation
py -m sha --version
```

**Using PowerShell**:

```powershell
# Install security-header-analyzer
py -m pip install security-header-analyzer

# Verify installation
py -m sha --version
```

**Adding to PATH** (if `sha` command not found):

1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Go to "Advanced" → "Environment Variables"
3. Under "User variables", edit `Path`
4. Add: `C:\Users\YourUsername\AppData\Local\Programs\Python\Python3x\Scripts`
5. Click OK, restart terminal

## Development Installation

For contributors and developers:

### 1. Clone and Setup

```bash
# Clone repository
git clone https://github.com/yourusername/security-header-analyzer.git
cd security-header-analyzer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

### 2. Install Pre-commit Hooks (Optional)

```bash
pip install pre-commit
pre-commit install
```

### 3. Run Tests

```bash
pytest
```

## Requirements

- **Python**: 3.7 or higher
- **Dependencies** (automatically installed):
  - `requests` ≥ 2.25.0 - HTTP library for fetching headers
  - `urllib3` ≥ 1.26.0 - HTTP client (dependency of requests)

## Troubleshooting

### Issue: `command not found: sha`

**Cause**: Installation directory not in PATH.

**Solution**:

1. Find installation location:
   ```bash
   python3 -m site --user-base
   ```

2. Add to PATH:
   ```bash
   # Linux/macOS (add to ~/.bashrc or ~/.zshrc)
   export PATH="$HOME/.local/bin:$PATH"

   # Windows (run in PowerShell as Administrator)
   [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Users\YourUsername\AppData\Local\Programs\Python\Python3x\Scripts", "User")
   ```

3. Restart terminal.

### Issue: `pip: command not found`

**Cause**: pip not installed or not in PATH.

**Solution**:

```bash
# Install pip
python3 -m ensurepip --upgrade

# Or download get-pip.py
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
```

### Issue: Permission Denied

**Cause**: Installing to system-wide location without sudo.

**Solution**:

```bash
# Use --user flag to install to user directory
pip install --user security-header-analyzer

# Or use virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install security-header-analyzer
```

### Issue: SSL Certificate Errors

**Cause**: Corporate proxy or outdated CA certificates.

**Solution**:

```bash
# Upgrade certifi (CA certificates)
pip install --upgrade certifi

# Or use --trusted-host (temporary workaround)
pip install --trusted-host pypi.org --trusted-host files.pythonhosted.org security-header-analyzer
```

### Issue: Dependency Conflicts

**Cause**: Conflicting package versions.

**Solution**:

```bash
# Use pipx for isolated installation
pipx install security-header-analyzer

# Or use virtual environment
python3 -m venv sha-env
source sha-env/bin/activate
pip install security-header-analyzer
```

## Verifying Installation

After installation, verify everything works:

```bash
# Check version
sha --version

# Run basic test
sha https://example.com

# Run with JSON output
sha https://example.com --json
```

Expected output: Security header analysis report.

## Uninstalling

Remove security-header-analyzer:

```bash
# If installed via pip
pip uninstall security-header-analyzer

# If installed via pipx
pipx uninstall security-header-analyzer
```

## Next Steps

- Read [usage-guide.md](usage-guide.md) for CLI usage patterns
- Try the [quick-start-tutorial.md](quick-start-tutorial.md) for hands-on introduction
- Explore [docs/headers/](headers/) for header-specific documentation

## Getting Help

- **Documentation**: [docs/](../docs/)
- **Issues**: [GitHub Issues](https://github.com/yourusername/security-header-analyzer/issues)
- **Contributing**: [CONTRIBUTING.md](../CONTRIBUTING.md)
