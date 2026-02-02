#!/bin/bash

# OmniProbe Scanner Installation Script
# Supports: macOS (Homebrew), Linux (Debian/Ubuntu/Kali)

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] OmniProbe Scanner Setup${NC}"

# 1. Detect OS & Define Helper
OS="$(uname)"
is_installed() {
    command -v "$1" &> /dev/null
}

install_if_missing() {
    TOOL=$1
    CMD=$2
    if is_installed "$TOOL"; then
        echo -e "${GREEN}[✔] $TOOL is already installed. Skipping.${NC}"
    else
        echo -e "${BLUE}[*] Installing $TOOL...${NC}"
        eval "$CMD"
    fi
}

if [ "$OS" == "Darwin" ]; then
    echo -e "${GREEN}[+] macOS detected.${NC}"
    if ! command -v brew &> /dev/null; then
        echo -e "${RED}[!] Homebrew not found. Please install Homebrew first.${NC}"
        exit 1
    fi
    PACKAGE_MANAGER="brew"
elif [ -f /etc/debian_version ]; then
    echo -e "${GREEN}[+] Debian/Linux detected.${NC}"
    PACKAGE_MANAGER="apt"
else
    echo -e "${RED}[!] Unsupported OS. This script supports macOS and Debian-based Linux.${NC}"
    exit 1
fi

# 2. Install System Dependencies
echo -e "${BLUE}[*] Checking system dependencies...${NC}"

if [ "$PACKAGE_MANAGER" == "brew" ]; then
    install_if_missing "nmap" "brew install nmap"
    install_if_missing "python3" "brew install python3"
    install_if_missing "node" "brew install node"
    install_if_missing "go" "brew install go"
    # Wapiti is better installed via pip on all platforms
elif [ "$PACKAGE_MANAGER" == "apt" ]; then
    echo -e "${BLUE}[*] Updating apt repositories...${NC}"
    sudo apt-get update
    install_if_missing "nmap" "sudo apt-get install -y nmap"
    install_if_missing "python3" "sudo apt-get install -y python3 python3-pip python3-venv"
    install_if_missing "node" "sudo apt-get install -y nodejs npm"
    install_if_missing "go" "sudo apt-get install -y golang-go"
fi

# 3. Install Security Tools (Nuclei, Katana, Httpx) via Go
echo -e "${BLUE}[*] Checking ProjectDiscovery tools...${NC}"
export PATH=$PATH:$(go env GOPATH)/bin

install_go_tool() {
    TOOL=$1
    REPO=$2
    if is_installed "$TOOL"; then
        echo -e "${GREEN}[✔] $TOOL is already installed. Skipping.${NC}"
    else
        echo -e "${BLUE}[*] Installing $TOOL...${NC}"
        go install -v "$REPO@latest"
    fi
}

install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"
install_go_tool "katana" "github.com/projectdiscovery/katana/cmd/katana"
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"

# 4. Install Wapiti (Via Pip - Universal)
echo -e "${BLUE}[*] Checking Wapiti...${NC}"
if is_installed "wapiti"; then
    echo -e "${GREEN}[✔] wapiti is already installed. Skipping.${NC}"
else
    echo -e "${BLUE}[*] Installing Wapiti via pip3 (Global)...${NC}"
    # Use --break-system-packages if on managed python env (newer linux/mac), otherwise normal pip
    if pip3 install wapiti3 --break-system-packages &> /dev/null; then
        echo -e "${GREEN}[✔] Wapiti installed successfully.${NC}"
    else
        echo -e "${BLUE}[*] Retrying standard pip install...${NC}"
        pip3 install wapiti3
    fi
fi


# Add Go bin to path if not exists
if [[ ":$PATH:" != *":$HOME/go/bin:"* ]]; then
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
    echo -e "${GREEN}[+] Added Go binaries to PATH. Please restart your terminal or source your shell config.${NC}"
fi

# 4. Backend Setup
echo -e "${BLUE}[*] Setting up Backend...${NC}"
cd backend
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt
cd ..

# 5. Frontend Setup
echo -e "${BLUE}[*] Setting up Frontend...${NC}"
cd frontend
npm install
cd ..

echo -e "${GREEN}[✔] Installation Complete!${NC}"
echo -e "${BLUE}[*] To start the scanner, run:${NC} ./run_app.sh"
chmod +x run_app.sh run_backend.sh install.sh
