#!/bin/bash

# OmniProbe Scanner Installation Script
# Supports: macOS (Homebrew), Linux (Debian/Ubuntu/Kali)

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}[*] OmniProbe Scanner Setup${NC}"

# 1. Detect OS
OS="$(uname)"
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

# 2. Install System Dependencies (Nmap, Python, Node, Go)
echo -e "${BLUE}[*] Installing system dependencies...${NC}"
if [ "$PACKAGE_MANAGER" == "brew" ]; then
    brew install nmap python3 node go
    brew install wapiti
elif [ "$PACKAGE_MANAGER" == "apt" ]; then
    sudo apt-get update
    sudo apt-get install -y nmap python3 python3-pip python3-venv nodejs npm golang-go wapiti
fi

# 3. Install Security Tools (Nuclei, Katana, Httpx) via Go
echo -e "${BLUE}[*] Installing ProjectDiscovery tools (Nuclei, Katana, Httpx)...${NC}"
export PATH=$PATH:$(go env GOPATH)/bin
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

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
