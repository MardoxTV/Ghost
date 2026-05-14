#!/bin/bash
# Ghost - Anonymity Suite Installer for Kali Linux

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[+]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }

echo -e "${RED}"
cat << 'EOF'
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
        Anonymity Suite Installer
EOF
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
    fail "Run as root: sudo bash install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── System Dependencies ───────────────────────────────────────────
info "Updating package lists..."
apt-get update -qq

info "Installing system dependencies..."
PACKAGES=(
    "tor"
    "proxychains4"
    "iptables"
    "iproute2"
    "net-tools"
    "curl"
    "python3"
    "python3-pip"
    "python3-venv"
    "systemd"
)

for pkg in "${PACKAGES[@]}"; do
    if ! dpkg -s "$pkg" &>/dev/null; then
        apt-get install -y -qq "$pkg"
        ok "Installed: $pkg"
    else
        ok "Already installed: $pkg"
    fi
done

# ─── Python Environment ────────────────────────────────────────────
info "Setting up Python virtual environment..."
python3 -m venv "$SCRIPT_DIR/venv"
source "$SCRIPT_DIR/venv/bin/activate"

info "Installing Python dependencies..."
pip install -q --upgrade pip
pip install -q -r "$SCRIPT_DIR/requirements.txt"
ok "Python dependencies installed"

# ─── Tor Configuration ────────────────────────────────────────────
info "Configuring Tor service..."
systemctl enable tor --quiet 2>/dev/null || true
cp "$SCRIPT_DIR/config/torrc" /etc/tor/torrc
ok "Tor configured"

# ─── Ghost Launcher ───────────────────────────────────────────────
info "Creating ghost launcher..."
cat > /usr/local/bin/ghost << LAUNCHER
#!/bin/bash
GHOST_DIR="$SCRIPT_DIR"
source "\$GHOST_DIR/venv/bin/activate"
exec python3 "\$GHOST_DIR/main.py" "\$@"
LAUNCHER

chmod +x /usr/local/bin/ghost
ok "Launcher created at /usr/local/bin/ghost"

# ─── Permissions ─────────────────────────────────────────────────
chmod +x "$SCRIPT_DIR/main.py"

echo
echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Ghost installed successfully!      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo
echo -e "  Run:  ${CYAN}sudo ghost${NC}                    (interactive TUI)"
echo -e "  Run:  ${CYAN}sudo ghost --ghost-on${NC}          (enable everything)"
echo -e "  Run:  ${CYAN}sudo ghost --status${NC}            (show status)"
echo -e "  Run:  ${CYAN}sudo ghost --help${NC}              (all options)"
echo
warn "Always run with sudo — Ghost requires root for iptables and MAC changes."
echo
