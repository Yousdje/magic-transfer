#!/bin/bash
# Arch Linux Setup Script
# Voor Youssef's desktop

set -e

echo "🔐 Secure Transfer - Arch Linux Setup"
echo "======================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo "⚠️  Don't run this script as root!"
    echo "   Use your regular user account"
    exit 1
fi

# Install dependencies via pacman
echo "📦 Installing dependencies..."
if ! command -v python &> /dev/null; then
    echo "Installing Python..."
    sudo pacman -S --needed --noconfirm python python-pip
fi

# Install Python packages
echo "Installing Python packages..."
pip install --user --break-system-packages cryptography requests || \
    pip install --user cryptography requests

echo "✅ Dependencies installed"
echo ""

# Check Tailscale
echo "🔌 Checking Tailscale..."
if ! command -v tailscale &> /dev/null; then
    echo "⚠️  Tailscale not installed"
    read -p "Install Tailscale? (y/n) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo pacman -S --needed --noconfirm tailscale
        sudo systemctl enable --now tailscaled
        echo "✅ Tailscale installed"
        echo "   Now run: sudo tailscale up"
    fi
else
    echo "✅ Tailscale installed"
    tailscale status || echo "   Run: sudo tailscale up"
fi
echo ""

# Create bin directory
BIN_DIR="$HOME/bin"
echo "📁 Creating bin directory: $BIN_DIR"
mkdir -p "$BIN_DIR"

# Copy client if exists
if [ -f "client.py" ]; then
    echo "📄 Copying client.py..."
    cp client.py "$BIN_DIR/"
    chmod +x "$BIN_DIR/client.py"
    echo "✅ Client installed to $BIN_DIR/client.py"
else
    echo "⚠️  client.py not found in current directory"
    echo "   Please copy client.py to: $BIN_DIR/"
fi
echo ""

# Setup shell configuration
SHELL_CONFIG=""
if [ -n "$ZSH_VERSION" ]; then
    SHELL_CONFIG="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_CONFIG="$HOME/.bashrc"
fi

if [ -n "$SHELL_CONFIG" ]; then
    echo "🔧 Configuring shell: $SHELL_CONFIG"
    
    # Check if already configured
    if grep -q "TRANSFER_SERVER" "$SHELL_CONFIG" 2>/dev/null; then
        echo "ℹ️  Shell already configured"
    else
        cat >> "$SHELL_CONFIG" << 'EOF'

# === Secure Transfer Shortcuts ===
export TRANSFER_SERVER="http://daggertooth-daggertooth.ts.net:8080"
export PATH="$HOME/bin:$PATH"

alias tsend='~/bin/client.py send'
alias trecv='~/bin/client.py receive'

# Quick help
alias thelp='echo "tsend <file> - Send file
trecv <code> - Receive file
Server: $TRANSFER_SERVER"'
# === End Secure Transfer ===

EOF
        echo "✅ Shell configured"
    fi
else
    echo "⚠️  Could not detect shell config file"
fi
echo ""

# Test Python imports
echo "🧪 Testing Python imports..."
python -c "import cryptography, requests" && echo "✅ Imports OK" || echo "❌ Import failed"
echo ""

# Final instructions
echo "🎉 Setup Complete!"
echo ""
echo "📝 Next Steps:"
echo "   1. Reload shell: source $SHELL_CONFIG"
echo "   2. If Tailscale not connected: sudo tailscale up"
echo "   3. Test: tsend /tmp/test.txt"
echo ""
echo "🚀 Usage:"
echo "   tsend ~/Documents/file.pdf"
echo "   trecv 123456"
echo "   trecv 123456 --output ~/Downloads"
echo "   thelp  # Show help"
echo ""
echo "🌐 Server URLs:"
echo "   Tailscale: http://daggertooth-daggertooth.ts.net:8080"
echo "   LAN:       http://192.168.1.30:8080"
echo ""
echo "💡 Pro tip: Add 'eval \$(tailscale status)' to your shell config"
echo "   for quick Tailscale status in your prompt!"
echo ""

# Offer to reload shell
read -p "Reload shell config now? (y/n) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if [ -n "$ZSH_VERSION" ]; then
        exec zsh
    elif [ -n "$BASH_VERSION" ]; then
        exec bash
    fi
fi
