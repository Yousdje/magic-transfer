#!/bin/bash

# Universal Secure File Transfer - Setup Script
# Voor Proxmox/Docker deployment

set -e

echo "🔐 Universal Secure File Transfer - Setup"
echo "Cross-platform: iOS, Android, Windows, Linux, macOS"
echo "=========================================="
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker niet gevonden. Installeer eerst Docker."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose niet gevonden. Installeer eerst docker-compose."
    exit 1
fi

echo "✅ Docker en Docker Compose gevonden"
echo ""

# Create directories
echo "📁 Creëer directories..."
mkdir -p input output

# Set permissions
chmod 755 input output

echo "✅ Directories aangemaakt"
echo ""

# Build container
echo "🏗️  Building Docker container..."
docker-compose build

echo "✅ Container gebuild"
echo ""

# Start service
echo "🚀 Starten van service..."
docker-compose up -d

echo "✅ Service gestart"
echo ""

# Wait for service to be ready
echo "⏳ Wachten tot service ready is..."
sleep 5

# Check health
if docker ps | grep -q "secure-file-transfer"; then
    echo "✅ Container draait"
    echo ""
    
    # Get IP addresses
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    echo "🎉 Setup compleet!"
    echo ""
    echo "📱 Toegang per platform:"
    echo "   iOS/Android: Open browser → http://${LOCAL_IP}:8080"
    echo "   Windows:     python client.py send file.txt --server http://${LOCAL_IP}:8080"
    echo "   Linux:       ./client.py send file.txt --server http://${LOCAL_IP}:8080"
    echo ""
    echo "💡 Tips:"
    echo "   1. Installeer PWA op je phone (Add to Home Screen)"
    echo "   2. Setup Tailscale voor remote toegang"
    echo "   3. Lees INSTALL.md voor gedetailleerde instructies per platform"
    echo ""
    echo "📊 Handige commands:"
    echo "   - Logs bekijken:  docker-compose logs -f"
    echo "   - Stoppen:        docker-compose down"
    echo "   - Herstarten:     docker-compose restart"
    echo "   - Status:         docker-compose ps"
    echo ""
    echo "🔒 Security:"
    echo "   - Alleen gebruiken binnen trusted netwerk (LAN/VPN)"
    echo "   - Pairing codes delen via veilige kanalen"
    echo "   - Voor WAN: gebruik Tailscale VPN"
else
    echo "❌ Container start gefaald. Check logs:"
    echo "   docker-compose logs"
    exit 1
fi
