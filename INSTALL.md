# Universal Installation Guide
## Cross-Platform Secure File Transfer

Dit systeem werkt op **ALLE** je apparaten:
- ✅ iOS (iPhone/iPad)
- ✅ Android (phone/tablet)  
- ✅ Windows (10/11)
- ✅ Linux (Arch, Ubuntu, Debian, Fedora, etc)
- ✅ macOS
- ✅ Linux zonder GUI (servers)

---

## 🏗️ Stap 1: Server Setup (Eenmalig)

De server draait in Docker op je Proxmox. Dit hoef je maar 1x te doen.

### Op je Proxmox host:

```bash
# 1. Download de bestanden
cd /opt
git clone <jouw-repo> secure-transfer
cd secure-transfer

# OF: upload de folder handmatig via SCP/SFTP

# 2. Maak directories
mkdir -p input output

# 3. Start de server
docker-compose up -d

# 4. Check of het draait
docker-compose logs -f
```

De server is nu bereikbaar op:
- **LAN**: `http://192.168.1.x:8080` (vervang x met je Proxmox IP)
- **Tailscale**: `http://proxmox.tailnet-name.ts.net:8080`

### Tailscale Setup (Optioneel maar aanbevolen)

Voor toegang van buitenaf via VPN:

```bash
# Op je Proxmox
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up

# Noteer de hostname (bijv: proxmox.tailnet-name.ts.net)
```

---

## 📱 Stap 2: Client Setup per Platform

### iOS (iPhone/iPad)

**Methode 1: PWA (Aanbevolen)**
1. Open **Safari**
2. Ga naar: `http://192.168.1.x:8080` (of Tailscale URL)
3. Tap op **Share** button (vierkantje met pijltje)
4. Scroll en tap **"Add to Home Screen"**
5. Tap **"Add"**
6. ✅ Nu heb je een app-icoon op je home screen!

**Methode 2: Gewoon browser**
1. Open Safari
2. Ga naar server URL
3. Gebruik direct

**Tips voor iOS:**
- Safari heeft soms issues met grote bestanden → gebruik PWA methode
- Voor privacy: gebruik Private Browsing mode
- Files worden gedownload naar Downloads folder

---

### Android

**Methode 1: PWA (Aanbevolen)**
1. Open **Chrome**
2. Ga naar: `http://192.168.1.x:8080` (of Tailscale URL)
3. Tap op **⋮** (drie puntjes rechtsboven)
4. Tap **"Install app"** of **"Add to Home screen"**
5. Tap **"Install"**
6. ✅ Nu heb je een app in je app drawer!

**Methode 2: Gewoon browser**
1. Open Chrome of Firefox
2. Ga naar server URL
3. Gebruik direct

**Tips voor Android:**
- PWA werkt het best in Chrome
- Geef browser toegang tot storage voor downloads
- Files gaan naar Downloads folder

---

### Windows

**Methode 1: CLI (Aanbevolen voor power users)**

```powershell
# 1. Install Python (als je die nog niet hebt)
# Download van: https://www.python.org/downloads/
# Vink "Add Python to PATH" aan!

# 2. Install dependencies
pip install cryptography requests

# 3. Download client.py naar een folder
# Bijv: C:\Tools\secure-transfer\

# 4. Gebruik:
cd C:\Tools\secure-transfer
python client.py send C:\Users\Youssef\Documents\file.pdf --server http://192.168.1.x:8080

# OF: ontvangen
python client.py receive 123456 --output C:\Downloads
```

**Methode 2: Browser**
1. Open Chrome/Edge/Firefox
2. Ga naar: `http://192.168.1.x:8080`
3. Gebruik web interface

**Windows Tips:**
- Gebruik PowerShell (niet CMD) voor betere ervaring
- Maak een alias voor gemak:
  ```powershell
  # In PowerShell profile
  function transfer { python C:\Tools\secure-transfer\client.py $args }
  # Nu kun je: transfer send file.txt
  ```

---

### Linux (Arch, Ubuntu, etc - Met GUI)

**Methode 1: CLI**

```bash
# 1. Install dependencies (Arch)
sudo pacman -S python python-cryptography python-requests

# OF: Ubuntu/Debian
sudo apt install python3 python3-pip
pip3 install cryptography requests

# 2. Download client
wget https://jouw-server/client.py
chmod +x client.py

# 3. Gebruik
./client.py send ~/Documents/file.pdf --server http://192.168.1.x:8080
./client.py receive 123456 --output ~/Downloads
```

**Methode 2: Browser**
- Open Firefox/Chrome
- Ga naar server URL

**Linux Tips - Aliases maken:**

```bash
# In ~/.bashrc of ~/.zshrc
export TRANSFER_SERVER="http://proxmox.tailnet.ts.net:8080"
alias tsend='python3 ~/bin/client.py send'
alias trecv='python3 ~/bin/client.py receive'

# Nu kun je:
tsend ~/file.pdf
trecv 123456 --output ~/Downloads
```

---

### Linux Zonder GUI (Servers, SSH)

Perfect voor je andere Linux machines zonder desktop!

```bash
# 1. Install (geen GUI dependencies nodig)
sudo apt install python3 python3-pip  # Ubuntu/Debian
sudo pacman -S python python-pip      # Arch

pip3 install --user cryptography requests

# 2. Download client
cd ~
mkdir -p bin
cd bin
wget https://jouw-server/client.py
chmod +x client.py

# 3. Gebruik via SSH
./client.py send /data/backup.tar.gz --server http://192.168.1.x:8080
# Output toont pairing code

# 4. Op ander apparaat
./client.py receive 123456 --output /backups
```

**Automation voorbeelden:**

```bash
#!/bin/bash
# Automated backup transfer
DATE=$(date +%Y%m%d)
BACKUP_FILE="/backups/backup-${DATE}.tar.gz"

# Create backup
tar czf ${BACKUP_FILE} /data

# Send via secure transfer
~/bin/client.py send ${BACKUP_FILE} --server http://proxmox:8080

# Log it
echo "Backup sent at $(date)" >> /var/log/transfers.log
```

---

### macOS

**Methode 1: CLI**

```bash
# 1. Install Python (als nog niet aanwezig)
brew install python3

# 2. Install dependencies
pip3 install cryptography requests

# 3. Download en gebruik client
curl -O https://jouw-server/client.py
chmod +x client.py

./client.py send ~/Documents/file.pdf --server http://192.168.1.x:8080
./client.py receive 123456 --output ~/Downloads
```

**Methode 2: Browser**
- Open Safari/Chrome
- Ga naar server URL

---

## 🔄 Praktische Workflows

### Scenario 1: Van iPhone naar Windows PC

```
iPhone:
1. Open Secure Transfer app (PWA)
2. Tap "Send"
3. Selecteer foto/video
4. Noteer code: 123456

Windows PC:
1. Open PowerShell
2. Run: python client.py receive 123456 --output C:\Downloads
3. ✅ Bestand binnen!
```

### Scenario 2: Van Arch Linux naar Android

```
Arch:
1. tsend ~/Documents/report.pdf
2. Zie code: 789012

Android:
1. Open Secure Transfer app
2. Tap "Receive"  
3. Enter: 789012
4. ✅ Download naar phone!
```

### Scenario 3: Van Windows naar Headless Linux Server

```
Windows:
1. python client.py send C:\Backup\data.zip --server http://proxmox:8080
2. Code: 456789

SSH naar Linux server:
1. ./client.py receive 456789 --output /mnt/storage
2. ✅ Backup op server!
```

---

## ⚙️ Advanced Configuration

### Custom Server URL

**Optie 1: Environment Variable**
```bash
# Linux/macOS
export TRANSFER_SERVER="http://proxmox.tailnet.ts.net:8080"

# Windows PowerShell
$env:TRANSFER_SERVER="http://proxmox.tailnet.ts.net:8080"

# Nu hoef je geen --server flag meer te gebruiken
python client.py send file.txt
```

**Optie 2: Config File** (future enhancement)
```ini
# ~/.transfer-config
[server]
url = http://proxmox.tailnet.ts.net:8080
```

### Firewall Rules

**UniFi (UXG-Max):**
```
Firewall Rule:
- Name: Secure Transfer
- Type: Accept
- Protocol: TCP
- Port: 8080
- Source: LAN / VPN
```

**Linux iptables:**
```bash
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
```

**Windows Firewall:**
```powershell
New-NetFirewallRule -DisplayName "Secure Transfer" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
```

---

## 🔧 Troubleshooting per Platform

### iOS Issues

**"Cannot download file"**
- Probeer Safari Private Browsing mode
- Check Storage settings → Safari → Downloads
- Herinstall PWA

**"Connection failed"**
- Check of je op zelfde netwerk zit (LAN of Tailscale)
- Probeer cellular data uit en WiFi aan
- Test URL in Safari eerst

### Android Issues

**"Download failed"**
- Ga naar Chrome Settings → Site Settings → Allow downloads
- Check storage permissions voor Chrome
- Clear Chrome cache

**PWA niet beschikbaar**
- Update Chrome naar nieuwste versie
- Probeer Firefox als alternatief

### Windows Issues

**"python not found"**
```powershell
# Check of Python in PATH staat
python --version

# Zo niet, voeg toe via:
$env:Path += ";C:\Python311"
```

**"pip install fails"**
```powershell
# Upgrade pip eerst
python -m pip install --upgrade pip
```

### Linux Issues

**"Permission denied"**
```bash
chmod +x client.py
# OF:
python3 client.py send file.txt
```

**"Module not found"**
```bash
# Install in user directory
pip3 install --user cryptography requests
```

---

## 📊 Comparison: Wanneer welke methode?

| Situatie | Beste Methode |
|----------|---------------|
| Snel delen vanaf phone | PWA (iOS/Android) |
| Grote bestanden (>1GB) | CLI |
| Automation/scripting | CLI |
| Geen Python beschikbaar | Web browser |
| Headless server | CLI |
| Occasional use | Web browser |
| Daily use | PWA of CLI alias |

---

## 🚀 Quick Reference Card

```
=== VERSTUREN ===
iOS/Android:  Open app → Send → Select file → Share code
Windows:      python client.py send file.txt
Linux:        ./client.py send file.txt

=== ONTVANGEN ===
iOS/Android:  Open app → Receive → Enter code
Windows:      python client.py receive 123456
Linux:        ./client.py receive 123456

=== SERVER INFO ===
LAN:          http://192.168.1.x:8080
Tailscale:    http://proxmox.tailnet.ts.net:8080
Health:       /health endpoint
```

---

## 💡 Pro Tips

1. **Bookmark de server URL** op al je apparaten
2. **Installeer PWA** op phones voor native app ervaring
3. **Gebruik Tailscale** voor secure remote access
4. **Maak aliases** op CLI voor sneller werken
5. **Test eerst met klein bestand** voor elke nieuwe setup

---

## 🆘 Support

Als iets niet werkt:

1. **Check server**: `docker-compose logs -f`
2. **Test connectivity**: Ping het server IP
3. **Verify URL**: Open in browser, moet login tonen
4. **Check firewall**: Poort 8080 open?
5. **Try alternative**: Als CLI faalt, probeer web interface

Voor specifieke platform issues, zie Troubleshooting sectie hierboven.
