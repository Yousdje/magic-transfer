# 🚀 Quick Start Guide

Start in **5 minuten** met het versturen van bestanden tussen al je devices!

## Stap 1: Server Starten (1x doen)

```bash
# Op je Proxmox of Linux machine
cd secure-file-transfer
./setup.sh
```

Noteer het IP adres dat wordt getoond (bijv. `192.168.1.100`)

## Stap 2: Eerste Transfer

### Van Phone naar Computer

**Op je iPhone/Android:**
1. Open Safari/Chrome
2. Ga naar `http://192.168.1.100:8080` (gebruik jouw IP)
3. Tap "Send" tab
4. Selecteer foto/bestand
5. Tap "Upload & Generate Code"
6. Noteer de 6-cijferige code (bijv. `123456`)

**Op je Computer:**
```bash
# Windows (PowerShell)
python client.py receive 123456 --output C:\Downloads

# Linux/macOS
./client.py receive 123456 --output ~/Downloads
```

✅ **Klaar!** Bestand is nu op je computer.

---

### Van Computer naar Phone

**Op je Computer:**
```bash
# Windows
python client.py send C:\Documents\foto.jpg

# Linux/macOS
./client.py send ~/Documents/foto.jpg
```

Noteer de code die wordt getoond (bijv. `789012`)

**Op je Phone:**
1. Open de web interface
2. Tap "Receive" tab
3. Voer code in: `789012`
4. Tap "Connect & Download"

✅ **Klaar!** Bestand is nu op je phone.

---

## Stap 3: Maak het Makkelijker

### Phone: Installeer als App

**iOS:**
1. In Safari: tap Share button
2. "Add to Home Screen"
3. Tap "Add"
4. Nu heb je een app icon!

**Android:**
1. In Chrome: tap ⋮ menu
2. "Install app"
3. Tap "Install"
4. Nu in je app drawer!

### Computer: Maak Shortcut

**Windows (PowerShell profile):**
```powershell
# Edit: notepad $PROFILE
function transfer { python C:\Tools\secure-transfer\client.py $args }

# Nu kun je:
transfer send file.txt
transfer receive 123456
```

**Linux/macOS (bash/zsh):**
```bash
# In ~/.bashrc of ~/.zshrc
alias tsend='~/secure-transfer/client.py send'
alias trecv='~/secure-transfer/client.py receive'

# Nu kun je:
tsend ~/file.pdf
trecv 123456
```

---

## Cheat Sheet

| Actie | iOS/Android | Windows | Linux/Mac |
|-------|-------------|---------|-----------|
| **Send** | Open app → Send → Pick file | `python client.py send file.txt` | `./client.py send file.txt` |
| **Receive** | Open app → Receive → Code | `python client.py receive CODE` | `./client.py receive CODE` |

**Server URL:** `http://192.168.1.x:8080` (vervang x met jouw IP)

---

## Troubleshooting

**"Cannot connect to server"**
- Check of Docker container draait: `docker ps`
- Ping het IP: `ping 192.168.1.100`
- Check firewall (poort 8080 open?)

**"Invalid pairing code"**
- Codes zijn 5 min geldig
- Let op typo's (cijfers only)
- Gebruik nieuwe transfer

**Windows: "python not found"**
- Installeer Python: https://www.python.org/downloads/
- Vink "Add Python to PATH" aan

**Linux: "Permission denied"**
```bash
chmod +x client.py
# OF gebruik: python3 client.py
```

---

## Next Steps

1. ✅ Lees [INSTALL.md](INSTALL.md) voor gedetailleerde setup per platform
2. ✅ Setup Tailscale voor remote toegang
3. ✅ Check [SECURITY.md](SECURITY.md) voor best practices

**Veel plezier met secure file sharing! 🎉**
