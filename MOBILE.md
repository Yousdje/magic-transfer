# Mobile Installation Instructions

## iPhone/iPad (iOS)

### Direct via Browser
1. Open **Safari**
2. Navigate to: `http://daggertooth-daggertooth.ts.net:8080`
3. Use the web interface directly

### Install as App (Recommended)
1. Open **Safari**
2. Navigate to: `http://daggertooth-daggertooth.ts.net:8080`
3. Tap the **Share** button (square with arrow pointing up)
4. Scroll down and tap **"Add to Home Screen"**
5. Edit name to "Secure Transfer" (optional)
6. Tap **"Add"**

✅ **Now you have an app icon on your home screen!**

### Requirements
- Tailscale app installed and connected
- iOS 15 or later
- Safari browser (for PWA installation)

---

## Android

### Direct via Browser
1. Open **Chrome**
2. Navigate to: `http://daggertooth-daggertooth.ts.net:8080`
3. Use the web interface directly

### Install as App (Recommended)
1. Open **Chrome**
2. Navigate to: `http://daggertooth-daggertooth.ts.net:8080`
3. Tap the **⋮** menu (three dots in top-right)
4. Tap **"Install app"** or **"Add to Home screen"**
5. Tap **"Install"**

✅ **Now you have an app in your app drawer!**

### Requirements
- Tailscale app installed and connected
- Android 8 or later
- Chrome browser (for PWA installation)

---

## Using the App

### Send a File
1. Open the Secure Transfer app
2. Tap **"Send"** tab
3. Tap the upload area or drag a file
4. Select file from your device
5. Tap **"Upload & Generate Code"**
6. Share the 6-digit code with the recipient

### Receive a File
1. Open the Secure Transfer app
2. Tap **"Receive"** tab
3. Enter the 6-digit pairing code
4. Tap **"Connect & Download"**
5. File downloads to your device

---

## Tips for Mobile

### iOS Tips
- **File Access**: Downloads go to Files app → Downloads folder
- **Large Files**: Use WiFi for files >100MB
- **Background**: Keep Tailscale app running in background
- **Privacy**: Use Safari Private Browsing for extra privacy
- **Shortcuts**: Create Siri Shortcut to open app quickly

### Android Tips
- **File Access**: Downloads go to Downloads folder
- **Permissions**: Grant Chrome storage permission when prompted
- **Battery**: Disable battery optimization for Tailscale
- **Quick Access**: Add Quick Settings tile for Tailscale
- **File Manager**: Use any file manager to access downloads

---

## Network Settings

### Always-On VPN (Recommended)

**iOS:**
1. Settings → General → VPN & Device Management
2. Enable "Connect On Demand" for Tailscale
3. Now Tailscale auto-connects when needed

**Android:**
1. Settings → Network & Internet → VPN
2. Tap Tailscale → Settings ⚙️
3. Enable "Always-on VPN"
4. Enable "Block connections without VPN"

This ensures secure access even when switching networks!

---

## Troubleshooting Mobile

### "Cannot open page" or "Server not found"
✅ **Fix:**
1. Open Tailscale app
2. Ensure you're connected (blue checkmark)
3. Try again

### "Connection timeout"
✅ **Fix:**
1. Check if server is running: `http://192.168.1.30:8080/health`
2. Restart Tailscale app
3. Toggle airplane mode on/off

### "Download failed"
✅ **Fix (iOS):**
1. Settings → Safari → Downloads
2. Change download location to "On My iPhone"

✅ **Fix (Android):**
1. Chrome → Settings → Site Settings → Storage
2. Clear cache for the site
3. Grant storage permissions

### "App icon disappeared"
- iOS: Re-add via Safari Share menu
- Android: Reinstall from Chrome menu

---

## QR Code Access

For easy sharing with others, create a QR code:

```
URL: http://daggertooth-daggertooth.ts.net:8080
```

Use any QR code generator with this URL, then:
- Print it
- Save to photos
- Share via messaging

Scan with camera app → Opens in browser → Install as app!

---

## Comparison: Native Browser vs PWA

| Feature | Browser | PWA (Installed) |
|---------|---------|-----------------|
| Bookmark needed | Yes | No, has icon |
| Full screen | No | Yes |
| Splash screen | No | Yes |
| Background | No | Limited |
| Notifications | Limited | Better |
| Speed | Good | Better (cached) |

**Recommendation:** Always install as PWA for best experience!

---

## Security Notes for Mobile

1. **Only use via Tailscale** when outside home network
2. **Don't share pairing codes** via SMS or public channels
3. **Use Signal/WhatsApp** for sharing codes
4. **Enable Touch/Face ID** for Tailscale app
5. **Clear browser cache** after sensitive transfers

---

## Quick Reference

**Server URLs:**
- Tailscale: `http://daggertooth-daggertooth.ts.net:8080`
- LAN only: `http://192.168.1.30:8080`

**Pairing Codes:**
- 6 digits
- Valid for 5 minutes
- One-time use

**File Size Limits:**
- Technical: 10GB max
- Practical: WiFi recommended for >100MB
- Mobile data: Keep under 50MB

---

Need help? Check the full [TAILSCALE.md](TAILSCALE.md) guide!
