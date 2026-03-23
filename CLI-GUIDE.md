# CLI Versie - Gebruik

## Direct Python Gebruik (Zonder Docker)

### Installatie
```bash
pip install cryptography==41.0.7
chmod +x cli.py
```

### Bestand Versturen
```bash
# Start sender (genereert pairing code)
./cli.py send /pad/naar/bestand.txt

# Met custom port
./cli.py send /pad/naar/bestand.txt --port 9999

# Op specifiek interface
./cli.py send /pad/naar/bestand.txt --host 192.168.1.100
```

### Bestand Ontvangen
```bash
# Ontvang met pairing code
./cli.py receive 123456 --host 192.168.1.100

# Met custom output directory
./cli.py receive 123456 --host 192.168.1.100 --output /downloads

# Met custom port
./cli.py receive 123456 --host 192.168.1.100 --port 9999
```

## Docker CLI Gebruik

### Build CLI Image
```bash
docker build -f Dockerfile.cli -t secure-transfer-cli .
```

### Sender (Docker)
```bash
# Maak alias voor gemak
alias secure-send='docker run --rm -it \
    -v $(pwd)/input:/input:ro \
    -p 9999:9999 \
    --network host \
    secure-transfer-cli send'

# Gebruik
secure-send /input/bestand.txt
```

### Receiver (Docker)
```bash
# Maak alias
alias secure-recv='docker run --rm -it \
    -v $(pwd)/output:/output:rw \
    --network host \
    secure-transfer-cli receive'

# Gebruik
secure-recv 123456 --host 192.168.1.100 --output /output
```

## Network Scenarios

### Scenario 1: Zelfde netwerk (LAN)
```bash
# Systeem A (sender)
./cli.py send file.txt

# Systeem B (receiver) - gebruik LAN IP van A
./cli.py receive 123456 --host 192.168.1.100
```

### Scenario 2: Over VPN (Tailscale/WireGuard)
```bash
# Systeem A (sender) - bind op VPN interface
./cli.py send file.txt --host 100.64.x.x

# Systeem B (receiver) - connect naar VPN IP
./cli.py receive 123456 --host 100.64.x.x
```

### Scenario 3: Port Forwarding
```bash
# Systeem A (sender) - achter NAT
./cli.py send file.txt --port 9999

# Forward poort 9999 op router naar Systeem A

# Systeem B (receiver) - van internet
./cli.py receive 123456 --host jouw-publiek-ip.nl --port 9999
```

## UniFi Firewall Regels

Voor gebruik in jouw netwerk met UXG-Max:

```
# Allow inbound op poort 9999
Name: Secure File Transfer
Action: Accept
Protocol: TCP
Port: 9999
Source: Any (of specifiek IP bereik)
Destination: LAN
```

## Security Tips

1. **Gebruik binnen trusted network**
   - Alleen binnen LAN of VPN
   - Niet direct exposen naar internet

2. **Pairing code delen**
   - Via veilig kanaal (Signal, Telegram)
   - Niet via email/SMS

3. **Firewall tijdens transfer**
   ```bash
   # Open poort tijdelijk
   sudo ufw allow 9999/tcp
   
   # Na transfer
   sudo ufw delete allow 9999/tcp
   ```

4. **Monitor transfers**
   ```bash
   # Watch network traffic
   sudo tcpdump -i any port 9999
   
   # Monitor bandwidth
   iftop -f "port 9999"
   ```

## Troubleshooting

### "Connection refused"
```bash
# Check of sender draait
netstat -tlnp | grep 9999

# Check firewall
sudo ufw status
```

### "Hash mismatch"
```bash
# Mogelijk network corruption
# Retry transfer
# Check netwerk stabiliteit
```

### "Permission denied"
```bash
# Fix permissions
chmod 644 /pad/naar/bestand.txt
chmod 755 /output/directory
```

## Performance Tuning

### Grote bestanden (>1GB)
```bash
# Verhoog chunk size (edit cli.py)
self.chunk_size = 131072  # 128KB

# Gebruik op 10Gbit netwerk
self.chunk_size = 1048576  # 1MB
```

### LAN optimization
```bash
# Disable Nagle's algorithm voor betere latency
# Voeg toe aan cli.py in _handle_sender_client:
sock = writer.get_extra_info('socket')
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
```

## Automation Voorbeelden

### Batch transfers
```bash
#!/bin/bash
for file in /data/*.zip; do
    ./cli.py send "$file" --port 9999
    echo "Sent: $file"
    sleep 5
done
```

### Met notification
```bash
#!/bin/bash
./cli.py send file.txt && \
    notify-send "Transfer Complete" "File sent successfully"
```

### Scheduled transfer (cron)
```bash
# crontab -e
0 2 * * * /usr/local/bin/secure-transfer/cli.py send /backups/daily.tar.gz --host backup-server
```

## Integration met je Homelab

### Proxmox LXC container
```bash
# In container
apt update && apt install python3-pip
pip3 install cryptography
# Copy cli.py
chmod +x cli.py
```

### Systemd service voor permanente sender
```ini
[Unit]
Description=Secure Transfer Receiver
After=network.target

[Service]
Type=simple
User=transfer
ExecStart=/usr/bin/python3 /opt/secure-transfer/cli.py receive %i --output /data/received
Restart=always

[Install]
WantedBy=multi-user.target
```

### Met Portainer
```bash
# Deploy via Portainer Stack
# Gebruik docker-compose met CLI image
```
