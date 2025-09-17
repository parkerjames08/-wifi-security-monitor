# WiFi Security Monitor

A comprehensive cybersecurity analysis tool for Raspberry Pi to detect fake WiFi networks, evil twins, and potential scams in your area.

## 🛡️ Features

- **Real-time WiFi Network Scanning**: Monitor all WiFi networks in your vicinity
- **Fake Access Point Detection**: Advanced algorithms to detect evil twin attacks
- **Threat Scoring System**: Intelligent risk assessment for each network
- **Web Dashboard**: User-friendly interface for real-time monitoring
- **Alert System**: Immediate notifications for suspicious networks
- **Historical Analysis**: Track network behavior over time
- **CLI Interface**: Command-line tools for advanced users

## 🚀 Quick Start

### Prerequisites
- Raspberry Pi (any model with WiFi)
- Raspberry Pi OS (Bullseye or newer)
- Root access for WiFi monitor mode

### Installation

1. **Download and install:**
```bash
git clone https://github.com/your-repo/wifi-security-monitor.git
cd wifi-security-monitor
sudo bash install.sh
```

2. **Access the web dashboard:**
   - Open browser to `http://localhost:5000`
   - Or click the desktop shortcut

3. **Start scanning:**
   - Click "Start Scanning" in the web interface
   - Or use CLI: `sudo wifi-security-monitor --cli --scan 60`

## 📊 How It Works

### Threat Detection Algorithms

The tool uses multiple detection methods:

1. **SSID Analysis**: Detects suspicious network names
2. **Evil Twin Detection**: Identifies networks similar to legitimate ones
3. **Signal Strength Analysis**: Flags unusually strong signals
4. **MAC Address Patterns**: Checks for manipulated hardware addresses
5. **Encryption Analysis**: Identifies weak or missing encryption
6. **Behavioral Patterns**: Monitors network appearance timing

### Threat Scoring

Networks receive threat scores (0-100%):
- **0-20%**: Low risk (green)
- **21-40%**: Medium risk (yellow)
- **41-60%**: High risk (orange)  
- **61-100%**: Critical risk (red)

## 🖥️ Usage

### Web Interface

1. **Dashboard**: Overview of network status and threats
2. **Network List**: Detailed view of all discovered networks
3. **Threat Analysis**: In-depth analysis of suspicious networks
4. **Statistics**: Historical scanning data and trends

### Command Line Interface

```bash
# Single scan
sudo wifi-security-monitor --cli --scan 60

# Continuous monitoring
sudo wifi-security-monitor --cli --continuous

# Use specific WiFi interface
sudo wifi-security-monitor --interface wlan1 --cli

# Web dashboard mode
sudo wifi-security-monitor --web
```

### Service Management

```bash
# Check service status
sudo systemctl status wifi-security-monitor

# Stop service
sudo systemctl stop wifi-security-monitor

# Start service
sudo systemctl start wifi-security-monitor

# View logs
sudo journalctl -u wifi-security-monitor -f
```

## ⚙️ Configuration

Edit `/opt/wifi-security-monitor/config.py` to customize:

```python
# WiFi interface settings
WIFI_INTERFACE = "wlan0"
SCAN_INTERVAL = 30  # seconds

# Alert thresholds
SUSPICIOUS_SSID_THRESHOLD = 0.8
SIGNAL_STRENGTH_THRESHOLD = -30

# Web interface
WEB_HOST = "0.0.0.0"
WEB_PORT = 5000
```

## 🔍 Understanding Threats

### Common Attack Patterns Detected

1. **Evil Twin Networks**
   - Networks with names similar to legitimate ones
   - Same SSID as known networks but different BSSID

2. **Fake Hotspots**
   - Generic names like "Free WiFi", "Public WiFi"
   - Open networks in suspicious locations

3. **Signal Anomalies**
   - Unusually strong signals (possible proximity attacks)
   - Multiple networks with identical signal strength

4. **Suspicious Characteristics**
   - Hidden SSIDs with no encryption
   - Networks appearing only at night
   - MAC addresses with suspicious patterns

## 📱 Recommendations

When the tool detects threats:

- **Critical (80-100%)**: Do not connect under any circumstances
- **High (60-79%)**: Avoid connection, use VPN if absolutely necessary
- **Medium (40-59%)**: Exercise caution, verify network authenticity
- **Low (20-39%)**: Generally safe but remain vigilant

## 🛠️ Troubleshooting

### Common Issues

1. **"Permission denied" errors**
   - Ensure running with `sudo`
   - Check WiFi interface name in config

2. **No networks detected**
   - Verify WiFi interface is active: `iwconfig`
   - Try different interface: `--interface wlan1`

3. **Web dashboard not accessible**
   - Check service status: `systemctl status wifi-security-monitor`
   - Verify port 5000 is not blocked

4. **Monitor mode fails**
   - Stop NetworkManager: `sudo systemctl stop NetworkManager`
   - Manually enable: `sudo iwconfig wlan0 mode monitor`

### Logs and Debugging

```bash
# View application logs
tail -f /var/log/wifi-security-monitor/wifi_monitor.log

# Enable debug logging
sudo wifi-security-monitor --verbose --cli

# Check system logs
sudo journalctl -u wifi-security-monitor
```

## 🔒 Security Considerations

- **Root Privileges**: Required for WiFi monitor mode
- **Network Interruption**: Scanning may temporarily disconnect WiFi
- **Privacy**: Tool only monitors, never connects to networks
- **Data Storage**: Network data stored locally in SQLite database

## 🤝 Contributing

Contributions welcome! Please read our contributing guidelines and submit pull requests.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and defensive security purposes only. Users are responsible for complying with local laws and regulations regarding WiFi monitoring.

## 📞 Support

- GitHub Issues: Report bugs and feature requests
- Documentation: See `/opt/wifi-security-monitor/docs/`
- Community: Join our security community discussions

---

**Stay secure! 🛡️**
