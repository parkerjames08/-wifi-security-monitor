#!/bin/bash
# WiFi Security Monitor - Raspberry Pi OS Installer
# Optimized for Raspberry Pi OS (Bookworm) and newer
# Run with: curl -sSL https://raw.githubusercontent.com/your-repo/install.sh | sudo bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/wifi-security-monitor"
SERVICE_USER="wifimonitor"
LOG_DIR="/var/log/wifi-security-monitor"
CONFIG_DIR="/etc/wifi-security-monitor"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                    🛡️  WiFi Security Monitor                      ║"
    echo "║              Raspberry Pi Cybersecurity Analysis Tool           ║"
    echo "║                                                                  ║"
    echo "║         Detect Fake WiFi Networks and Scams in Your Area        ║"
    echo "║                  Optimized for Raspberry Pi OS                   ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

check_requirements() {
    log "Checking system requirements..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
        exit 1
    fi
    
    # Check if running on Raspberry Pi
    if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null; then
        warn "This doesn't appear to be a Raspberry Pi. Some features may not work optimally."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Detect Raspberry Pi model
    if grep -q "Raspberry Pi" /proc/cpuinfo; then
        PI_MODEL=$(grep "Model" /proc/cpuinfo | cut -d':' -f2 | xargs)
        log "Detected: $PI_MODEL"
    fi
    
    # Check OS version
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        log "OS: $PRETTY_NAME"
        
        # Check if it's Raspberry Pi OS
        if [[ ! "$ID" == "debian" ]] && [[ ! "$NAME" =~ "Raspberry Pi OS" ]]; then
            warn "This installer is optimized for Raspberry Pi OS (Debian-based)"
        fi
    fi
    
    # Check available memory
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [[ $TOTAL_MEM -lt 512 ]]; then
        warn "Low memory detected ($TOTAL_MEM MB). Performance may be limited."
    else
        log "Memory: ${TOTAL_MEM} MB - OK"
    fi
    
    # Check WiFi interface
    WIFI_INTERFACES=$(ls /sys/class/net/ | grep -E '^wl' || true)
    if [[ -z "$WIFI_INTERFACES" ]]; then
        error "No WiFi interface detected. Please ensure WiFi is enabled."
        exit 1
    else
        log "WiFi interfaces found: $WIFI_INTERFACES"
    fi
}

update_system() {
    log "Updating system packages..."
    
    # Update package lists
    apt update
    
    # Upgrade existing packages
    apt upgrade -y
    
    # Install firmware updates for Raspberry Pi
    if command -v rpi-update >/dev/null 2>&1; then
        log "Updating Raspberry Pi firmware..."
        rpi-update
    fi
}

install_dependencies() {
    log "Installing system dependencies..."
    
    # Essential packages for Raspberry Pi
    PACKAGES=(
        # Python and development tools
        python3
        python3-pip
        python3-venv
        python3-dev
        python3-setuptools
        python3-wheel
        
        # WiFi and networking tools
        wireless-tools
        aircrack-ng
        iw
        net-tools
        hostapd
        dnsmasq
        iptables
        
        # System tools
        sqlite3
        git
        curl
        wget
        nano
        htop
        
        # Build tools
        build-essential
        cmake
        pkg-config
        
        # Libraries
        libpcap-dev
        libffi-dev
        libssl-dev
        libjpeg-dev
        libfreetype6-dev
        
        # Hardware-specific for Raspberry Pi
        raspberrypi-kernel-headers
        
        # Optional GUI tools
        chromium-browser
        xdg-utils
    )
    
    # Install packages with error handling
    for package in "${PACKAGES[@]}"; do
        if apt-cache show "$package" >/dev/null 2>&1; then
            apt install -y "$package" || warn "Failed to install $package"
        else
            warn "Package $package not available"
        fi
    done
    
    # Enable SPI and I2C (useful for hardware expansion)
    log "Enabling hardware interfaces..."
    raspi-config nonint do_spi 0
    raspi-config nonint do_i2c 0
    
    success "System dependencies installed"
}

setup_python_environment() {
    log "Setting up Python environment..."
    
    # Upgrade pip
    python3 -m pip install --upgrade pip
    
    # Install Python packages
    log "Installing Python dependencies..."
    
    # Create temporary requirements file with Raspberry Pi optimizations
    cat > /tmp/rpi_requirements.txt << EOF
# Core dependencies
scapy==2.5.0
flask==2.3.2
flask-socketio==5.3.4
netifaces==0.11.0
psutil==5.9.5
requests==2.31.0
numpy==1.24.3
pandas==2.0.3
python-nmap==0.7.1
colorama==0.4.6
click==8.1.3
schedule==1.2.0
cryptography==41.0.3

# Raspberry Pi specific
RPi.GPIO==0.7.1
gpiozero==1.6.2
w1thermsensor==2.0.0

# Optional GUI dependencies
matplotlib==3.7.1

# System monitoring
py-cpuinfo==9.0.0
EOF
    
    # Install with optimizations for Raspberry Pi
    pip3 install -r /tmp/rpi_requirements.txt --no-cache-dir
    
    # Clean up
    rm /tmp/rpi_requirements.txt
    
    success "Python environment configured"
}

create_system_user() {
    log "Creating system user and directories..."
    
    # Create service user
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
        log "Created user: $SERVICE_USER"
    fi
    
    # Create directories
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "/home/pi/.local/share/wifi-security-monitor"
    
    # Set permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
    chown -R pi:pi "/home/pi/.local/share/wifi-security-monitor"
    
    success "System user and directories created"
}

install_application() {
    log "Installing WiFi Security Monitor application..."
    
    # Copy application files
    if [[ -f "$SCRIPT_DIR/wifi_monitor.py" ]]; then
        cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
    else
        error "Application files not found in $SCRIPT_DIR"
        exit 1
    fi
    
    # Make scripts executable
    chmod +x "$INSTALL_DIR/wifi_monitor.py"
    chmod +x "$INSTALL_DIR/rpi_installer.sh"
    
    # Create Raspberry Pi specific configuration
    cat > "$CONFIG_DIR/rpi_config.py" << EOF
# Raspberry Pi Specific Configuration
import os

# Hardware settings
RPI_MODEL = "$(grep "Model" /proc/cpuinfo | cut -d':' -f2 | xargs || echo "Unknown")"
CPU_TEMP_PATH = "/sys/class/thermal/thermal_zone0/temp"
GPIO_AVAILABLE = True

# WiFi interface detection
WIFI_INTERFACES = [
    "wlan0",    # Built-in WiFi
    "wlan1",    # USB WiFi adapter
    "wlx*"      # USB WiFi with MAC-based naming
]

# Performance settings based on Pi model
if "Pi 4" in RPI_MODEL or "Pi 5" in RPI_MODEL:
    SCAN_THREADS = 4
    MAX_CONCURRENT_SCANS = 2
    BUFFER_SIZE = 2048
elif "Pi 3" in RPI_MODEL:
    SCAN_THREADS = 2
    MAX_CONCURRENT_SCANS = 1
    BUFFER_SIZE = 1024
else:
    SCAN_THREADS = 1
    MAX_CONCURRENT_SCANS = 1
    BUFFER_SIZE = 512

# Display settings for different setups
ENABLE_HDMI_OUTPUT = True
ENABLE_SSH_ACCESS = True
AUTO_START_ON_BOOT = True

# LED indicators (if available)
STATUS_LED_PIN = 18
ALERT_LED_PIN = 19
ENABLE_LED_INDICATORS = True

# Power management
ENABLE_POWER_SAVING = False
CPU_GOVERNOR = "performance"  # or "powersave"
EOF
    
    # Update main config to include Raspberry Pi settings
    cat >> "$INSTALL_DIR/config.py" << EOF

# Import Raspberry Pi specific settings
try:
    import sys
    sys.path.append('$CONFIG_DIR')
    from rpi_config import *
    RPI_MODE = True
except ImportError:
    RPI_MODE = False
EOF
    
    success "Application installed"
}

setup_systemd_service() {
    log "Setting up systemd service..."
    
    # Create systemd service file optimized for Raspberry Pi
    cat > /etc/systemd/system/wifi-security-monitor.service << EOF
[Unit]
Description=WiFi Security Monitor - Raspberry Pi Cybersecurity Tool
Documentation=file://$INSTALL_DIR/README.md
After=network-online.target
Wants=network-online.target
Requires=multi-user.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PYTHONPATH=$INSTALL_DIR
Environment=PYTHONUNBUFFERED=1
ExecStartPre=/bin/sleep 10
ExecStart=/usr/bin/python3 $INSTALL_DIR/wifi_monitor.py --web --rpi-mode
Restart=always
RestartSec=10
TimeoutStartSec=60
TimeoutStopSec=30

# Resource limits for Raspberry Pi
MemoryLimit=256M
CPUQuota=80%

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR $LOG_DIR /tmp

# Capabilities needed for WiFi monitoring
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable and configure service
    systemctl daemon-reload
    systemctl enable wifi-security-monitor
    
    success "Systemd service configured"
}

setup_wifi_monitoring() {
    log "Configuring WiFi monitoring capabilities..."
    
    # Create WiFi interface management script
    cat > "$INSTALL_DIR/manage_wifi.sh" << 'EOF'
#!/bin/bash
# WiFi Interface Management for Raspberry Pi

INTERFACE=${1:-wlan0}
ACTION=${2:-status}

case $ACTION in
    "monitor")
        echo "Enabling monitor mode on $INTERFACE..."
        ip link set $INTERFACE down
        iw $INTERFACE set type monitor
        ip link set $INTERFACE up
        echo "Monitor mode enabled"
        ;;
    "managed")
        echo "Enabling managed mode on $INTERFACE..."
        ip link set $INTERFACE down
        iw $INTERFACE set type managed
        ip link set $INTERFACE up
        systemctl restart NetworkManager
        echo "Managed mode enabled"
        ;;
    "status")
        echo "Interface: $INTERFACE"
        iw $INTERFACE info 2>/dev/null || echo "Interface not found"
        ;;
    *)
        echo "Usage: $0 <interface> <monitor|managed|status>"
        ;;
esac
EOF
    
    chmod +x "$INSTALL_DIR/manage_wifi.sh"
    
    # Create udev rules for USB WiFi adapters
    cat > /etc/udev/rules.d/99-wifi-security-monitor.rules << EOF
# USB WiFi adapter rules for WiFi Security Monitor
SUBSYSTEM=="net", ACTION=="add", ATTRS{idVendor}=="148f", ATTRS{idProduct}=="3070", NAME="wlan-rt3070"
SUBSYSTEM=="net", ACTION=="add", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="8187", NAME="wlan-rtl8187"
SUBSYSTEM=="net", ACTION=="add", ATTRS{idVendor}=="148f", ATTRS{idProduct}=="5370", NAME="wlan-rt5370"
EOF
    
    # Reload udev rules
    udevadm control --reload-rules
    
    success "WiFi monitoring configured"
}

setup_web_interface() {
    log "Setting up web interface..."
    
    # Create nginx configuration for better performance
    if command -v nginx >/dev/null 2>&1; then
        cat > /etc/nginx/sites-available/wifi-security-monitor << EOF
server {
    listen 80;
    server_name localhost $(hostname).local;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
    
    location /static {
        alias $INSTALL_DIR/static;
        expires 1d;
        add_header Cache-Control "public, immutable";
    }
}
EOF
        
        # Enable site
        ln -sf /etc/nginx/sites-available/wifi-security-monitor /etc/nginx/sites-enabled/
        systemctl reload nginx 2>/dev/null || true
    fi
    
    # Create desktop environment integration
    if [[ -d "/home/pi/Desktop" ]]; then
        cat > "/home/pi/Desktop/WiFi Security Monitor.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=WiFi Security Monitor
Comment=Monitor for fake WiFi networks and cybersecurity threats
Exec=chromium-browser --new-window http://localhost:5000
Icon=$INSTALL_DIR/static/icon.png
Terminal=false
Categories=Network;Security;System;
StartupNotify=true
EOF
        
        chmod +x "/home/pi/Desktop/WiFi Security Monitor.desktop"
        chown pi:pi "/home/pi/Desktop/WiFi Security Monitor.desktop"
    fi
    
    success "Web interface configured"
}

setup_hardware_features() {
    log "Configuring Raspberry Pi hardware features..."
    
    # Create LED status indicators script
    cat > "$INSTALL_DIR/led_status.py" << 'EOF'
#!/usr/bin/env python3
"""
LED Status Indicators for Raspberry Pi
"""
try:
    import RPi.GPIO as GPIO
    import time
    import sys
    
    # LED pin configuration
    STATUS_LED = 18  # Green LED
    ALERT_LED = 19   # Red LED
    
    def setup_leds():
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(STATUS_LED, GPIO.OUT)
        GPIO.setup(ALERT_LED, GPIO.OUT)
        
        # Turn off both LEDs initially
        GPIO.output(STATUS_LED, GPIO.LOW)
        GPIO.output(ALERT_LED, GPIO.LOW)
    
    def status_normal():
        """Steady green light"""
        GPIO.output(STATUS_LED, GPIO.HIGH)
        GPIO.output(ALERT_LED, GPIO.LOW)
    
    def status_scanning():
        """Blinking green light"""
        GPIO.output(STATUS_LED, GPIO.HIGH)
        time.sleep(0.5)
        GPIO.output(STATUS_LED, GPIO.LOW)
        time.sleep(0.5)
    
    def status_alert():
        """Steady red light"""
        GPIO.output(STATUS_LED, GPIO.LOW)
        GPIO.output(ALERT_LED, GPIO.HIGH)
    
    def status_critical():
        """Blinking red light"""
        GPIO.output(STATUS_LED, GPIO.LOW)
        for _ in range(5):
            GPIO.output(ALERT_LED, GPIO.HIGH)
            time.sleep(0.2)
            GPIO.output(ALERT_LED, GPIO.LOW)
            time.sleep(0.2)
    
    def cleanup():
        GPIO.cleanup()
    
    if __name__ == "__main__":
        if len(sys.argv) < 2:
            print("Usage: led_status.py <normal|scanning|alert|critical|off>")
            sys.exit(1)
        
        setup_leds()
        
        try:
            action = sys.argv[1].lower()
            if action == "normal":
                status_normal()
            elif action == "scanning":
                for _ in range(10):  # Blink for 10 seconds
                    status_scanning()
            elif action == "alert":
                status_alert()
            elif action == "critical":
                status_critical()
            elif action == "off":
                cleanup()
            else:
                print(f"Unknown action: {action}")
        except KeyboardInterrupt:
            cleanup()

except ImportError:
    print("RPi.GPIO not available - LED functionality disabled")
EOF
    
    chmod +x "$INSTALL_DIR/led_status.py"
    
    # CPU temperature monitoring
    cat > "$INSTALL_DIR/temp_monitor.py" << 'EOF'
#!/usr/bin/env python3
"""
Temperature monitoring for Raspberry Pi
"""
import time

def get_cpu_temp():
    """Get CPU temperature in Celsius"""
    try:
        with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
            temp = float(f.read()) / 1000.0
        return temp
    except:
        return None

def check_thermal_throttling():
    """Check if thermal throttling is active"""
    try:
        with open('/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq', 'r') as f:
            current_freq = int(f.read())
        with open('/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq', 'r') as f:
            max_freq = int(f.read())
        
        return current_freq < max_freq * 0.8  # Throttled if <80% of max
    except:
        return False

if __name__ == "__main__":
    temp = get_cpu_temp()
    throttled = check_thermal_throttling()
    
    print(f"CPU Temperature: {temp:.1f}°C")
    print(f"Thermal Throttling: {'Yes' if throttled else 'No'}")
    
    if temp and temp > 80:
        print("⚠️  High temperature detected!")
    if throttled:
        print("⚠️  Performance may be reduced due to thermal throttling")
EOF
    
    chmod +x "$INSTALL_DIR/temp_monitor.py"
    
    success "Hardware features configured"
}

create_cli_tools() {
    log "Creating command-line tools..."
    
    # Main CLI wrapper
    cat > /usr/local/bin/wifi-security-monitor << EOF
#!/bin/bash
# WiFi Security Monitor CLI wrapper for Raspberry Pi

cd "$INSTALL_DIR"
python3 wifi_monitor.py "\$@"
EOF
    
    # System status tool
    cat > /usr/local/bin/wifi-monitor-status << EOF
#!/bin/bash
# WiFi Security Monitor status tool

echo "🛡️  WiFi Security Monitor - System Status"
echo "========================================"
echo

# Service status
echo "📋 Service Status:"
systemctl is-active wifi-security-monitor >/dev/null 2>&1 && echo "  ✅ Service: Running" || echo "  ❌ Service: Stopped"

# System info
echo "💻 System Information:"
echo "  Model: \$(grep "Model" /proc/cpuinfo | cut -d':' -f2 | xargs 2>/dev/null || echo "Unknown")"
echo "  OS: \$(lsb_release -ds 2>/dev/null || echo "Unknown")"
echo "  Uptime: \$(uptime -p)"

# Temperature
if [[ -f "$INSTALL_DIR/temp_monitor.py" ]]; then
    echo "🌡️  Temperature:"
    python3 "$INSTALL_DIR/temp_monitor.py" | sed 's/^/  /'
fi

# Memory usage
echo "💾 Memory Usage:"
free -h | awk 'NR==2{printf "  Used: %s/%s (%.1f%%)\n", \$3, \$2, \$3/\$2*100}'

# WiFi interfaces
echo "📡 WiFi Interfaces:"
for iface in \$(ls /sys/class/net/ | grep -E '^wl'); do
    status=\$(cat "/sys/class/net/\$iface/operstate" 2>/dev/null || echo "unknown")
    echo "  \$iface: \$status"
done

# Recent alerts
if [[ -f "$INSTALL_DIR/alerts.json" ]]; then
    echo "🚨 Recent Alerts:"
    python3 -c "
import json
from datetime import datetime, timedelta
try:
    with open('$INSTALL_DIR/alerts.json', 'r') as f:
        alerts = json.load(f)
    recent = [a for a in alerts if datetime.fromisoformat(a['timestamp']) > datetime.now() - timedelta(hours=24)]
    print(f'  Last 24h: {len(recent)} alerts')
    if recent:
        latest = max(recent, key=lambda x: x['timestamp'])
        print(f'  Latest: {latest[\"severity\"]} threat at {latest[\"timestamp\"]}')
except:
    print('  No alerts found')
"
fi

echo
echo "🔗 Web Interface: http://localhost:5000"
echo "📖 Logs: journalctl -u wifi-security-monitor -f"
EOF
    
    chmod +x /usr/local/bin/wifi-security-monitor
    chmod +x /usr/local/bin/wifi-monitor-status
    
    success "CLI tools created"
}

finalize_installation() {
    log "Finalizing installation..."
    
    # Set final permissions
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod -R 755 "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR"/*.py
    
    # Start the service
    log "Starting WiFi Security Monitor service..."
    systemctl start wifi-security-monitor
    
    # Wait for service to start
    sleep 5
    
    # Check service status
    if systemctl is-active wifi-security-monitor >/dev/null 2>&1; then
        success "Service started successfully"
    else
        error "Service failed to start. Check logs with: journalctl -u wifi-security-monitor"
    fi
    
    # Create quick start guide
    cat > "/home/pi/WiFi-Security-Monitor-QuickStart.txt" << EOF
🛡️  WiFi Security Monitor - Quick Start Guide
============================================

🚀 Getting Started:
1. Web Interface: http://localhost:5000
2. Status Check: wifi-monitor-status
3. CLI Scan: sudo wifi-security-monitor --cli --scan 60

📋 Service Management:
- Start: sudo systemctl start wifi-security-monitor
- Stop: sudo systemctl stop wifi-security-monitor  
- Status: sudo systemctl status wifi-security-monitor
- Logs: sudo journalctl -u wifi-security-monitor -f

🔧 Configuration:
- Main config: $INSTALL_DIR/config.py
- Raspberry Pi config: $CONFIG_DIR/rpi_config.py

📖 Documentation: $INSTALL_DIR/README.md

⚠️  Important Notes:
- Requires sudo for WiFi monitoring
- May temporarily affect WiFi connectivity during scans
- Monitor CPU temperature during intensive scanning

🆘 Support:
- Check system status: wifi-monitor-status
- View logs: journalctl -u wifi-security-monitor
- Temperature monitoring: python3 $INSTALL_DIR/temp_monitor.py
EOF
    
    chown pi:pi "/home/pi/WiFi-Security-Monitor-QuickStart.txt"
    
    success "Installation completed successfully!"
}

print_summary() {
    echo
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                   🎉 Installation Complete! 🎉                   ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
    success "WiFi Security Monitor is now installed and running!"
    echo
    echo -e "${BLUE}📋 What's been installed:${NC}"
    echo "  ✅ WiFi Security Monitor service (auto-starts on boot)"
    echo "  ✅ Web dashboard: http://localhost:5000"
    echo "  ✅ CLI tools: wifi-security-monitor, wifi-monitor-status"
    echo "  ✅ Desktop shortcut (if GUI available)"
    echo "  ✅ Raspberry Pi hardware optimizations"
    echo "  ✅ LED status indicators (if GPIO available)"
    echo "  ✅ Temperature monitoring"
    echo
    echo -e "${BLUE}🚀 Quick Start:${NC}"
    echo "  🌐 Open browser to: http://localhost:5000"
    echo "  📊 Check status: wifi-monitor-status"
    echo "  🔍 CLI scan: sudo wifi-security-monitor --cli --scan 60"
    echo "  📖 Quick guide: ~/WiFi-Security-Monitor-QuickStart.txt"
    echo
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo "  • Requires sudo privileges for WiFi monitor mode"
    echo "  • Monitor CPU temperature during intensive operations"
    echo "  • May temporarily disconnect WiFi during scans"
    echo "  • Configure WiFi interface in $CONFIG_DIR/rpi_config.py"
    echo
    echo -e "${GREEN}🎯 Next Steps:${NC}"
    echo "  1. Open the web interface and start your first scan"
    echo "  2. Review the configuration files"
    echo "  3. Set up email alerts if desired"
    echo "  4. Check the documentation for advanced features"
    echo
    echo -e "${PURPLE}📞 Support:${NC}"
    echo "  • System status: wifi-monitor-status"
    echo "  • Service logs: sudo journalctl -u wifi-security-monitor -f"
    echo "  • Documentation: $INSTALL_DIR/README.md"
    echo
    echo -e "${GREEN}Happy monitoring! Stay secure! 🛡️${NC}"
}

# Main installation flow
main() {
    print_banner
    
    log "Starting WiFi Security Monitor installation for Raspberry Pi..."
    
    check_requirements
    update_system
    install_dependencies
    setup_python_environment
    create_system_user
    install_application
    setup_systemd_service
    setup_wifi_monitoring
    setup_web_interface
    setup_hardware_features
    create_cli_tools
    finalize_installation
    
    print_summary
}

# Run installation
main "$@"