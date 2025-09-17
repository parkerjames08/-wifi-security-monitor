#!/usr/bin/env python3
"""
Raspberry Pi Optimized WiFi Scanner
Hardware-specific optimizations for Raspberry Pi OS
"""
import os
import sys
import time
import json
import sqlite3
import subprocess
import threading
import logging
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import psutil

# Raspberry Pi specific imports
try:
    import RPi.GPIO as GPIO
    RPI_GPIO_AVAILABLE = True
except ImportError:
    RPI_GPIO_AVAILABLE = False

try:
    from gpiozero import LED
    GPIOZERO_AVAILABLE = True
except ImportError:
    GPIOZERO_AVAILABLE = False

@dataclass
class WiFiNetwork:
    """Enhanced WiFi network data structure for Raspberry Pi"""
    ssid: str
    bssid: str
    channel: int
    signal_strength: int
    encryption: str
    vendor: str
    first_seen: str
    last_seen: str
    packet_count: int = 0
    is_suspicious: bool = False
    threat_score: float = 0.0
    threat_reasons: List[str] = None
    detected_by_interface: str = ""
    hardware_flags: List[str] = None
    
    def __post_init__(self):
        if self.threat_reasons is None:
            self.threat_reasons = []
        if self.hardware_flags is None:
            self.hardware_flags = []

class RaspberryPiWiFiScanner:
    """Raspberry Pi optimized WiFi scanner with hardware integration"""
    
    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.networks = {}
        self.scanning = False
        self.temp_threshold = 80.0
        self.logger = logging.getLogger(__name__)
        
        self.init_raspberry_pi()
        self.setup_database()
        self.setup_hardware_monitoring()
        
    def init_raspberry_pi(self):
        """Initialize Raspberry Pi specific features"""
        try:
            self.setup_gpio()
            self.logger.info("Raspberry Pi features initialized")
        except Exception as e:
            self.logger.error(f"Error initializing Pi features: {e}")
    
    def setup_gpio(self):
        """Setup GPIO for LED indicators"""
        if GPIOZERO_AVAILABLE:
            try:
                self.status_led = LED(18)  # Green LED
                self.alert_led = LED(19)   # Red LED
                self.led_controller = "gpiozero"
                self.logger.info("GPIO LEDs initialized")
            except:
                self.led_controller = None
        else:
            self.led_controller = None
    
    def setup_database(self):
        """Initialize SQLite database"""
        self.conn = sqlite3.connect('rpi_wifi_security.db', check_same_thread=False)
        cursor = self.conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ssid TEXT,
                bssid TEXT UNIQUE,
                channel INTEGER,
                signal_strength INTEGER,
                encryption TEXT,
                vendor TEXT,
                first_seen TEXT,
                last_seen TEXT,
                packet_count INTEGER DEFAULT 0,
                is_suspicious BOOLEAN DEFAULT 0,
                threat_score REAL DEFAULT 0.0,
                threat_reasons TEXT,
                detected_by_interface TEXT,
                hardware_flags TEXT
            )
        ''')
        self.conn.commit()
    
    def setup_hardware_monitoring(self):
        """Setup hardware monitoring"""
        self.monitor_thread = threading.Thread(target=self.hardware_monitor_loop, daemon=True)
        self.monitor_thread.start()
    
    def hardware_monitor_loop(self):
        """Monitor hardware status"""
        while True:
            try:
                temp = self.get_cpu_temperature()
                if temp > self.temp_threshold and self.scanning:
                    self.logger.warning(f"High temperature: {temp:.1f}°C")
                    self.set_led_status("overheat")
                time.sleep(30)
            except:
                time.sleep(60)
    
    def get_cpu_temperature(self) -> float:
        """Get CPU temperature"""
        try:
            with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                temp = float(f.read()) / 1000.0
            return temp
        except:
            return 0.0
    
    def set_led_status(self, status: str):
        """Set LED status"""
        if not self.led_controller:
            return
        
        try:
            if status == "scanning":
                self.status_led.blink(on_time=0.5, off_time=0.5)
                self.alert_led.off()
            elif status == "alert":
                self.status_led.off()
                self.alert_led.on()
            elif status == "overheat":
                self.status_led.off()
                self.alert_led.blink(on_time=0.2, off_time=0.2)
            else:  # idle
                self.status_led.on()
                self.alert_led.off()
        except:
            pass
    
    def start_scanning(self, duration: int = 60):
        """Start WiFi scanning"""
        self.logger.info("Starting WiFi scanning...")
        self.scanning = True
        self.set_led_status("scanning")
        
        try:
            self.scan_with_iwlist(duration)
        except Exception as e:
            self.logger.error(f"Scanning error: {e}")
        finally:
            self.scanning = False
            self.set_led_status("idle")
    
    def scan_with_iwlist(self, duration: int):
        """Scan using iwlist command"""
        end_time = time.time() + duration
        
        while time.time() < end_time and self.scanning:
            try:
                result = subprocess.run(['sudo', 'iwlist', self.interface, 'scan'], 
                                      capture_output=True, text=True, check=True)
                self.parse_iwlist_output(result.stdout)
                time.sleep(5)
            except subprocess.CalledProcessError as e:
                self.logger.error(f"iwlist scan failed: {e}")
                break
    
    def parse_iwlist_output(self, output: str):
        """Parse iwlist scan output"""
        networks = []
        current_network = {}
        
        for line in output.split('\n'):
            line = line.strip()
            
            if 'Cell' in line and 'Address:' in line:
                if current_network:
                    networks.append(current_network)
                current_network = {'bssid': line.split('Address: ')[1]}
            elif 'ESSID:' in line:
                essid = line.split('ESSID:')[1].strip('"')
                current_network['ssid'] = essid
            elif 'Channel:' in line:
                import re
                channel = re.search(r'Channel:(\d+)', line)
                if channel:
                    current_network['channel'] = int(channel.group(1))
            elif 'Signal level=' in line:
                import re
                signal = re.search(r'Signal level=(-?\d+)', line)
                if signal:
                    current_network['signal_strength'] = int(signal.group(1))
            elif 'Encryption key:' in line:
                if 'off' in line:
                    current_network['encryption'] = 'Open'
                else:
                    current_network['encryption'] = 'WEP/WPA/WPA2'
        
        if current_network:
            networks.append(current_network)
        
        # Process networks
        current_time = datetime.now().isoformat()
        for net_data in networks:
            if 'bssid' in net_data:
                bssid = net_data['bssid']
                network = WiFiNetwork(
                    ssid=net_data.get('ssid', ''),
                    bssid=bssid,
                    channel=net_data.get('channel', 0),
                    signal_strength=net_data.get('signal_strength', -100),
                    encryption=net_data.get('encryption', 'Unknown'),
                    vendor='Unknown',
                    first_seen=current_time,
                    last_seen=current_time,
                    detected_by_interface=self.interface
                )
                
                self.networks[bssid] = network
                self.analyze_network_threats(network)
                self.save_network_to_db(network)
    
    def analyze_network_threats(self, network: WiFiNetwork):
        """Analyze network for threats"""
        threat_score = 0.0
        reasons = []
        
        if not network.ssid or network.ssid.strip() == "":
            threat_score += 20
            reasons.append("Hidden SSID")
        
        if network.encryption == "Open":
            threat_score += 25
            reasons.append("No encryption")
        
        if network.signal_strength > -25:
            threat_score += 30
            reasons.append("Very strong signal")
        
        suspicious_names = ['free wifi', 'public wifi', 'guest', 'internet']
        if any(name in network.ssid.lower() for name in suspicious_names):
            threat_score += 35
            reasons.append("Suspicious SSID")
        
        network.threat_score = min(threat_score, 100.0)
        network.threat_reasons = reasons
        network.is_suspicious = threat_score > 50
        
        if network.is_suspicious:
            self.set_led_status("alert")
    
    def save_network_to_db(self, network: WiFiNetwork):
        """Save network to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO networks 
                (ssid, bssid, channel, signal_strength, encryption, vendor, 
                 first_seen, last_seen, packet_count, is_suspicious, threat_score, 
                 threat_reasons, detected_by_interface, hardware_flags)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                network.ssid, network.bssid, network.channel, network.signal_strength,
                network.encryption, network.vendor, network.first_seen, network.last_seen,
                network.packet_count, network.is_suspicious, network.threat_score,
                json.dumps(network.threat_reasons), network.detected_by_interface,
                json.dumps(network.hardware_flags)
            ))
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Error saving network: {e}")
    
    def get_networks(self) -> List[Dict]:
        """Get all discovered networks"""
        return [asdict(network) for network in self.networks.values()]
    
    def get_hardware_status(self) -> Dict:
        """Get hardware status"""
        return {
            'cpu_temp': self.get_cpu_temperature(),
            'memory_usage': psutil.virtual_memory().percent,
            'cpu_usage': psutil.cpu_percent(),
            'scanning_active': self.scanning
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.scanning = False
        
        if self.led_controller and hasattr(self, 'status_led'):
            try:
                self.status_led.close()
                self.alert_led.close()
            except:
                pass
        
        if hasattr(self, 'conn'):
            self.conn.close()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Raspberry Pi WiFi Security Scanner")
    parser.add_argument('--interface', default='wlan0', help='WiFi interface')
    parser.add_argument('--duration', type=int, default=60, help='Scan duration')
    parser.add_argument('--verbose', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')
    
    scanner = RaspberryPiWiFiScanner(args.interface)
    
    try:
        print(f"🛡️  Starting Raspberry Pi WiFi Security Scan")
        print(f"Interface: {args.interface}, Duration: {args.duration}s")
        
        hw_status = scanner.get_hardware_status()
        print(f"CPU Temperature: {hw_status['cpu_temp']:.1f}°C")
        
        scanner.start_scanning(args.duration)
        
        networks = scanner.get_networks()
        suspicious = [n for n in networks if n['is_suspicious']]
        
        print(f"\nScan Results:")
        print(f"Total networks: {len(networks)}")
        print(f"Suspicious networks: {len(suspicious)}")
        
        if suspicious:
            print(f"\n🚨 Suspicious Networks:")
            for network in suspicious:
                print(f"  {network['ssid'] or '[Hidden]'} - Score: {network['threat_score']:.1f}%")
        
    except KeyboardInterrupt:
        print("\nScan interrupted")
    finally:
        scanner.cleanup()