"""
WiFi Network Scanner Module
Handles network discovery and monitoring
"""
import time
import json
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
import subprocess
import re
import logging
from dataclasses import dataclass, asdict
from scapy.all import *
import netifaces
import psutil

@dataclass
class WiFiNetwork:
    """WiFi network data structure"""
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

    def __post_init__(self):
        if self.threat_reasons is None:
            self.threat_reasons = []

class WiFiScanner:
    """Main WiFi scanning and analysis class"""
    
    def __init__(self, interface: str = "wlan0"):
        self.interface = interface
        self.networks = {}
        self.known_networks = set()
        self.scanning = False
        self.logger = logging.getLogger(__name__)
        self.setup_database()
        self.load_vendor_database()
        
    def setup_database(self):
        """Initialize SQLite database for storing network data"""
        self.conn = sqlite3.connect('wifi_security.db', check_same_thread=False)
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
                threat_reasons TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                networks_found INTEGER,
                suspicious_count INTEGER,
                scan_duration REAL
            )
        ''')
        
        self.conn.commit()
    
    def load_vendor_database(self):
        """Load MAC address vendor database"""
        self.vendor_db = {}
        try:
            # Try to load local vendor database
            with open('vendor_db.json', 'r') as f:
                self.vendor_db = json.load(f)
        except FileNotFoundError:
            self.logger.warning("Vendor database not found, will use unknown vendors")
    
    def get_vendor_from_mac(self, mac_address: str) -> str:
        """Get vendor from MAC address OUI"""
        if not mac_address or len(mac_address) < 8:
            return "Unknown"
        
        oui = mac_address[:8].upper().replace(':', '')
        return self.vendor_db.get(oui, "Unknown")
    
    def start_monitor_mode(self) -> bool:
        """Enable monitor mode on WiFi interface"""
        try:
            # Stop NetworkManager to avoid conflicts
            subprocess.run(['sudo', 'systemctl', 'stop', 'NetworkManager'], 
                         capture_output=True, check=False)
            
            # Bring interface down
            subprocess.run(['sudo', 'ifconfig', self.interface, 'down'], 
                         capture_output=True, check=True)
            
            # Set monitor mode
            subprocess.run(['sudo', 'iwconfig', self.interface, 'mode', 'monitor'], 
                         capture_output=True, check=True)
            
            # Bring interface up
            subprocess.run(['sudo', 'ifconfig', self.interface, 'up'], 
                         capture_output=True, check=True)
            
            self.logger.info(f"Monitor mode enabled on {self.interface}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to enable monitor mode: {e}")
            return False
    
    def stop_monitor_mode(self):
        """Disable monitor mode and restore managed mode"""
        try:
            # Bring interface down
            subprocess.run(['sudo', 'ifconfig', self.interface, 'down'], 
                         capture_output=True, check=True)
            
            # Set managed mode
            subprocess.run(['sudo', 'iwconfig', self.interface, 'mode', 'managed'], 
                         capture_output=True, check=True)
            
            # Bring interface up
            subprocess.run(['sudo', 'ifconfig', self.interface, 'up'], 
                         capture_output=True, check=True)
            
            # Restart NetworkManager
            subprocess.run(['sudo', 'systemctl', 'start', 'NetworkManager'], 
                         capture_output=True, check=False)
            
            self.logger.info(f"Monitor mode disabled on {self.interface}")
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to disable monitor mode: {e}")
    
    def packet_handler(self, packet):
        """Handle captured WiFi packets"""
        if packet.haslayer(Dot11):
            if packet.type == 0 and packet.subtype == 8:  # Beacon frame
                self.process_beacon_frame(packet)
            elif packet.type == 0 and packet.subtype == 4:  # Probe request
                self.process_probe_request(packet)
    
    def process_beacon_frame(self, packet):
        """Process beacon frames to discover networks"""
        try:
            bssid = packet[Dot11].addr2
            if not bssid:
                return
            
            ssid = ""
            channel = 0
            encryption = "Open"
            
            # Extract SSID
            if packet.haslayer(Dot11Elt):
                ssid_layer = packet[Dot11Elt]
                if ssid_layer.ID == 0:  # SSID element
                    ssid = ssid_layer.info.decode('utf-8', errors='ignore')
            
            # Extract channel
            if packet.haslayer(Dot11Elt):
                elt = packet[Dot11Elt]
                while elt:
                    if elt.ID == 3:  # DS Parameter set
                        channel = elt.info[0] if elt.info else 0
                        break
                    elt = elt.payload.getlayer(Dot11Elt)
            
            # Determine encryption
            cap = packet[Dot11Beacon].cap
            if cap & 0x10:  # Privacy bit set
                encryption = "WEP/WPA/WPA2"
                if packet.haslayer(RSNinfo):
                    encryption = "WPA2"
                elif packet.sprintf("%Dot11Beacon.cap%").find("privacy") != -1:
                    encryption = "WEP"
            
            # Get signal strength
            signal_strength = -(256 - packet[RadioTap].dBm_AntSignal) if packet.haslayer(RadioTap) else -100
            
            # Get vendor
            vendor = self.get_vendor_from_mac(bssid)
            
            # Create or update network entry
            current_time = datetime.now().isoformat()
            
            if bssid in self.networks:
                network = self.networks[bssid]
                network.last_seen = current_time
                network.packet_count += 1
                network.signal_strength = max(network.signal_strength, signal_strength)
            else:
                network = WiFiNetwork(
                    ssid=ssid,
                    bssid=bssid,
                    channel=channel,
                    signal_strength=signal_strength,
                    encryption=encryption,
                    vendor=vendor,
                    first_seen=current_time,
                    last_seen=current_time,
                    packet_count=1
                )
                self.networks[bssid] = network
                
                # Analyze for threats
                self.analyze_network_threats(network)
                
                # Save to database
                self.save_network_to_db(network)
            
        except Exception as e:
            self.logger.error(f"Error processing beacon frame: {e}")
    
    def process_probe_request(self, packet):
        """Process probe request frames"""
        # This can be used to detect devices searching for specific networks
        pass
    
    def analyze_network_threats(self, network: WiFiNetwork):
        """Analyze network for potential threats"""
        threat_score = 0.0
        reasons = []
        
        # Check for suspicious SSID patterns
        if self.is_suspicious_ssid(network.ssid):
            threat_score += 30
            reasons.append("Suspicious SSID pattern")
        
        # Check for very strong signal (possible evil twin)
        if network.signal_strength > -30:
            threat_score += 25
            reasons.append("Unusually strong signal strength")
        
        # Check for hidden SSID
        if not network.ssid or network.ssid.strip() == "":
            threat_score += 15
            reasons.append("Hidden SSID")
        
        # Check for open network in suspicious locations
        if network.encryption == "Open":
            threat_score += 20
            reasons.append("Open network (no encryption)")
        
        # Check for similar SSIDs to known legitimate networks
        similar_networks = self.find_similar_networks(network.ssid)
        if similar_networks:
            threat_score += 40
            reasons.append(f"Similar to legitimate network: {similar_networks[0]}")
        
        # Check vendor patterns
        if self.is_suspicious_vendor(network.vendor):
            threat_score += 15
            reasons.append("Suspicious device vendor")
        
        network.threat_score = min(threat_score, 100.0)
        network.threat_reasons = reasons
        network.is_suspicious = threat_score > 50
    
    def is_suspicious_ssid(self, ssid: str) -> bool:
        """Check if SSID matches suspicious patterns"""
        if not ssid:
            return True
        
        suspicious_patterns = [
            "free wifi", "public wifi", "guest", "internet", "connection",
            "network", "wifi", "hotspot", "login", "setup", "configure"
        ]
        
        ssid_lower = ssid.lower()
        return any(pattern in ssid_lower for pattern in suspicious_patterns)
    
    def find_similar_networks(self, ssid: str) -> List[str]:
        """Find networks with similar SSIDs (potential evil twins)"""
        if not ssid:
            return []
        
        similar = []
        for known_ssid in self.known_networks:
            if known_ssid != ssid and self.calculate_similarity(ssid, known_ssid) > 0.8:
                similar.append(known_ssid)
        
        return similar
    
    def calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate string similarity using simple method"""
        if not str1 or not str2:
            return 0.0
        
        longer = str1 if len(str1) > len(str2) else str2
        shorter = str2 if len(str1) > len(str2) else str1
        
        if len(longer) == 0:
            return 1.0
        
        matches = sum(1 for i, char in enumerate(shorter) if i < len(longer) and char == longer[i])
        return matches / len(longer)
    
    def is_suspicious_vendor(self, vendor: str) -> bool:
        """Check if vendor is known to be suspicious"""
        suspicious_vendors = [
            "Unknown", "Private", "Randomized", "Local"
        ]
        return vendor in suspicious_vendors
    
    def save_network_to_db(self, network: WiFiNetwork):
        """Save network data to database"""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO networks 
                (ssid, bssid, channel, signal_strength, encryption, vendor, 
                 first_seen, last_seen, packet_count, is_suspicious, threat_score, threat_reasons)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                network.ssid, network.bssid, network.channel, network.signal_strength,
                network.encryption, network.vendor, network.first_seen, network.last_seen,
                network.packet_count, network.is_suspicious, network.threat_score,
                json.dumps(network.threat_reasons)
            ))
            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Error saving network to database: {e}")
    
    def start_scanning(self, duration: int = 0):
        """Start WiFi scanning"""
        self.logger.info("Starting WiFi scanning...")
        self.scanning = True
        
        try:
            if not self.start_monitor_mode():
                self.logger.error("Failed to start monitor mode, using regular scanning")
                return self.scan_networks_regular()
            
            start_time = time.time()
            
            # Start packet capture
            sniff(iface=self.interface, prn=self.packet_handler, 
                  timeout=duration if duration > 0 else None,
                  stop_filter=lambda x: not self.scanning)
            
            scan_duration = time.time() - start_time
            
            # Log scan results
            suspicious_count = sum(1 for net in self.networks.values() if net.is_suspicious)
            
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO scan_history (timestamp, networks_found, suspicious_count, scan_duration)
                VALUES (?, ?, ?, ?)
            ''', (datetime.now().isoformat(), len(self.networks), suspicious_count, scan_duration))
            self.conn.commit()
            
            self.logger.info(f"Scan completed: {len(self.networks)} networks found, {suspicious_count} suspicious")
            
        except Exception as e:
            self.logger.error(f"Error during scanning: {e}")
        finally:
            self.stop_monitor_mode()
            self.scanning = False
    
    def scan_networks_regular(self):
        """Fallback scanning method without monitor mode"""
        try:
            # Use iwlist to scan networks
            result = subprocess.run(['sudo', 'iwlist', self.interface, 'scan'], 
                                  capture_output=True, text=True, check=True)
            
            self.parse_iwlist_output(result.stdout)
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Regular scan failed: {e}")
    
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
                channel = re.search(r'Channel:(\d+)', line)
                if channel:
                    current_network['channel'] = int(channel.group(1))
            
            elif 'Signal level=' in line:
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
        
        # Process discovered networks
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
                    vendor=self.get_vendor_from_mac(bssid),
                    first_seen=current_time,
                    last_seen=current_time
                )
                
                self.networks[bssid] = network
                self.analyze_network_threats(network)
                self.save_network_to_db(network)
    
    def stop_scanning(self):
        """Stop WiFi scanning"""
        self.scanning = False
        self.logger.info("WiFi scanning stopped")
    
    def get_networks(self) -> List[Dict]:
        """Get all discovered networks"""
        return [asdict(network) for network in self.networks.values()]
    
    def get_suspicious_networks(self) -> List[Dict]:
        """Get only suspicious networks"""
        return [asdict(network) for network in self.networks.values() if network.is_suspicious]
    
    def clear_networks(self):
        """Clear network cache"""
        self.networks.clear()
    
    def close(self):
        """Close database connection"""
        if hasattr(self, 'conn'):
            self.conn.close()

if __name__ == "__main__":
    # Test the scanner
    logging.basicConfig(level=logging.INFO)
    scanner = WiFiScanner()
    
    try:
        print("Starting WiFi scan for 30 seconds...")
        scanner.start_scanning(30)
        
        networks = scanner.get_networks()
        suspicious = scanner.get_suspicious_networks()
        
        print(f"\nFound {len(networks)} networks:")
        for network in networks:
            print(f"  {network['ssid']} ({network['bssid']}) - Threat Score: {network['threat_score']}")
        
        print(f"\nSuspicious networks ({len(suspicious)}):")
        for network in suspicious:
            print(f"  ⚠️  {network['ssid']} ({network['bssid']})")
            print(f"     Reasons: {', '.join(network['threat_reasons'])}")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
    finally:
        scanner.close()