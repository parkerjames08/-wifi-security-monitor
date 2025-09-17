#!/usr/bin/env python3
"""
WiFi Security Monitor - Main Application
Cybersecurity analysis tool for detecting fake WiFi networks and scams
"""
import os
import sys
import argparse
import logging
import signal
import time
from datetime import datetime
import threading
import json

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from wifi_scanner import WiFiScanner
from threat_detector import ThreatDetector
from app import app, socketio, init_services
import config

class WiFiSecurityMonitor:
    """Main application class"""
    
    def __init__(self):
        self.scanner = None
        self.detector = None
        self.running = False
        self.scan_thread = None
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=getattr(logging, config.LOG_LEVEL),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(config.LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def initialize(self):
        """Initialize components"""
        try:
            self.logger.info("Initializing WiFi Security Monitor...")
            
            # Check if running as root (required for monitor mode)
            if os.geteuid() != 0:
                self.logger.warning("Not running as root - some features may be limited")
            
            # Initialize scanner and detector
            self.scanner = WiFiScanner(config.WIFI_INTERFACE)
            self.detector = ThreatDetector(config.DATABASE_PATH)
            
            self.logger.info("Initialization complete")
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    def start_cli_mode(self, scan_duration=0, continuous=False):
        """Start in CLI mode"""
        self.logger.info("Starting CLI mode")
        
        if not self.initialize():
            return False
        
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            if continuous:
                self.logger.info("Starting continuous scanning mode")
                while self.running:
                    self.run_scan_cycle()
                    if self.running:
                        time.sleep(config.SCAN_INTERVAL)
            else:
                self.logger.info(f"Starting single scan (duration: {scan_duration}s)")
                self.run_scan_cycle(scan_duration)
                
        except KeyboardInterrupt:
            self.logger.info("Scan interrupted by user")
        finally:
            self.cleanup()
            
        return True
    
    def start_web_mode(self):
        """Start web dashboard mode"""
        self.logger.info("Starting web dashboard mode")
        
        if not self.initialize():
            return False
        
        try:
            # Initialize Flask services
            init_services()
            
            self.logger.info(f"Starting web server on {config.WEB_HOST}:{config.WEB_PORT}")
            socketio.run(app, host=config.WEB_HOST, port=config.WEB_PORT, debug=config.DEBUG)
            
        except Exception as e:
            self.logger.error(f"Web server error: {e}")
            return False
    
    def run_scan_cycle(self, duration=30):
        """Run a single scan cycle"""
        start_time = time.time()
        self.logger.info("Starting scan cycle...")
        
        # Clear previous results
        self.scanner.clear_networks()
        
        # Start scanning
        self.scanner.start_scanning(duration)
        
        # Get results
        networks = self.scanner.get_networks()
        suspicious = self.scanner.get_suspicious_networks()
        
        scan_time = time.time() - start_time
        
        # Display results
        self.display_results(networks, suspicious, scan_time)
        
        return len(networks), len(suspicious)
    
    def display_results(self, networks, suspicious, scan_time):
        """Display scan results in CLI"""
        print(f"\n{'='*60}")
        print(f"SCAN COMPLETE - Duration: {scan_time:.1f}s")
        print(f"{'='*60}")
        print(f"Total Networks Found: {len(networks)}")
        print(f"Suspicious Networks: {len(suspicious)}")
        print(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if suspicious:
            print(f"\n🚨 SUSPICIOUS NETWORKS DETECTED:")
            print("-" * 60)
            
            for network in suspicious:
                threat_level = "🔴 CRITICAL" if network['threat_score'] > 80 else \
                              "🟠 HIGH" if network['threat_score'] > 60 else \
                              "🟡 MEDIUM" if network['threat_score'] > 40 else \
                              "🟢 LOW"
                
                print(f"\n{threat_level} - Score: {network['threat_score']:.1f}%")
                print(f"SSID: {network['ssid'] or '[Hidden]'}")
                print(f"BSSID: {network['bssid']}")
                print(f"Channel: {network['channel']} | Signal: {network['signal_strength']} dBm")
                print(f"Encryption: {network['encryption']} | Vendor: {network['vendor']}")
                
                if network['threat_reasons']:
                    print("Threat Indicators:")
                    for reason in network['threat_reasons']:
                        print(f"  • {reason}")
        
        if networks and not suspicious:
            print(f"\n✅ No suspicious networks detected")
            print("All discovered networks appear legitimate")
        
        if networks:
            print(f"\nAll Networks:")
            print("-" * 40)
            for network in networks[:10]:  # Show first 10
                suspicious_marker = " 🚨" if network['is_suspicious'] else ""
                print(f"{network['ssid'] or '[Hidden]'} ({network['bssid']}) - {network['threat_score']:.1f}%{suspicious_marker}")
            
            if len(networks) > 10:
                print(f"... and {len(networks) - 10} more networks")
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        if self.scanner:
            self.scanner.stop_scanning()
    
    def cleanup(self):
        """Cleanup resources"""
        self.logger.info("Cleaning up...")
        if self.scanner:
            self.scanner.close()
        self.logger.info("Cleanup complete")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="WiFi Security Monitor - Detect fake WiFi networks and scams",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python wifi_monitor.py --web                 # Start web dashboard
  python wifi_monitor.py --cli --scan 60      # Single 60-second scan
  python wifi_monitor.py --cli --continuous   # Continuous scanning
  python wifi_monitor.py --interface wlan1    # Use specific interface
        """
    )
    
    parser.add_argument('--web', action='store_true', 
                       help='Start web dashboard mode')
    parser.add_argument('--cli', action='store_true',
                       help='Start CLI mode')
    parser.add_argument('--scan', type=int, default=30,
                       help='Scan duration in seconds (default: 30)')
    parser.add_argument('--continuous', action='store_true',
                       help='Continuous scanning mode')
    parser.add_argument('--interface', type=str, default=config.WIFI_INTERFACE,
                       help=f'WiFi interface to use (default: {config.WIFI_INTERFACE})')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Update config with CLI arguments
    if args.interface:
        config.WIFI_INTERFACE = args.interface
    if args.verbose:
        config.LOG_LEVEL = "DEBUG"
    
    # Create monitor instance
    monitor = WiFiSecurityMonitor()
    
    # Determine mode
    if args.web:
        success = monitor.start_web_mode()
    elif args.cli:
        success = monitor.start_cli_mode(args.scan, args.continuous)
    else:
        # Default to web mode
        print("WiFi Security Monitor")
        print("Starting web dashboard...")
        success = monitor.start_web_mode()
    
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())