#!/usr/bin/env python3
"""
WiFi Security Monitor - Demo Script
Quick demonstration of the cybersecurity analysis tool
"""

import sys
import os
import time
import json
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_banner():
    """Print application banner"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                    🛡️  WiFi Security Monitor                      ║
║              Cybersecurity Analysis Tool for Raspberry Pi        ║
║                                                                  ║
║         Detect Fake WiFi Networks and Scams in Your Area        ║
╚══════════════════════════════════════════════════════════════════╝
    """)

def demo_threat_detection():
    """Demonstrate threat detection capabilities"""
    print("🔍 Demonstrating Threat Detection Algorithms...")
    print("-" * 60)
    
    # Import threat detector
    try:
        from threat_detector import ThreatDetector
        detector = ThreatDetector()
        
        # Sample networks for demonstration
        demo_networks = [
            {
                'ssid': 'Home_WiFi',
                'bssid': '00:1A:2B:3C:4D:5E',
                'channel': 6,
                'signal_strength': -45,
                'encryption': 'WPA2',
                'vendor': 'Linksys',
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat()
            },
            {
                'ssid': 'Free WiFi',
                'bssid': '00:00:00:11:22:33',
                'channel': 11,
                'signal_strength': -20,
                'encryption': 'Open',
                'vendor': 'Unknown',
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat()
            },
            {
                'ssid': 'Starbucks_WiFi',
                'bssid': 'AA:BB:CC:DD:EE:FF',
                'channel': 1,
                'signal_strength': -30,
                'encryption': 'Open',
                'vendor': 'Private',
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat()
            },
            {
                'ssid': '',  # Hidden SSID
                'bssid': '12:34:56:78:90:AB',
                'channel': 6,
                'signal_strength': -15,
                'encryption': 'WEP',
                'vendor': 'Randomized',
                'first_seen': datetime.now().isoformat(),
                'last_seen': datetime.now().isoformat()
            }
        ]
        
        print("Analyzing sample networks...\n")
        
        for i, network in enumerate(demo_networks, 1):
            print(f"Network {i}: {network['ssid'] or '[Hidden]'}")
            
            # Generate threat report
            report = detector.generate_threat_report(network)
            
            # Display results
            threat_score = report['threat_assessment']['overall_score']
            severity = report['threat_assessment']['severity_level']
            is_suspicious = report['threat_assessment']['is_suspicious']
            
            if is_suspicious:
                print(f"  🚨 THREAT DETECTED - Score: {threat_score:.1f}% ({severity.upper()})")
                print(f"  📡 BSSID: {network['bssid']}")
                print(f"  📶 Signal: {network['signal_strength']} dBm")
                print(f"  🔒 Encryption: {network['encryption']}")
                
                print("  ⚠️  Threat Indicators:")
                for reason in report['threat_assessment']['threat_reasons']:
                    print(f"     • {reason}")
                
                print("  💡 Recommendations:")
                for rec in report['recommendations']:
                    print(f"     {rec}")
            else:
                print(f"  ✅ SAFE - Score: {threat_score:.1f}% (Low Risk)")
            
            print()
            
    except ImportError as e:
        print(f"❌ Error importing threat detector: {e}")
        return False
    except Exception as e:
        print(f"❌ Error during demonstration: {e}")
        return False
    
    return True

def demo_features():
    """Demonstrate key features"""
    print("\n🚀 Key Features of WiFi Security Monitor:")
    print("-" * 50)
    
    features = [
        "✅ Real-time WiFi network scanning",
        "✅ Advanced threat detection algorithms",
        "✅ Evil twin network identification", 
        "✅ Fake hotspot detection",
        "✅ Signal strength analysis",
        "✅ Encryption vulnerability assessment",
        "✅ Web-based dashboard interface",
        "✅ Command-line interface",
        "✅ Alert and notification system",
        "✅ Historical analysis and reporting",
        "✅ Raspberry Pi optimized",
        "✅ Easy installation and setup"
    ]
    
    for feature in features:
        print(f"  {feature}")
        time.sleep(0.1)  # Add small delay for effect

def show_usage_examples():
    """Show usage examples"""
    print("\n📖 Usage Examples:")
    print("-" * 30)
    
    examples = [
        ("🌐 Start Web Dashboard:", "python wifi_monitor.py --web"),
        ("🔍 Single Network Scan:", "python wifi_monitor.py --cli --scan 60"),
        ("⏰ Continuous Monitoring:", "python wifi_monitor.py --cli --continuous"),
        ("📡 Specific Interface:", "python wifi_monitor.py --interface wlan1 --cli"),
        ("🔧 Verbose Logging:", "python wifi_monitor.py --verbose --cli")
    ]
    
    for description, command in examples:
        print(f"  {description}")
        print(f"    {command}")
        print()

def main():
    """Main demo function"""
    print_banner()
    
    print("Welcome to the WiFi Security Monitor demonstration!")
    print("This tool helps you detect fake WiFi networks and potential scams.")
    print()
    
    # Show features
    demo_features()
    
    # Demonstrate threat detection
    print("\n" + "="*60)
    success = demo_threat_detection()
    
    if success:
        print("✅ Threat detection demonstration completed successfully!")
    else:
        print("⚠️  Threat detection demonstration encountered issues.")
    
    # Show usage examples
    show_usage_examples()
    
    print("🛡️  Installation Options:")
    print("-" * 25)
    print("  🐧 Raspberry Pi/Linux: sudo bash install.sh")
    print("  🪟 Windows: Run install.bat as Administrator")
    print()
    
    print("🔗 Quick Start:")
    print("-" * 15)
    print("  1. Install dependencies: pip install -r requirements.txt")
    print("  2. Start web interface: python wifi_monitor.py --web")
    print("  3. Open browser to: http://localhost:5000")
    print("  4. Click 'Start Scanning' to begin monitoring")
    print()
    
    print("⚠️  Important Security Notes:")
    print("-" * 30)
    print("  • Requires elevated privileges for WiFi monitoring")
    print("  • Tool only monitors networks, never connects")
    print("  • Use responsibly and comply with local laws")
    print("  • Report serious threats to authorities")
    print()
    
    print("📞 Support & Documentation:")
    print("-" * 30)
    print("  • README.md - Complete setup guide")
    print("  • config.py - Configuration options")
    print("  • GitHub Issues - Bug reports and features")
    print()
    
    print("Thank you for using WiFi Security Monitor! 🛡️")
    print("Stay secure and keep your network safe! 🔒")

if __name__ == "__main__":
    main()