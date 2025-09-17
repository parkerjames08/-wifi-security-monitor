"""
Configuration settings for WiFi Security Monitor
"""
import os

# Application settings
APP_NAME = "WiFi Security Monitor"
VERSION = "1.0.0"
DEBUG = True

# Network scanning settings
SCAN_INTERVAL = 30  # seconds
WIFI_INTERFACE = "wlan0"  # Default WiFi interface for Raspberry Pi
MONITOR_MODE_INTERFACE = "wlan0mon"

# Database settings
DATABASE_PATH = "wifi_security.db"
MAX_HISTORY_DAYS = 30

# Alert thresholds
SUSPICIOUS_SSID_THRESHOLD = 0.8  # Similarity threshold for fake APs
SIGNAL_STRENGTH_THRESHOLD = -30  # Very strong signals (possible evil twin)
ENCRYPTION_DOWNGRADE_ALERT = True
KNOWN_EVIL_TWINS_DB = "known_threats.json"

# Web interface settings
WEB_HOST = "0.0.0.0"
WEB_PORT = 5000
SECRET_KEY = "wifi-security-monitor-2024"

# Notification settings
ENABLE_EMAIL_ALERTS = False
EMAIL_SMTP_SERVER = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USERNAME = ""
EMAIL_PASSWORD = ""
EMAIL_RECIPIENTS = []

# Logging settings
LOG_LEVEL = "INFO"
LOG_FILE = "wifi_monitor.log"
MAX_LOG_SIZE = 10 * 1024 * 1024  # 10MB

# Detection patterns
SUSPICIOUS_SSIDS = [
    "Free WiFi",
    "Public WiFi",
    "Guest Network",
    "WiFi",
    "Internet",
    "Connection",
    "Network",
    ""  # Hidden/empty SSID
]

# Common legitimate network patterns to whitelist
LEGITIMATE_PATTERNS = [
    r".*_5G$",  # 5GHz networks
    r".*_2.4G$",  # 2.4GHz networks
    r".*-guest$",  # Official guest networks
]

# Vendor OUI database for MAC address analysis
VENDOR_OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"