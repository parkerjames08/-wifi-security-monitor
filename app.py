"""
Web Dashboard for WiFi Security Monitor
Real-time monitoring interface with threat visualization
"""
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import sqlite3
import threading
import time
from datetime import datetime
import logging
from wifi_scanner import WiFiScanner
from threat_detector import ThreatDetector
import config

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
scanner = None
detector = None
scanning_active = False

def init_services():
    """Initialize scanner and detector services"""
    global scanner, detector
    scanner = WiFiScanner(config.WIFI_INTERFACE)
    detector = ThreatDetector(config.DATABASE_PATH)

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/networks')
def get_networks():
    """Get all discovered networks"""
    try:
        conn = sqlite3.connect(config.DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT ssid, bssid, channel, signal_strength, encryption, vendor,
                   first_seen, last_seen, is_suspicious, threat_score, threat_reasons
            FROM networks ORDER BY threat_score DESC
        ''')
        
        networks = []
        for row in cursor.fetchall():
            networks.append({
                'ssid': row[0], 'bssid': row[1], 'channel': row[2],
                'signal_strength': row[3], 'encryption': row[4], 'vendor': row[5],
                'first_seen': row[6], 'last_seen': row[7], 'is_suspicious': bool(row[8]),
                'threat_score': row[9], 'threat_reasons': json.loads(row[10] or '[]')
            })
        
        conn.close()
        return jsonify(networks)
    except Exception as e:
        return jsonify([]), 500

@app.route('/api/start_scan')
def start_scan():
    """Start WiFi scanning"""
    global scanning_active
    if not scanning_active:
        scanning_active = True
        threading.Thread(target=run_scan, daemon=True).start()
        return jsonify({'status': 'started'})
    return jsonify({'status': 'already_running'})

@app.route('/api/stop_scan')
def stop_scan():
    """Stop WiFi scanning"""
    global scanning_active
    scanning_active = False
    if scanner:
        scanner.stop_scanning()
    return jsonify({'status': 'stopped'})

def run_scan():
    """Background scanning function"""
    global scanning_active
    while scanning_active:
        if scanner:
            scanner.start_scanning(30)  # 30 second scans
            socketio.emit('scan_update', {'networks': len(scanner.networks)})
        time.sleep(60)  # Wait 1 minute between scans

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('status', {'scanning': scanning_active})

if __name__ == '__main__':
    init_services()
    socketio.run(app, host=config.WEB_HOST, port=config.WEB_PORT, debug=config.DEBUG)