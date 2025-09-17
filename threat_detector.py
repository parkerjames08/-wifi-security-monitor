"""
Advanced Threat Detection and Analysis Module
Specialized algorithms for detecting fake WiFi networks and scams
"""
import json
import math
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Tuple, Set
from dataclasses import dataclass
import re
import logging
from collections import defaultdict, Counter
import numpy as np

@dataclass
class ThreatPattern:
    """Threat pattern definition"""
    name: str
    description: str
    weight: float
    pattern_type: str  # 'ssid', 'mac', 'behavior', 'signal'
    pattern_data: Dict
    severity: str  # 'low', 'medium', 'high', 'critical'

class ThreatDetector:
    """Advanced threat detection system"""
    
    def __init__(self, db_path: str = "wifi_security.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.threat_patterns = []
        self.legitimate_networks = set()
        self.known_evil_twins = {}
        self.load_threat_patterns()
        self.load_known_networks()
        
    def load_threat_patterns(self):
        """Load predefined threat detection patterns"""
        self.threat_patterns = [
            # Evil Twin Patterns
            ThreatPattern(
                name="Evil Twin SSID",
                description="SSID similar to legitimate networks",
                weight=40.0,
                pattern_type="ssid",
                pattern_data={"similarity_threshold": 0.85},
                severity="high"
            ),
            
            # Suspicious SSID Patterns
            ThreatPattern(
                name="Generic Free WiFi",
                description="Generic free WiFi names often used in attacks",
                weight=35.0,
                pattern_type="ssid",
                pattern_data={
                    "patterns": [
                        r"free.*wifi", r"public.*wifi", r"guest.*network",
                        r"^wifi$", r"^internet$", r"^connection$",
                        r"hotel.*wifi", r"airport.*wifi", r"starbucks.*wifi"
                    ]
                },
                severity="medium"
            ),
            
            ThreatPattern(
                name="Suspicious Characters",
                description="SSID contains suspicious characters or encoding",
                weight=25.0,
                pattern_type="ssid",
                pattern_data={
                    "patterns": [
                        r"[^\x20-\x7E]",  # Non-printable characters
                        r"\\x[0-9a-fA-F]{2}",  # Hex encoding
                        r"[\u0000-\u001F]",  # Control characters
                    ]
                },
                severity="medium"
            ),
            
            # Signal Strength Patterns
            ThreatPattern(
                name="Unusually Strong Signal",
                description="Signal strength suggests proximity-based attack",
                weight=30.0,
                pattern_type="signal",
                pattern_data={"threshold": -25},
                severity="medium"
            ),
            
            ThreatPattern(
                name="Signal Strength Spoofing",
                description="Multiple networks with identical signal strength",
                weight=45.0,
                pattern_type="signal",
                pattern_data={"duplicate_threshold": 3},
                severity="high"
            ),
            
            # MAC Address Patterns
            ThreatPattern(
                name="MAC Address Manipulation",
                description="Suspicious MAC address patterns",
                weight=35.0,
                pattern_type="mac",
                pattern_data={
                    "patterns": [
                        r"^00:00:00:",  # Null MAC
                        r"^FF:FF:FF:",  # Broadcast MAC
                        r"^02:",        # Locally administered
                        r".*([0-9A-F]{2}:)\1{2,}"  # Repeated octets
                    ]
                },
                severity="medium"
            ),
            
            # Encryption Patterns
            ThreatPattern(
                name="Encryption Downgrade",
                description="Weak or no encryption on suspicious networks",
                weight=25.0,
                pattern_type="encryption",
                pattern_data={"weak_encryption": ["Open", "WEP"]},
                severity="medium"
            ),
            
            # Behavioral Patterns
            ThreatPattern(
                name="Rapid Appearance",
                description="Network appeared recently and matches suspicious patterns",
                weight=20.0,
                pattern_type="behavior",
                pattern_data={"time_threshold": 3600},  # 1 hour
                severity="low"
            ),
            
            ThreatPattern(
                name="Channel Overlap",
                description="Multiple suspicious networks on same channel",
                weight=30.0,
                pattern_type="behavior",
                pattern_data={"overlap_threshold": 2},
                severity="medium"
            ),
            
            # Captive Portal Patterns
            ThreatPattern(
                name="Fake Captive Portal",
                description="Network likely to have malicious captive portal",
                weight=50.0,
                pattern_type="behavior",
                pattern_data={
                    "indicators": [
                        "login", "signin", "auth", "portal", "access",
                        "hotspot", "wifi_login", "internet_access"
                    ]
                },
                severity="critical"
            )
        ]
    
    def load_known_networks(self):
        """Load known legitimate networks from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get networks that have been seen multiple times over days
            cursor.execute('''
                SELECT DISTINCT ssid FROM networks 
                WHERE datetime(first_seen) < datetime('now', '-24 hours')
                AND threat_score < 30
                AND ssid != ''
            ''')
            
            self.legitimate_networks = {row[0] for row in cursor.fetchall()}
            conn.close()
            
            self.logger.info(f"Loaded {len(self.legitimate_networks)} known legitimate networks")
            
        except Exception as e:
            self.logger.error(f"Error loading known networks: {e}")
    
    def analyze_network_threats(self, network_data: Dict) -> Tuple[float, List[str], str]:
        """
        Comprehensive threat analysis for a network
        Returns: (threat_score, threat_reasons, severity_level)
        """
        threat_score = 0.0
        threat_reasons = []
        max_severity = "low"
        
        for pattern in self.threat_patterns:
            score, reason = self.apply_threat_pattern(network_data, pattern)
            if score > 0:
                threat_score += score
                threat_reasons.append(reason)
                
                # Update max severity
                severities = {"low": 1, "medium": 2, "high": 3, "critical": 4}
                if severities[pattern.severity] > severities[max_severity]:
                    max_severity = pattern.severity
        
        # Apply additional contextual analysis
        context_score, context_reasons = self.analyze_context(network_data)
        threat_score += context_score
        threat_reasons.extend(context_reasons)
        
        # Normalize score (0-100)
        threat_score = min(threat_score, 100.0)
        
        return threat_score, threat_reasons, max_severity
    
    def apply_threat_pattern(self, network_data: Dict, pattern: ThreatPattern) -> Tuple[float, str]:
        """Apply a specific threat pattern to network data"""
        
        if pattern.pattern_type == "ssid":
            return self.check_ssid_patterns(network_data, pattern)
        elif pattern.pattern_type == "signal":
            return self.check_signal_patterns(network_data, pattern)
        elif pattern.pattern_type == "mac":
            return self.check_mac_patterns(network_data, pattern)
        elif pattern.pattern_type == "encryption":
            return self.check_encryption_patterns(network_data, pattern)
        elif pattern.pattern_type == "behavior":
            return self.check_behavioral_patterns(network_data, pattern)
        
        return 0.0, ""
    
    def check_ssid_patterns(self, network_data: Dict, pattern: ThreatPattern) -> Tuple[float, str]:
        """Check SSID-based threat patterns"""
        ssid = network_data.get('ssid', '').lower()
        
        if pattern.name == "Evil Twin SSID":
            similarity = self.find_evil_twin_similarity(network_data['ssid'])
            if similarity > pattern.pattern_data['similarity_threshold']:
                return pattern.weight, f"Similar to legitimate network (similarity: {similarity:.2f})"
        
        elif pattern.name == "Generic Free WiFi":
            for regex_pattern in pattern.pattern_data['patterns']:
                if re.search(regex_pattern, ssid, re.IGNORECASE):
                    return pattern.weight, f"Matches suspicious SSID pattern: {regex_pattern}"
        
        elif pattern.name == "Suspicious Characters":
            for regex_pattern in pattern.pattern_data['patterns']:
                if re.search(regex_pattern, network_data.get('ssid', '')):
                    return pattern.weight, "Contains suspicious characters"
        
        return 0.0, ""
    
    def check_signal_patterns(self, network_data: Dict, pattern: ThreatPattern) -> Tuple[float, str]:
        """Check signal-based threat patterns"""
        signal = network_data.get('signal_strength', -100)
        
        if pattern.name == "Unusually Strong Signal":
            if signal > pattern.pattern_data['threshold']:
                return pattern.weight, f"Unusually strong signal: {signal} dBm"
        
        elif pattern.name == "Signal Strength Spoofing":
            # Check for multiple networks with same signal strength
            duplicates = self.count_signal_duplicates(signal)
            if duplicates >= pattern.pattern_data['duplicate_threshold']:
                return pattern.weight, f"Signal strength duplicated across {duplicates} networks"
        
        return 0.0, ""
    
    def check_mac_patterns(self, network_data: Dict, pattern: ThreatPattern) -> Tuple[float, str]:
        """Check MAC address-based threat patterns"""
        mac = network_data.get('bssid', '').upper()
        
        if pattern.name == "MAC Address Manipulation":
            for regex_pattern in pattern.pattern_data['patterns']:
                if re.search(regex_pattern, mac):
                    return pattern.weight, f"Suspicious MAC pattern: {mac}"
        
        return 0.0, ""
    
    def check_encryption_patterns(self, network_data: Dict, pattern: ThreatPattern) -> Tuple[float, str]:
        """Check encryption-based threat patterns"""
        encryption = network_data.get('encryption', '')
        
        if pattern.name == "Encryption Downgrade":
            if encryption in pattern.pattern_data['weak_encryption']:
                return pattern.weight, f"Weak/no encryption: {encryption}"
        
        return 0.0, ""
    
    def check_behavioral_patterns(self, network_data: Dict, pattern: ThreatPattern) -> Tuple[float, str]:
        """Check behavioral threat patterns"""
        
        if pattern.name == "Rapid Appearance":
            first_seen = datetime.fromisoformat(network_data.get('first_seen', ''))
            age_seconds = (datetime.now() - first_seen).total_seconds()
            if age_seconds < pattern.pattern_data['time_threshold']:
                return pattern.weight, f"Recently appeared network ({age_seconds/60:.1f} minutes ago)"
        
        elif pattern.name == "Channel Overlap":
            overlapping = self.count_channel_overlap(network_data.get('channel', 0))
            if overlapping >= pattern.pattern_data['overlap_threshold']:
                return pattern.weight, f"Multiple suspicious networks on channel {network_data.get('channel')}"
        
        elif pattern.name == "Fake Captive Portal":
            ssid = network_data.get('ssid', '').lower()
            for indicator in pattern.pattern_data['indicators']:
                if indicator in ssid:
                    return pattern.weight, f"Likely fake captive portal (keyword: {indicator})"
        
        return 0.0, ""
    
    def find_evil_twin_similarity(self, ssid: str) -> float:
        """Find similarity to known legitimate networks"""
        if not ssid or ssid in self.legitimate_networks:
            return 0.0
        
        max_similarity = 0.0
        for legit_ssid in self.legitimate_networks:
            similarity = self.calculate_ssid_similarity(ssid, legit_ssid)
            max_similarity = max(max_similarity, similarity)
        
        return max_similarity
    
    def calculate_ssid_similarity(self, ssid1: str, ssid2: str) -> float:
        """Calculate similarity between two SSIDs using multiple methods"""
        if not ssid1 or not ssid2:
            return 0.0
        
        # Exact match
        if ssid1 == ssid2:
            return 1.0
        
        # Case-insensitive match
        if ssid1.lower() == ssid2.lower():
            return 0.95
        
        # Levenshtein distance similarity
        distance = self.levenshtein_distance(ssid1.lower(), ssid2.lower())
        max_len = max(len(ssid1), len(ssid2))
        if max_len == 0:
            return 0.0
        
        similarity = 1.0 - (distance / max_len)
        
        # Check for common typosquatting patterns
        typo_similarity = self.check_typosquatting(ssid1, ssid2)
        
        return max(similarity, typo_similarity)
    
    def levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def check_typosquatting(self, ssid1: str, ssid2: str) -> float:
        """Check for common typosquatting patterns"""
        s1, s2 = ssid1.lower(), ssid2.lower()
        
        # Character substitution patterns
        substitutions = {
            'o': '0', '0': 'o', 'i': '1', '1': 'i', 'l': '1',
            'e': '3', '3': 'e', 's': '5', '5': 's', 'a': '@'
        }
        
        # Check if one is a substitution of the other
        for char, replacement in substitutions.items():
            if s1.replace(char, replacement) == s2 or s2.replace(char, replacement) == s1:
                return 0.9
        
        # Check for missing/extra characters
        if len(s1) == len(s2) + 1:
            for i in range(len(s1)):
                if s1[:i] + s1[i+1:] == s2:
                    return 0.85
        
        return 0.0
    
    def count_signal_duplicates(self, signal_strength: int) -> int:
        """Count networks with identical signal strength"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM networks 
                WHERE signal_strength = ? 
                AND datetime(last_seen) > datetime('now', '-1 hour')
            ''', (signal_strength,))
            
            count = cursor.fetchone()[0]
            conn.close()
            return count
            
        except Exception as e:
            self.logger.error(f"Error counting signal duplicates: {e}")
            return 0
    
    def count_channel_overlap(self, channel: int) -> int:
        """Count suspicious networks on the same channel"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM networks 
                WHERE channel = ? 
                AND is_suspicious = 1
                AND datetime(last_seen) > datetime('now', '-1 hour')
            ''', (channel,))
            
            count = cursor.fetchone()[0]
            conn.close()
            return count
            
        except Exception as e:
            self.logger.error(f"Error counting channel overlap: {e}")
            return 0
    
    def analyze_context(self, network_data: Dict) -> Tuple[float, List[str]]:
        """Analyze contextual factors for threat assessment"""
        context_score = 0.0
        context_reasons = []
        
        # Check vendor reputation
        vendor_score, vendor_reason = self.analyze_vendor_reputation(network_data.get('vendor', ''))
        if vendor_score > 0:
            context_score += vendor_score
            context_reasons.append(vendor_reason)
        
        # Check geographic clustering
        cluster_score, cluster_reason = self.analyze_geographic_clustering(network_data)
        if cluster_score > 0:
            context_score += cluster_score
            context_reasons.append(cluster_reason)
        
        # Check time-based patterns
        time_score, time_reason = self.analyze_temporal_patterns(network_data)
        if time_score > 0:
            context_score += time_score
            context_reasons.append(time_reason)
        
        return context_score, context_reasons
    
    def analyze_vendor_reputation(self, vendor: str) -> Tuple[float, str]:
        """Analyze vendor reputation"""
        # Known suspicious/generic vendors
        suspicious_vendors = {
            'Unknown': 15.0,
            'Private': 10.0,
            'Randomized': 20.0,
            'Local': 15.0,
            'Generic': 10.0
        }
        
        if vendor in suspicious_vendors:
            return suspicious_vendors[vendor], f"Suspicious vendor: {vendor}"
        
        return 0.0, ""
    
    def analyze_geographic_clustering(self, network_data: Dict) -> Tuple[float, str]:
        """Analyze if network is part of suspicious clustering"""
        # This would require GPS/location data
        # For now, return basic clustering based on signal strength proximity
        return 0.0, ""
    
    def analyze_temporal_patterns(self, network_data: Dict) -> Tuple[float, str]:
        """Analyze temporal patterns"""
        try:
            first_seen = datetime.fromisoformat(network_data.get('first_seen', ''))
            current_time = datetime.now()
            
            # Check if network appeared during suspicious hours
            hour = first_seen.hour
            if 22 <= hour or hour <= 6:  # Late night/early morning
                return 10.0, "Appeared during suspicious hours (late night/early morning)"
            
            # Check if network appeared on weekend (common for targeted attacks)
            if first_seen.weekday() >= 5:  # Saturday = 5, Sunday = 6
                return 5.0, "Appeared on weekend"
            
        except Exception as e:
            self.logger.error(f"Error analyzing temporal patterns: {e}")
        
        return 0.0, ""
    
    def generate_threat_report(self, network_data: Dict) -> Dict:
        """Generate comprehensive threat report for a network"""
        threat_score, threat_reasons, severity = self.analyze_network_threats(network_data)
        
        # Get additional analysis
        vendor_analysis = self.analyze_vendor_reputation(network_data.get('vendor', ''))
        similarity_analysis = self.find_evil_twin_similarity(network_data.get('ssid', ''))
        
        report = {
            'network': network_data,
            'threat_assessment': {
                'overall_score': threat_score,
                'severity_level': severity,
                'is_suspicious': threat_score > 50,
                'threat_reasons': threat_reasons,
                'confidence': min(threat_score / 50.0, 1.0)  # Confidence 0-1
            },
            'detailed_analysis': {
                'vendor_risk': vendor_analysis[0],
                'evil_twin_similarity': similarity_analysis,
                'encryption_risk': self.assess_encryption_risk(network_data.get('encryption', '')),
                'signal_anomaly': self.assess_signal_anomaly(network_data.get('signal_strength', -100))
            },
            'recommendations': self.generate_recommendations(threat_score, threat_reasons),
            'timestamp': datetime.now().isoformat()
        }
        
        return report
    
    def assess_encryption_risk(self, encryption: str) -> str:
        """Assess encryption risk level"""
        risk_levels = {
            'Open': 'high',
            'WEP': 'high',
            'WPA': 'medium',
            'WPA2': 'low',
            'WPA3': 'very_low'
        }
        return risk_levels.get(encryption, 'unknown')
    
    def assess_signal_anomaly(self, signal_strength: int) -> str:
        """Assess signal strength anomaly"""
        if signal_strength > -25:
            return "extremely_strong"
        elif signal_strength > -40:
            return "very_strong"
        elif signal_strength > -60:
            return "normal"
        elif signal_strength > -80:
            return "weak"
        else:
            return "very_weak"
    
    def generate_recommendations(self, threat_score: float, threat_reasons: List[str]) -> List[str]:
        """Generate security recommendations based on threat analysis"""
        recommendations = []
        
        if threat_score > 80:
            recommendations.extend([
                "🚨 CRITICAL: Do not connect to this network under any circumstances",
                "🚨 Report this network to local authorities if in a public space",
                "🚨 Warn others about this potential threat"
            ])
        elif threat_score > 60:
            recommendations.extend([
                "⚠️ HIGH RISK: Avoid connecting to this network",
                "⚠️ If you must connect, use a VPN and avoid sensitive activities",
                "⚠️ Monitor for any suspicious activity"
            ])
        elif threat_score > 40:
            recommendations.extend([
                "⚠️ MEDIUM RISK: Exercise caution when connecting",
                "🔒 Use HTTPS websites only",
                "🔒 Consider using a VPN for additional protection"
            ])
        elif threat_score > 20:
            recommendations.extend([
                "ℹ️ LOW RISK: Generally safe but remain vigilant",
                "ℹ️ Verify network authenticity if possible"
            ])
        
        # Specific recommendations based on threat reasons
        if any("evil twin" in reason.lower() for reason in threat_reasons):
            recommendations.append("🔍 Verify with network administrator if this is legitimate")
        
        if any("open" in reason.lower() or "no encryption" in reason.lower() for reason in threat_reasons):
            recommendations.append("🔒 Avoid transmitting sensitive data over unencrypted connection")
        
        if any("captive portal" in reason.lower() for reason in threat_reasons):
            recommendations.append("🚫 Do not enter personal credentials on captive portal")
        
        return recommendations

# Example usage and testing
if __name__ == "__main__":
    detector = ThreatDetector()
    
    # Test with sample network data
    test_network = {
        'ssid': 'Free WiFi',
        'bssid': '00:00:00:11:22:33',
        'channel': 6,
        'signal_strength': -20,
        'encryption': 'Open',
        'vendor': 'Unknown',
        'first_seen': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat()
    }
    
    report = detector.generate_threat_report(test_network)
    print(json.dumps(report, indent=2))