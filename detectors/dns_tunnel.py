"""
DNS Tunneling Detector Module
Detects potential DNS tunneling by analyzing DNS queries for suspicious patterns
"""

import time
import re
import math
from collections import defaultdict, deque
from scapy.all import DNS, DNSQR

class DNSTunnelDetector:
    """Detector for DNS tunneling attacks"""
    
    def __init__(self, analyzer):
        """Initialize the DNS tunneling detector"""
        self.analyzer = analyzer
        self.query_history = defaultdict(list)  # Maps source IPs to lists of query timestamps
        self.domain_history = defaultdict(int)  # Counts occurrences of domains
        self.last_alert_time = {}  # Tracks when alerts were last sent
        self.alert_cooldown = 60  # Seconds between repeated alerts
        
        # Sliding window of recent queries for entropy analysis
        self.recent_queries = deque(maxlen=100)
        
        # Thresholds
        self.max_subdomain_length = 40  # Maximum normal subdomain length
        self.max_query_rate = 10  # Maximum queries per second from a single source
        self.entropy_threshold = 4.0  # Entropy threshold for suspicious domains
        self.base64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
    
    def analyze(self, packet):
        """Analyze a packet for signs of DNS tunneling"""
        if not (DNS in packet and packet.haslayer(DNSQR)):
            return
        
        # Extract DNS query information
        qname = packet[DNSQR].qname.decode('utf-8', errors='ignore').lower()
        if not qname:
            return
            
        # Remove trailing dot if present
        if qname.endswith('.'):
            qname = qname[:-1]
            
        # Get source IP
        src_ip = None
        if packet.haslayer('IP'):
            src_ip = packet['IP'].src
        
        # Add to recent queries for entropy analysis
        self.recent_queries.append(qname)
        
        # Check for long subdomains
        self._check_subdomain_length(qname, src_ip, packet)
        
        # Check query frequency
        if src_ip:
            self._check_query_frequency(src_ip, packet)
        
        # Check for high entropy (randomness) in domain names
        self._check_domain_entropy(qname, packet)
        
        # Check for base64-encoded subdomains
        self._check_base64_encoding(qname, packet)
    
    def _check_subdomain_length(self, qname, src_ip, packet):
        """Check for unusually long subdomains"""
        parts = qname.split('.')
        
        for part in parts:
            if len(part) > self.max_subdomain_length:
                # Check if we've alerted about this domain recently
                current_time = time.time()
                alert_key = f"long_subdomain_{qname}"
                
                if alert_key not in self.last_alert_time or (current_time - self.last_alert_time[alert_key]) > self.alert_cooldown:
                    self.analyzer.add_alert(
                        "DNS Tunneling",
                        f"Unusually long subdomain detected: {qname}",
                        severity="medium",
                        packet=packet
                    )
                    self.last_alert_time[alert_key] = current_time
                break
    
    def _check_query_frequency(self, src_ip, packet):
        """Check for high frequency of DNS queries from a single source"""
        current_time = time.time()
        
        # Add current query timestamp
        self.query_history[src_ip].append(current_time)
        
        # Remove old timestamps (older than 10 seconds)
        self.query_history[src_ip] = [t for t in self.query_history[src_ip] if current_time - t <= 10]
        
        # Calculate query rate (queries per second)
        query_count = len(self.query_history[src_ip])
        if query_count >= 10:  # Only check if we have enough data
            time_span = current_time - min(self.query_history[src_ip])
            if time_span > 0:
                query_rate = query_count / time_span
                
                if query_rate > self.max_query_rate:
                    # Check if we've alerted about this IP recently
                    alert_key = f"high_frequency_{src_ip}"
                    
                    if alert_key not in self.last_alert_time or (current_time - self.last_alert_time[alert_key]) > self.alert_cooldown:
                        self.analyzer.add_alert(
                            "DNS Tunneling",
                            f"High DNS query rate detected from {src_ip}: {query_rate:.2f} queries/second",
                            severity="medium",
                            packet=packet
                        )
                        self.last_alert_time[alert_key] = current_time
    
    def _check_domain_entropy(self, qname, packet):
        """Check for high entropy (randomness) in domain names, which could indicate encoded data"""
        # Calculate Shannon entropy for the domain
        parts = qname.split('.')
        
        for part in parts:
            if len(part) >= 10:  # Only check longer subdomains
                entropy = self._calculate_entropy(part)
                
                if entropy > self.entropy_threshold:
                    # Check if we've alerted about this domain recently
                    current_time = time.time()
                    alert_key = f"high_entropy_{qname}"
                    
                    if alert_key not in self.last_alert_time or (current_time - self.last_alert_time[alert_key]) > self.alert_cooldown:
                        self.analyzer.add_alert(
                            "DNS Tunneling",
                            f"Suspicious high-entropy domain detected: {qname} (entropy: {entropy:.2f})",
                            severity="medium",
                            packet=packet
                        )
                        self.last_alert_time[alert_key] = current_time
                    break
    
    def _check_base64_encoding(self, qname, packet):
        """Check for base64-encoded subdomains, which are common in DNS tunneling"""
        parts = qname.split('.')
        
        for part in parts:
            if len(part) >= 16 and self.base64_pattern.match(part):
                # Check if we've alerted about this domain recently
                current_time = time.time()
                alert_key = f"base64_{qname}"
                
                if alert_key not in self.last_alert_time or (current_time - self.last_alert_time[alert_key]) > self.alert_cooldown:
                    self.analyzer.add_alert(
                        "DNS Tunneling",
                        f"Possible base64-encoded DNS tunneling detected: {qname}",
                        severity="high",
                        packet=packet
                    )
                    self.last_alert_time[alert_key] = current_time
                break
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy for a string"""
        if not text:
            return 0
            
        entropy = 0
        text_len = len(text)
        
        # Count character frequencies
        char_count = defaultdict(int)
        for char in text:
            char_count[char] += 1
        
        # Calculate entropy
        for count in char_count.values():
            probability = count / text_len
            entropy -= probability * math.log2(probability)
            
        return entropy