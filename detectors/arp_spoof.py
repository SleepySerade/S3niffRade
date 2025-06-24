"""
ARP Spoofing Detector Module
Detects potential ARP spoofing/poisoning attacks by monitoring for inconsistent ARP mappings
"""

import time
from collections import defaultdict
from scapy.all import ARP

class ARPSpoofDetector:
    """Detector for ARP spoofing attacks"""
    
    def __init__(self, analyzer):
        """Initialize the ARP spoofing detector"""
        self.analyzer = analyzer
        self.ip_mac_mapping = {}  # Maps IP addresses to MAC addresses
        self.mac_ip_mapping = defaultdict(set)  # Maps MAC addresses to sets of IP addresses
        self.last_alert_time = {}  # Tracks when alerts were last sent for specific IPs
        self.alert_cooldown = 60  # Seconds between repeated alerts for the same IP
    
    def analyze(self, packet):
        """Analyze a packet for signs of ARP spoofing"""
        if ARP not in packet:
            return
        
        # Extract information from the ARP packet
        arp = packet[ARP]
        src_ip = arp.psrc
        src_mac = arp.hwsrc
        dst_ip = arp.pdst
        
        # Ignore empty or broadcast addresses
        if not src_ip or not src_mac or src_ip == "0.0.0.0" or src_mac == "00:00:00:00:00:00":
            return
        
        # Check for ARP poisoning
        self._check_arp_poisoning(src_ip, src_mac, packet)
        
        # Check for multiple IPs associated with a single MAC (potential sign of spoofing)
        self._check_multiple_ips_per_mac(src_mac, src_ip, packet)
    
    def _check_arp_poisoning(self, ip, mac, packet):
        """Check if an IP address has changed its associated MAC address"""
        if ip in self.ip_mac_mapping and self.ip_mac_mapping[ip] != mac:
            # IP address has changed its MAC - potential ARP poisoning
            old_mac = self.ip_mac_mapping[ip]
            
            # Check if we've alerted about this IP recently
            current_time = time.time()
            if ip not in self.last_alert_time or (current_time - self.last_alert_time[ip]) > self.alert_cooldown:
                self.analyzer.add_alert(
                    "ARP Spoofing",
                    f"Possible ARP poisoning detected: IP {ip} changed MAC from {old_mac} to {mac}",
                    severity="high",
                    packet=packet
                )
                self.last_alert_time[ip] = current_time
        
        # Update the mappings
        self.ip_mac_mapping[ip] = mac
        self.mac_ip_mapping[mac].add(ip)
    
    def _check_multiple_ips_per_mac(self, mac, new_ip, packet):
        """Check if a MAC address is associated with multiple IP addresses"""
        # If this MAC has more than 3 IPs associated with it, it might be suspicious
        if len(self.mac_ip_mapping[mac]) > 3:
            # Check if we've alerted about this MAC recently
            current_time = time.time()
            if mac not in self.last_alert_time or (current_time - self.last_alert_time[mac]) > self.alert_cooldown:
                ip_list = ", ".join(list(self.mac_ip_mapping[mac]))
                self.analyzer.add_alert(
                    "ARP Spoofing",
                    f"Suspicious MAC address {mac} is associated with multiple IPs: {ip_list}",
                    severity="medium",
                    packet=packet
                )
                self.last_alert_time[mac] = current_time