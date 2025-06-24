"""
Port Scanning Detector Module
Detects potential port scanning activities by analyzing TCP/UDP traffic patterns
"""

import time
from collections import defaultdict
from scapy.all import TCP, UDP, IP

class PortScanDetector:
    """Detector for port scanning activities"""
    
    def __init__(self, analyzer):
        """Initialize the port scanning detector"""
        self.analyzer = analyzer
        
        # Track connection attempts
        self.syn_attempts = defaultdict(lambda: defaultdict(list))  # src_ip -> dst_ip -> [ports]
        self.udp_attempts = defaultdict(lambda: defaultdict(list))  # src_ip -> dst_ip -> [ports]
        
        # Track when alerts were last sent
        self.last_alert_time = {}
        self.alert_cooldown = 60  # Seconds between repeated alerts
        
        # Thresholds
        self.tcp_scan_threshold = 10  # Number of different ports to trigger alert
        self.udp_scan_threshold = 10  # Number of different ports to trigger alert
        self.time_window = 60  # Time window in seconds to consider for scan detection
        
        # Common ports often targeted by scanners
        self.common_target_ports = {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
            993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443
        }
        
        # Track time of last cleanup
        self.last_cleanup_time = time.time()
        self.cleanup_interval = 300  # 5 minutes
    
    def analyze(self, packet):
        """Analyze a packet for signs of port scanning"""
        current_time = time.time()
        
        # Periodically clean up old data
        if current_time - self.last_cleanup_time > self.cleanup_interval:
            self._cleanup_old_data(current_time)
            self.last_cleanup_time = current_time
        
        # Check for TCP scans
        if IP in packet and TCP in packet:
            self._analyze_tcp(packet, current_time)
        
        # Check for UDP scans
        elif IP in packet and UDP in packet:
            self._analyze_udp(packet, current_time)
    
    def _analyze_tcp(self, packet, current_time):
        """Analyze TCP packets for port scanning patterns"""
        ip = packet[IP]
        tcp = packet[TCP]
        
        src_ip = ip.src
        dst_ip = ip.dst
        dst_port = tcp.dport
        
        # Check for SYN scan (SYN flag set, ACK and other flags not set)
        if tcp.flags & 0x02 and not (tcp.flags & 0x10):  # SYN flag set, ACK flag not set
            # Record this connection attempt
            self.syn_attempts[src_ip][dst_ip].append((dst_port, current_time))
            
            # Check if this is a scan of common vulnerable ports
            if dst_port in self.common_target_ports:
                self._check_common_port_scan(src_ip, dst_ip, dst_port, packet, current_time)
            
            # Check for horizontal port scanning (multiple ports on same destination)
            self._check_horizontal_scan(src_ip, dst_ip, packet, current_time)
    
    def _analyze_udp(self, packet, current_time):
        """Analyze UDP packets for port scanning patterns"""
        ip = packet[IP]
        udp = packet[UDP]
        
        src_ip = ip.src
        dst_ip = ip.dst
        dst_port = udp.dport
        
        # Record this connection attempt
        self.udp_attempts[src_ip][dst_ip].append((dst_port, current_time))
        
        # Check if this is a scan of common vulnerable ports
        if dst_port in self.common_target_ports:
            self._check_common_port_scan(src_ip, dst_ip, dst_port, packet, current_time, protocol="UDP")
        
        # Check for horizontal port scanning (multiple ports on same destination)
        self._check_horizontal_scan(src_ip, dst_ip, packet, current_time, protocol="UDP")
    
    def _check_horizontal_scan(self, src_ip, dst_ip, packet, current_time, protocol="TCP"):
        """Check for horizontal port scanning (multiple ports on same destination)"""
        # Get the appropriate attempts dictionary based on protocol
        attempts_dict = self.syn_attempts if protocol == "TCP" else self.udp_attempts
        threshold = self.tcp_scan_threshold if protocol == "TCP" else self.udp_scan_threshold
        
        # Get recent connection attempts within the time window
        recent_attempts = [(port, t) for port, t in attempts_dict[src_ip][dst_ip] 
                          if current_time - t <= self.time_window]
        
        # Update the attempts list with only recent attempts
        attempts_dict[src_ip][dst_ip] = recent_attempts
        
        # Count unique ports
        unique_ports = set(port for port, _ in recent_attempts)
        
        # Check if the number of unique ports exceeds the threshold
        if len(unique_ports) >= threshold:
            # Check if we've alerted about this scan recently
            alert_key = f"horizontal_scan_{protocol}_{src_ip}_{dst_ip}"
            
            if alert_key not in self.last_alert_time or (current_time - self.last_alert_time[alert_key]) > self.alert_cooldown:
                # Check if ports are sequential (more suspicious)
                sorted_ports = sorted(unique_ports)
                sequential_count = 0
                for i in range(1, len(sorted_ports)):
                    if sorted_ports[i] == sorted_ports[i-1] + 1:
                        sequential_count += 1
                
                severity = "high" if sequential_count >= 5 else "medium"
                port_list = ", ".join(str(p) for p in sorted(unique_ports)[:10])
                if len(unique_ports) > 10:
                    port_list += f", ... ({len(unique_ports) - 10} more)"
                
                self.analyzer.add_alert(
                    "Port Scanning",
                    f"Possible {protocol} port scan detected from {src_ip} to {dst_ip} ({len(unique_ports)} ports in {self.time_window}s): {port_list}",
                    severity=severity,
                    packet=packet
                )
                self.last_alert_time[alert_key] = current_time
    
    def _check_common_port_scan(self, src_ip, dst_ip, dst_port, packet, current_time, protocol="TCP"):
        """Check for scanning of commonly vulnerable ports"""
        # Get the appropriate attempts dictionary based on protocol
        attempts_dict = self.syn_attempts if protocol == "TCP" else self.udp_attempts
        
        # Count how many common ports this source has attempted to connect to on this destination
        common_port_attempts = set()
        
        for port, t in attempts_dict[src_ip][dst_ip]:
            if current_time - t <= self.time_window and port in self.common_target_ports:
                common_port_attempts.add(port)
        
        # If source has attempted multiple common vulnerable ports, it might be a targeted scan
        if len(common_port_attempts) >= 3:
            # Check if we've alerted about this scan recently
            alert_key = f"common_port_scan_{protocol}_{src_ip}_{dst_ip}"
            
            if alert_key not in self.last_alert_time or (current_time - self.last_alert_time[alert_key]) > self.alert_cooldown:
                port_list = ", ".join(str(p) for p in sorted(common_port_attempts))
                
                self.analyzer.add_alert(
                    "Port Scanning",
                    f"Possible targeted {protocol} scan of common vulnerable ports from {src_ip} to {dst_ip}: {port_list}",
                    severity="high",
                    packet=packet
                )
                self.last_alert_time[alert_key] = current_time
    
    def _cleanup_old_data(self, current_time):
        """Clean up old connection attempts data to prevent memory bloat"""
        # Clean up TCP attempts
        for src_ip in list(self.syn_attempts.keys()):
            for dst_ip in list(self.syn_attempts[src_ip].keys()):
                # Keep only recent attempts
                recent_attempts = [(port, t) for port, t in self.syn_attempts[src_ip][dst_ip] 
                                  if current_time - t <= self.time_window]
                
                if recent_attempts:
                    self.syn_attempts[src_ip][dst_ip] = recent_attempts
                else:
                    del self.syn_attempts[src_ip][dst_ip]
            
            # Remove empty source IPs
            if not self.syn_attempts[src_ip]:
                del self.syn_attempts[src_ip]
        
        # Clean up UDP attempts
        for src_ip in list(self.udp_attempts.keys()):
            for dst_ip in list(self.udp_attempts[src_ip].keys()):
                # Keep only recent attempts
                recent_attempts = [(port, t) for port, t in self.udp_attempts[src_ip][dst_ip] 
                                  if current_time - t <= self.time_window]
                
                if recent_attempts:
                    self.udp_attempts[src_ip][dst_ip] = recent_attempts
                else:
                    del self.udp_attempts[src_ip][dst_ip]
            
            # Remove empty source IPs
            if not self.udp_attempts[src_ip]:
                del self.udp_attempts[src_ip]
        
        # Clean up old alert times
        for key in list(self.last_alert_time.keys()):
            if current_time - self.last_alert_time[key] > self.alert_cooldown * 2:
                del self.last_alert_time[key]