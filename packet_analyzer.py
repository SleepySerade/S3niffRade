#!/usr/bin/env python3
"""
S3niffRade - Network Packet Analyzer with Threat Detection
A tool for capturing and analyzing network packets to detect suspicious activities
"""

import argparse
import time
import threading
import logging
import json
import os
from datetime import datetime
from scapy.all import sniff, ARP, DNS, IP, TCP, UDP, ICMP, Raw, conf
from colorama import init, Fore, Style

# Initialize colorama
init()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("s3niffrade.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("S3niffRade")

class PacketAnalyzer:
    """Main packet analyzer class that orchestrates packet capture and threat detection"""
    
    def __init__(self, interface=None, output_file=None, dashboard=False):
        """Initialize the packet analyzer"""
        self.interface = interface
        self.output_file = output_file
        self.dashboard = dashboard
        self.stop_sniffing = threading.Event()
        self.packet_count = 0
        self.start_time = None
        self.detectors = []
        self.dashboard_data = {
            "packets": [],
            "alerts": []
        }
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "protocols": {},
            "src_ips": {},
            "dst_ips": {},
            "alerts": []
        }
        
        # Load detectors
        self._load_detectors()
        
        # Start dashboard if requested
        if dashboard:
            from dashboard import start_dashboard
            threading.Thread(target=start_dashboard, args=(self,), daemon=True).start()
    
    def _load_detectors(self):
        """Load all threat detectors"""
        try:
            from detectors.arp_spoof import ARPSpoofDetector
            from detectors.dns_tunnel import DNSTunnelDetector
            from detectors.port_scan import PortScanDetector
            
            self.detectors.append(ARPSpoofDetector(self))
            self.detectors.append(DNSTunnelDetector(self))
            self.detectors.append(PortScanDetector(self))
            
            logger.info(f"Loaded {len(self.detectors)} threat detectors")
        except ImportError as e:
            logger.error(f"Failed to load detectors: {e}")
    
    def start(self):
        """Start packet sniffing"""
        self.start_time = time.time()
        logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda _: self.stop_sniffing.is_set()
            )
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            logger.error(f"Error during packet capture: {e}")
            self.stop()
    
    def stop(self):
        """Stop packet sniffing"""
        self.stop_sniffing.set()
        duration = time.time() - self.start_time if self.start_time else 0
        logger.info(f"Stopped packet capture. Processed {self.packet_count} packets in {duration:.2f} seconds")
        
        if self.output_file:
            self.save_results()
    
    def process_packet(self, packet):
        """Process a captured packet and run it through all detectors"""
        self.packet_count += 1
        self.stats["total_packets"] += 1
        
        # Extract basic packet info for statistics
        self._update_stats(packet)
        
        # Run packet through all detectors
        for detector in self.detectors:
            detector.analyze(packet)
        
        # Store packet data for dashboard if enabled
        if self.dashboard:
            packet_data = self._extract_packet_data(packet)
            self.dashboard_data["packets"].append(packet_data)
            
            # Limit stored packets to prevent memory issues
            if len(self.dashboard_data["packets"]) > 1000:
                self.dashboard_data["packets"] = self.dashboard_data["packets"][-1000:]
        
        return True
    
    def _update_stats(self, packet):
        """Update packet statistics"""
        # Protocol statistics
        if ARP in packet:
            self.stats["protocols"]["ARP"] = self.stats["protocols"].get("ARP", 0) + 1
        elif IP in packet:
            self.stats["protocols"]["IP"] = self.stats["protocols"].get("IP", 0) + 1
            
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Update source IP counts
            self.stats["src_ips"][src_ip] = self.stats["src_ips"].get(src_ip, 0) + 1
            
            # Update destination IP counts
            self.stats["dst_ips"][dst_ip] = self.stats["dst_ips"].get(dst_ip, 0) + 1
            
            if TCP in packet:
                self.stats["protocols"]["TCP"] = self.stats["protocols"].get("TCP", 0) + 1
            elif UDP in packet:
                self.stats["protocols"]["UDP"] = self.stats["protocols"].get("UDP", 0) + 1
            elif ICMP in packet:
                self.stats["protocols"]["ICMP"] = self.stats["protocols"].get("ICMP", 0) + 1
            
            if DNS in packet:
                self.stats["protocols"]["DNS"] = self.stats["protocols"].get("DNS", 0) + 1
    
    def _extract_packet_data(self, packet):
        """Extract relevant data from packet for dashboard display"""
        packet_data = {
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "protocol": "",
            "src": "",
            "dst": "",
            "info": ""
        }
        
        if ARP in packet:
            packet_data["protocol"] = "ARP"
            packet_data["src"] = packet[ARP].psrc
            packet_data["dst"] = packet[ARP].pdst
            packet_data["info"] = f"{'Request' if packet[ARP].op == 1 else 'Reply'} {packet[ARP].hwsrc} -> {packet[ARP].hwdst}"
        elif IP in packet:
            packet_data["src"] = packet[IP].src
            packet_data["dst"] = packet[IP].dst
            
            if TCP in packet:
                packet_data["protocol"] = "TCP"
                packet_data["info"] = f"Port {packet[TCP].sport} -> {packet[TCP].dport}"
            elif UDP in packet:
                packet_data["protocol"] = "UDP"
                packet_data["info"] = f"Port {packet[UDP].sport} -> {packet[UDP].dport}"
                
                if DNS in packet:
                    packet_data["protocol"] = "DNS"
                    if packet.qd:
                        packet_data["info"] = f"Query: {packet.qd.qname.decode()}"
            elif ICMP in packet:
                packet_data["protocol"] = "ICMP"
                packet_data["info"] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
        
        return packet_data
    
    def add_alert(self, alert_type, message, severity="medium", packet=None):
        """Add a security alert"""
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "type": alert_type,
            "message": message,
            "severity": severity
        }
        
        # Add packet details if available
        if packet:
            if IP in packet:
                alert["src_ip"] = packet[IP].src
                alert["dst_ip"] = packet[IP].dst
            elif ARP in packet:
                alert["src_ip"] = packet[ARP].psrc
                alert["dst_ip"] = packet[ARP].pdst
        
        # Add to statistics
        self.stats["alerts"].append(alert)
        
        # Add to dashboard data
        if self.dashboard:
            self.dashboard_data["alerts"].append(alert)
            
            # Limit stored alerts to prevent memory issues
            if len(self.dashboard_data["alerts"]) > 100:
                self.dashboard_data["alerts"] = self.dashboard_data["alerts"][-100:]
        
        # Log the alert with appropriate color based on severity
        color = Fore.YELLOW
        if severity == "high":
            color = Fore.RED
        elif severity == "low":
            color = Fore.CYAN
            
        logger.warning(f"{color}[ALERT] {alert_type}: {message}{Style.RESET_ALL}")
    
    def save_results(self):
        """Save analysis results to file"""
        try:
            with open(self.output_file, 'w') as f:
                json.dump(self.stats, f, indent=2)
            logger.info(f"Results saved to {self.output_file}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def print_available_interfaces(self):
        """Print all available network interfaces"""
        print(f"\n{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
        for iface, iface_data in sorted(conf.ifaces.items()):
            print(f"  - {iface}")
        print()

def main():
    """Main entry point for the packet analyzer"""
    parser = argparse.ArgumentParser(description="S3niffRade - Network Packet Analyzer with Threat Detection")
    parser.add_argument("-i", "--interface", help="Network interface to capture packets from")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-d", "--dashboard", action="store_true", help="Enable web dashboard")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List available network interfaces")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    analyzer = PacketAnalyzer(
        interface=args.interface,
        output_file=args.output,
        dashboard=args.dashboard
    )
    
    if args.list_interfaces:
        analyzer.print_available_interfaces()
        return
    
    print(f"{Fore.GREEN}Starting S3niffRade - Network Packet Analyzer{Style.RESET_ALL}")
    print(f"Press Ctrl+C to stop capturing packets\n")
    
    analyzer.start()

if __name__ == "__main__":
    main()