#!/usr/bin/env python3
"""
S3niffRade Test Script
A simple script to demonstrate how to use the Network Packet Analyzer
"""

import time
import argparse
from packet_analyzer import PacketAnalyzer

def main():
    """Main function to demonstrate the packet analyzer"""
    parser = argparse.ArgumentParser(description="S3niffRade Test Script")
    parser.add_argument("-i", "--interface", help="Network interface to capture packets from")
    parser.add_argument("-t", "--time", type=int, default=60, help="Duration to capture packets (seconds)")
    parser.add_argument("-d", "--dashboard", action="store_true", help="Enable web dashboard")
    parser.add_argument("-o", "--output", default="results.json", help="Output file to save results")
    
    args = parser.parse_args()
    
    print("Starting S3niffRade Network Packet Analyzer test...")
    print(f"Capturing packets for {args.time} seconds")
    
    # Create the packet analyzer
    analyzer = PacketAnalyzer(
        interface=args.interface,
        output_file=args.output,
        dashboard=args.dashboard
    )
    
    # If no interface specified, show available interfaces
    if not args.interface:
        analyzer.print_available_interfaces()
        print("No interface specified. Using default interface.")
    
    # Start a separate thread for the analyzer
    import threading
    analyzer_thread = threading.Thread(target=analyzer.start)
    analyzer_thread.daemon = True
    analyzer_thread.start()
    
    try:
        # Run for specified duration
        print(f"Analyzer running. Press Ctrl+C to stop before the {args.time} second timeout.")
        
        # If dashboard is enabled, provide the URL
        if args.dashboard:
            print("Dashboard available at: http://localhost:5000")
        
        # Wait for specified duration
        time.sleep(args.time)
        
        # Stop the analyzer
        analyzer.stop()
        print(f"\nCapture completed. Results saved to {args.output}")
        
        # Print summary
        print("\nCapture Summary:")
        print(f"Total packets: {analyzer.stats['total_packets']}")
        
        if analyzer.stats["protocols"]:
            print("\nProtocol Distribution:")
            for protocol, count in analyzer.stats["protocols"].items():
                print(f"  - {protocol}: {count} packets")
        
        if analyzer.stats["alerts"]:
            print("\nDetected Threats:")
            for alert in analyzer.stats["alerts"]:
                print(f"  - [{alert['severity'].upper()}] {alert['type']}: {alert['message']}")
        else:
            print("\nNo threats detected during the capture period.")
            
    except KeyboardInterrupt:
        # Handle Ctrl+C
        print("\nCapture interrupted by user.")
        analyzer.stop()
        print(f"Results saved to {args.output}")
    
    # Wait for dashboard to be closed if it's running
    if args.dashboard and analyzer_thread.is_alive():
        print("Dashboard is still running. Press Ctrl+C again to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Exiting...")

if __name__ == "__main__":
    main()