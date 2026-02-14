#!/usr/bin/env python3
"""
Hostile Token Generator - Test script for Watchman AI
Generates hostile network traffic patterns matching the training dataset to test detection.
"""

import time
import random
import argparse
import numpy as np
from scapy.all import IP, TCP, UDP, Raw, send, get_if_list
from typing import Optional

# --- CONFIGURATION ---
TARGET_IP = '127.0.0.1'  # Localhost (change to your router IP if testing on network)
TARGET_PORT = 1337       # The Honey Port
INTERFACE = None         # Auto-detect (or specify: 'lo0', 'en0', etc.)


class HostileTokenGenerator:
    """
    Generates hostile network traffic patterns matching training dataset characteristics.
    """
    
    def __init__(self, target_ip: str = TARGET_IP, target_port: int = TARGET_PORT, 
                 interface: Optional[str] = None):
        self.target_ip = target_ip
        self.target_port = target_port
        self.interface = interface or self._detect_interface()
        
    def _detect_interface(self) -> str:
        """Auto-detect network interface."""
        interfaces = get_if_list()
        # Prefer loopback for localhost testing
        if 'lo0' in interfaces:
            return 'lo0'
        elif 'lo' in interfaces:
            return 'lo'
        elif interfaces:
            return interfaces[0]
        return 'eth0'  # Default fallback
    
    def generate_payload(self, size: int) -> bytes:
        """Generate payload of specified size with suspicious content."""
        # Mix of suspicious patterns that might trigger detection
        patterns = [
            b'GET /admin HTTP/1.1\r\n',
            b'POST /login.php?cmd=',
            b'SELECT * FROM users WHERE',
            b'<script>alert("XSS")</script>',
            b'../../etc/passwd',
            b'UNION SELECT NULL--',
            b'<?php system($_GET["cmd"]); ?>',
            b'python -c "import socket,subprocess,os"',
        ]
        
        payload = b''
        while len(payload) < size:
            pattern = random.choice(patterns)
            payload += pattern
            if len(payload) >= size:
                break
            # Add some random bytes
            payload += bytes(random.randint(0, 255) for _ in range(min(10, size - len(payload))))
        
        return payload[:size]
    
    def pattern_port_scanning(self, count: int = 10):
        """
        Pattern 1: Port Scanning (40% of hostile training data)
        - Small packets (40-100 bytes)
        - Minimal payloads (0-50 bytes)
        - Very fast inter-arrival (0.001-0.1 seconds)
        - Low source ports (1-1024)
        - TCP
        """
        print(f"\n[*] Pattern 1: Port Scanning Attack")
        print(f"    Sending {count} packets with scanning characteristics...")
        
        for i in range(count):
            # Small packet size: 40-100 bytes
            packet_size = int(np.random.normal(60, 5))
            packet_size = max(40, min(100, packet_size))
            
            # Minimal payload: 0-50 bytes
            payload_size = int(np.random.exponential(10))
            payload_size = max(0, min(50, payload_size))
            
            # Low source port (suspicious)
            src_port = random.randint(1, 1024)
            
            # Generate packet
            payload = self.generate_payload(payload_size) if payload_size > 0 else b''
            
            packet = IP(dst=self.target_ip) / \
                     TCP(sport=src_port, dport=self.target_port, flags="S", 
                         seq=random.randint(1000, 999999)) / \
                     Raw(load=payload)
            
            send(packet, iface=self.interface, verbose=False)
            
            # Very fast inter-arrival: 0.001-0.1 seconds
            interval = np.random.exponential(0.01)
            interval = max(0.001, min(0.1, interval))
            time.sleep(interval)
            
            if (i + 1) % 5 == 0:
                print(f"    Sent {i + 1}/{count} scanning packets...")
        
        print(f"[+] Port scanning pattern complete!")
    
    def pattern_exploitation_attempts(self, count: int = 8):
        """
        Pattern 2: Exploitation Attempts (30% of hostile training data)
        - Medium-large packets (200-1000 bytes)
        - Large payloads (100-600 bytes)
        - Fast bursts (0.01-1.0 seconds)
        - Low source ports (1-1024)
        - TCP
        """
        print(f"\n[*] Pattern 2: Exploitation Attempts")
        print(f"    Sending {count} packets with exploit characteristics...")
        
        for i in range(count):
            # Medium-large packet: 200-1000 bytes
            packet_size = int(np.random.normal(400, 100))
            packet_size = max(200, min(1000, packet_size))
            
            # Large payload: 100-600 bytes
            payload_size = int(np.random.exponential(200))
            payload_size = max(100, min(600, payload_size))
            
            # Low source port
            src_port = random.randint(1, 1024)
            
            # Generate exploit-like payload
            payload = self.generate_payload(payload_size)
            
            packet = IP(dst=self.target_ip) / \
                     TCP(sport=src_port, dport=self.target_port, flags="PA",
                         seq=random.randint(1000, 999999)) / \
                     Raw(load=payload)
            
            send(packet, iface=self.interface, verbose=False)
            
            # Fast bursts: 0.01-1.0 seconds
            interval = np.random.exponential(0.1)
            interval = max(0.01, min(1.0, interval))
            time.sleep(interval)
            
            if (i + 1) % 3 == 0:
                print(f"    Sent {i + 1}/{count} exploit packets...")
        
        print(f"[+] Exploitation pattern complete!")
    
    def pattern_data_exfiltration(self, count: int = 5):
        """
        Pattern 3: Data Exfiltration (20% of hostile training data)
        - Large packets (800-1500 bytes)
        - Large payloads (700-1440 bytes)
        - Fast continuous (0.01-0.5 seconds)
        - Low source ports (1-1024)
        - TCP
        """
        print(f"\n[*] Pattern 3: Data Exfiltration")
        print(f"    Sending {count} packets with exfiltration characteristics...")
        
        for i in range(count):
            # Large packet: 800-1500 bytes
            packet_size = int(np.random.normal(1200, 200))
            packet_size = max(800, min(1500, packet_size))
            
            # Large payload: 700-1440 bytes
            payload_size = int(np.random.normal(1100, 150))
            payload_size = max(700, min(1440, payload_size))
            
            # Low source port
            src_port = random.randint(1, 1024)
            
            # Generate data-like payload (simulate exfiltrated data)
            payload = self.generate_payload(payload_size)
            # Add some "data" patterns
            payload += b'\x00' * (payload_size - len(payload))
            
            packet = IP(dst=self.target_ip) / \
                     TCP(sport=src_port, dport=self.target_port, flags="PA",
                         seq=random.randint(1000, 999999)) / \
                     Raw(load=payload)
            
            send(packet, iface=self.interface, verbose=False)
            
            # Fast continuous: 0.01-0.5 seconds
            interval = np.random.exponential(0.05)
            interval = max(0.01, min(0.5, interval))
            time.sleep(interval)
            
            if (i + 1) % 2 == 0:
                print(f"    Sent {i + 1}/{count} exfiltration packets...")
        
        print(f"[+] Data exfiltration pattern complete!")
    
    def pattern_udp_attacks(self, count: int = 3):
        """
        Pattern 4: UDP-based Attacks (10% of hostile training data)
        - Medium packets (100-500 bytes)
        - Medium payloads (50-400 bytes)
        - Very fast flooding (0.001-0.2 seconds)
        - Low source ports (1-1024)
        - UDP
        """
        print(f"\n[*] Pattern 4: UDP-based Attacks")
        print(f"    Sending {count} packets with UDP flooding characteristics...")
        
        for i in range(count):
            # Medium packet: 100-500 bytes
            packet_size = int(np.random.normal(200, 50))
            packet_size = max(100, min(500, packet_size))
            
            # Medium payload: 50-400 bytes
            payload_size = int(np.random.exponential(150))
            payload_size = max(50, min(400, payload_size))
            
            # Low source port
            src_port = random.randint(1, 1024)
            
            # Generate payload
            payload = self.generate_payload(payload_size)
            
            packet = IP(dst=self.target_ip) / \
                     UDP(sport=src_port, dport=self.target_port) / \
                     Raw(load=payload)
            
            send(packet, iface=self.interface, verbose=False)
            
            # Very fast flooding: 0.001-0.2 seconds
            interval = np.random.exponential(0.02)
            interval = max(0.001, min(0.2, interval))
            time.sleep(interval)
            
            print(f"    Sent {i + 1}/{count} UDP attack packets...")
        
        print(f"[+] UDP attack pattern complete!")
    
    def run_all_patterns(self, counts: Optional[dict] = None):
        """
        Run all hostile patterns in sequence.
        
        Args:
            counts: Dict with pattern names and counts, e.g. {'scanning': 10, 'exploit': 8}
        """
        if counts is None:
            counts = {
                'scanning': 10,
                'exploit': 8,
                'exfiltration': 5,
                'udp': 3
            }
        
        print("="*60)
        print("[*] HOSTILE TOKEN GENERATOR - Testing Watchman AI")
        print("="*60)
        print(f"[*] Target: {self.target_ip}:{self.target_port}")
        print(f"[*] Interface: {self.interface}")
        print(f"[*] Patterns: Following training dataset characteristics")
        print("="*60)
        
        try:
            # Run all patterns
            self.pattern_port_scanning(counts.get('scanning', 10))
            time.sleep(0.5)  # Brief pause between patterns
            
            self.pattern_exploitation_attempts(counts.get('exploit', 8))
            time.sleep(0.5)
            
            self.pattern_data_exfiltration(counts.get('exfiltration', 5))
            time.sleep(0.5)
            
            self.pattern_udp_attacks(counts.get('udp', 3))
            
            print("\n" + "="*60)
            print("[+] All hostile patterns sent!")
            print("[*] Check Watchman AI output for detection and blockchain logging")
            print("="*60)
            
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
        except Exception as e:
            print(f"\n[!] Error: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate hostile tokens to test Watchman AI detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all patterns with default counts
  sudo python generate_hostile_tokens.py
  
  # Run only port scanning pattern
  sudo python generate_hostile_tokens.py --pattern scanning --count 20
  
  # Custom target and interface
  sudo python generate_hostile_tokens.py --target 192.168.1.1 --interface en0
  
  # Run all patterns with custom counts
  sudo python generate_hostile_tokens.py --scanning 15 --exploit 10 --exfiltration 7 --udp 5
        """
    )
    
    parser.add_argument(
        '--target',
        type=str,
        default=TARGET_IP,
        help=f'Target IP address (default: {TARGET_IP})'
    )
    
    parser.add_argument(
        '--interface',
        type=str,
        default=None,
        help='Network interface (default: auto-detect)'
    )
    
    parser.add_argument(
        '--pattern',
        type=str,
        choices=['scanning', 'exploit', 'exfiltration', 'udp', 'all'],
        default='all',
        help='Which pattern to run (default: all)'
    )
    
    parser.add_argument(
        '--count',
        type=int,
        default=10,
        help='Number of packets for single pattern (default: 10)'
    )
    
    parser.add_argument(
        '--scanning',
        type=int,
        default=10,
        help='Number of port scanning packets (default: 10)'
    )
    
    parser.add_argument(
        '--exploit',
        type=int,
        default=8,
        help='Number of exploitation packets (default: 8)'
    )
    
    parser.add_argument(
        '--exfiltration',
        type=int,
        default=5,
        help='Number of exfiltration packets (default: 5)'
    )
    
    parser.add_argument(
        '--udp',
        type=int,
        default=3,
        help='Number of UDP attack packets (default: 3)'
    )
    
    args = parser.parse_args()
    
    # Create generator
    generator = HostileTokenGenerator(
        target_ip=args.target,
        target_port=TARGET_PORT,
        interface=args.interface
    )
    
    # Run selected pattern
    if args.pattern == 'all':
        generator.run_all_patterns({
            'scanning': args.scanning,
            'exploit': args.exploit,
            'exfiltration': args.exfiltration,
            'udp': args.udp
        })
    elif args.pattern == 'scanning':
        generator.pattern_port_scanning(args.count)
    elif args.pattern == 'exploit':
        generator.pattern_exploitation_attempts(args.count)
    elif args.pattern == 'exfiltration':
        generator.pattern_data_exfiltration(args.count)
    elif args.pattern == 'udp':
        generator.pattern_udp_attacks(args.count)


if __name__ == "__main__":
    main()
