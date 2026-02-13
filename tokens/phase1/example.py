#!/usr/bin/env python3
"""
Example usage of the Honey-Packet Injector.

This script demonstrates how to use the honey-packet system programmatically.
"""

from .honey_packets import HoneyPacketInjector, HoneyPacketConfig
import time

def main():
    """Example usage."""
    print("[*] Creating custom configuration...")
    
    # Create a custom configuration
    config = HoneyPacketConfig(
        router_ip="192.168.1.1",
        admin_ip="192.168.1.50",
        min_interval=15,
        max_interval=30,
        enable_telnet=True,
        enable_ssh=True,
        enable_snmp=True
    )
    
    print(f"[*] Router IP: {config.router_ip}")
    print(f"[*] Admin IP: {config.admin_ip}")
    print(f"[*] Injection interval: {config.min_interval}-{config.max_interval}s")
    print()
    
    # Create injector
    print("[*] Initializing honey-packet injector...")
    injector = HoneyPacketInjector(config)
    
    # Option 1: Inject a single packet (for testing)
    print("[*] Injecting single Telnet packet for testing...")
    injector.inject_single_packet("telnet")
    print("[+] Single packet injected!")
    print()
    
    # Option 2: Start continuous injection
    print("[*] Starting continuous injection (will run for 30 seconds)...")
    print("[*] Press Ctrl+C to stop early")
    injector.start()
    
    try:
        # Run for 30 seconds as an example
        time.sleep(30)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
    finally:
        print("[*] Stopping injector...")
        injector.stop()
        print("[+] Injector stopped successfully")

if __name__ == "__main__":
    main()
