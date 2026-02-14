#!/usr/bin/env python3
"""
Oracle Defense - Phase 1: Router Honey-Packets
Main entry point for the honey-packet injection system.
"""

import argparse
import signal
import sys
from .honey_packets import HoneyPacketInjector, HoneyPacketConfig


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    print("\n[!] Shutting down honey-packet injector...")
    if 'injector' in globals():
        injector.stop()
    sys.exit(0)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Oracle Defense - Phase 1: Router Honey-Packets Injector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Use default configuration
  python main.py

  # Custom router and admin IPs
  python main.py --router-ip 10.0.0.1 --admin-ip 10.0.0.50

  # Specify network interface
  python main.py --interface eth0

  # Inject single packet for testing
  python main.py --single --protocol telnet
        """
    )
    
    parser.add_argument(
        '--router-ip',
        type=str,
        default='192.168.1.1',
        help='Target router IP address (default: 192.168.1.1)'
    )
    
    parser.add_argument(
        '--admin-ip',
        type=str,
        default='192.168.1.50',
        help='Fake admin source IP address (default: 192.168.1.50)'
    )
    
    parser.add_argument(
        '--interface',
        type=str,
        default=None,
        help='Network interface to use (default: auto-detect)'
    )
    
    parser.add_argument(
        '--min-interval',
        type=int,
        default=10,
        help='Minimum injection interval in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--max-interval',
        type=int,
        default=60,
        help='Maximum injection interval in seconds (default: 60)'
    )
    
    parser.add_argument(
        '--disable-telnet',
        action='store_true',
        help='Disable Telnet (port 23) injection'
    )
    
    parser.add_argument(
        '--disable-ssh',
        action='store_true',
        help='Disable SSH (port 22) injection'
    )
    
    parser.add_argument(
        '--disable-snmp',
        action='store_true',
        help='Disable SNMP (port 161) injection'
    )
    
    parser.add_argument(
        '--single',
        action='store_true',
        help='Inject a single packet and exit (for testing)'
    )
    
    parser.add_argument(
        '--protocol',
        type=str,
        choices=['telnet', 'ssh', 'snmp'],
        default='telnet',
        help='Protocol to use with --single flag (default: telnet)'
    )
    
    args = parser.parse_args()
    
    # Create configuration
    config = HoneyPacketConfig(
        router_ip=args.router_ip,
        admin_ip=args.admin_ip,
        interface=args.interface,
        min_interval=args.min_interval,
        max_interval=args.max_interval,
        enable_telnet=not args.disable_telnet,
        enable_ssh=not args.disable_ssh,
        enable_snmp=not args.disable_snmp
    )
    
    # Create injector
    global injector
    injector = HoneyPacketInjector(config)
    
    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if args.single:
        # Single packet injection mode (for testing)
        print(f"[*] Injecting single {args.protocol} packet...")
        injector.inject_single_packet(args.protocol)
        print("[+] Packet injected successfully!")
    else:
        # Continuous injection mode
        print("[*] Starting honey-packet injection system...")
        print(f"[*] Router IP: {config.router_ip}")
        print(f"[*] Admin IP: {config.admin_ip}")
        print(f"[*] Interface: {config.interface}")
        print(f"[*] Protocols: Telnet={config.enable_telnet}, "
              f"SSH={config.enable_ssh}, SNMP={config.enable_snmp}")
        print(f"[*] Interval: {config.min_interval}-{config.max_interval} seconds")
        print("[*] Press Ctrl+C to stop\n")
        
        injector.start()
        
        try:
            # Keep main thread alive
            while injector.running:
                signal.pause()
        except KeyboardInterrupt:
            signal_handler(None, None)


if __name__ == "__main__":
    main()
