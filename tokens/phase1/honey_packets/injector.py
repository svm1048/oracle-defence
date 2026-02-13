"""
Honey-Packet Injector - Main injection engine.

Implements F-1.1 (Layered Construction), F-1.3 (Credential Baiting),
and F-1.4 (Temporal Logic) requirements.
"""

import time
import random
import threading
import logging
from typing import Optional

try:
    from scapy.all import send, get_if_list, get_if_addr
    import netifaces
except ImportError as e:
    raise ImportError(
        "Required libraries not installed. Run: pip install -r requirements.txt"
    ) from e

from .config import HoneyPacketConfig
from .protocols import TelnetHoney, SSHHoney, SNMPHoney


class HoneyPacketInjector:
    """
    Main injector class for honey-packet generation and injection.
    
    This class implements the core functionality for creating and injecting
    honey-packets that simulate router management plane traffic.
    """
    
    def __init__(self, config: Optional[HoneyPacketConfig] = None):
        """
        Initialize the honey-packet injector.
        
        Args:
            config: Configuration object. If None, uses default config.
        """
        self.config = config or HoneyPacketConfig()
        self.running = False
        self.injection_thread: Optional[threading.Thread] = None
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        # Detect network interface if not specified
        if self.config.interface is None:
            self.config.interface = self._detect_interface()
            self.logger.info(f"Auto-detected interface: {self.config.interface}")
    
    def _detect_interface(self) -> str:
        """
        Automatically detect the active network interface.
        
        Returns:
            Interface name (e.g., 'eth0', 'en0', 'wlan0')
        """
        try:
            # Get default gateway interface
            gateways = netifaces.gateways()
            default_interface = gateways['default'][netifaces.AF_INET][1]
            return default_interface
        except (KeyError, IndexError, AttributeError):
            # Fallback: use first available interface
            interfaces = get_if_list()
            if interfaces:
                # Filter out loopback
                for iface in interfaces:
                    if iface != 'lo' and 'lo0' not in iface:
                        return iface
            # Last resort
            return 'eth0'
    
    def _generate_random_credentials(self) -> tuple:
        """
        Generate random honey-token credentials.
        
        Returns:
            Tuple of (username, password)
        """
        username = random.choice(self.config.fake_usernames)
        password = random.choice(self.config.fake_passwords)
        return username, password
    
    def _generate_random_sport(self) -> int:
        """Generate random source port."""
        return random.randint(self.config.min_sport, self.config.max_sport)
    
    def _inject_telnet_packet(self):
        """Inject a Telnet honey-packet."""
        if not self.config.enable_telnet:
            return
        
        username, password = self._generate_random_credentials()
        src_port = self._generate_random_sport()
        
        # Randomly choose between login and config packets
        if random.random() > 0.5:
            packet = TelnetHoney.generate_packet(
                self.config.admin_ip,
                self.config.router_ip,
                src_port,
                username,
                password
            )
        else:
            packet = TelnetHoney.generate_config_packet(
                self.config.admin_ip,
                self.config.router_ip,
                src_port
            )
        
        try:
            send(packet, iface=self.config.interface, verbose=False)
            self.logger.debug(
                f"Injected Telnet packet: {self.config.admin_ip}:{src_port} -> "
                f"{self.config.router_ip}:23"
            )
        except Exception as e:
            self.logger.error(f"Failed to inject Telnet packet: {e}")
    
    def _inject_ssh_packet(self):
        """Inject an SSH honey-packet."""
        if not self.config.enable_ssh:
            return
        
        username, password = self._generate_random_credentials()
        src_port = self._generate_random_sport()
        
        # Randomly choose between auth and key exchange packets
        if random.random() > 0.5:
            packet = SSHHoney.generate_packet(
                self.config.admin_ip,
                self.config.router_ip,
                src_port,
                username,
                password
            )
        else:
            packet = SSHHoney.generate_key_exchange_packet(
                self.config.admin_ip,
                self.config.router_ip,
                src_port
            )
        
        try:
            send(packet, iface=self.config.interface, verbose=False)
            self.logger.debug(
                f"Injected SSH packet: {self.config.admin_ip}:{src_port} -> "
                f"{self.config.router_ip}:22"
            )
        except Exception as e:
            self.logger.error(f"Failed to inject SSH packet: {e}")
    
    def _inject_snmp_packet(self):
        """Inject an SNMP honey-packet."""
        if not self.config.enable_snmp:
            return
        
        src_port = self._generate_random_sport()
        # Use community strings as honey-tokens
        community = random.choice([
            "public", "private", "admin", "read", "write", "cisco"
        ])
        
        # Randomly choose between GET and general SNMP packets
        if random.random() > 0.5:
            packet = SNMPHoney.generate_packet(
                self.config.admin_ip,
                self.config.router_ip,
                src_port,
                community
            )
        else:
            packet = SNMPHoney.generate_get_request(
                self.config.admin_ip,
                self.config.router_ip,
                src_port,
                community
            )
        
        try:
            send(packet, iface=self.config.interface, verbose=False)
            self.logger.debug(
                f"Injected SNMP packet: {self.config.admin_ip}:{src_port} -> "
                f"{self.config.router_ip}:161 (community: {community})"
            )
        except Exception as e:
            self.logger.error(f"Failed to inject SNMP packet: {e}")
    
    def _injection_loop(self):
        """
        Main injection loop with randomized temporal logic (F-1.4).
        
        Implements randomized intervals between 10-60 seconds to appear human-like.
        """
        self.logger.info("Starting honey-packet injection loop...")
        
        while self.running:
            try:
                # Randomly select which protocol to inject
                protocol_choice = random.random()
                
                if protocol_choice < 0.33 and self.config.enable_telnet:
                    self._inject_telnet_packet()
                elif protocol_choice < 0.66 and self.config.enable_ssh:
                    self._inject_ssh_packet()
                elif self.config.enable_snmp:
                    self._inject_snmp_packet()
                
                # Calculate random interval (F-1.4: 10-60 seconds)
                interval = random.uniform(
                    self.config.min_interval,
                    self.config.max_interval
                )
                
                self.logger.info(
                    f"Injected packet. Next injection in {interval:.1f} seconds"
                )
                
                # Sleep for the interval, but check running flag periodically
                elapsed = 0
                while elapsed < interval and self.running:
                    time.sleep(0.5)
                    elapsed += 0.5
                    
            except Exception as e:
                self.logger.error(f"Error in injection loop: {e}")
                if self.running:
                    time.sleep(5)  # Brief pause before retrying
        
        self.logger.info("Honey-packet injection loop stopped.")
    
    def start(self):
        """Start the honey-packet injection in a background thread."""
        if self.running:
            self.logger.warning("Injector is already running.")
            return
        
        self.running = True
        self.injection_thread = threading.Thread(
            target=self._injection_loop,
            daemon=True
        )
        self.injection_thread.start()
        self.logger.info(
            f"Honey-packet injector started. "
            f"Router IP: {self.config.router_ip}, "
            f"Admin IP: {self.config.admin_ip}, "
            f"Interface: {self.config.interface}"
        )
    
    def stop(self):
        """Stop the honey-packet injection."""
        if not self.running:
            self.logger.warning("Injector is not running.")
            return
        
        self.running = False
        if self.injection_thread:
            self.injection_thread.join(timeout=5)
        self.logger.info("Honey-packet injector stopped.")
    
    def inject_single_packet(self, protocol: str = "telnet"):
        """
        Inject a single honey-packet (useful for testing).
        
        Args:
            protocol: Protocol to use ('telnet', 'ssh', or 'snmp')
        """
        if protocol.lower() == "telnet":
            self._inject_telnet_packet()
        elif protocol.lower() == "ssh":
            self._inject_ssh_packet()
        elif protocol.lower() == "snmp":
            self._inject_snmp_packet()
        else:
            raise ValueError(f"Unknown protocol: {protocol}")
