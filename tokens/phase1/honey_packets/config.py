"""
Configuration module for Honey-Packet injection.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class HoneyPacketConfig:
    """Configuration for honey-packet injection."""
    
    # Target router IP (simulated)
    router_ip: str = "192.168.1.1"
    
    # Fake admin source IP
    admin_ip: str = "192.168.1.50"
    
    # Network interface (None = auto-detect)
    interface: Optional[str] = None
    
    # Injection interval range (seconds)
    min_interval: int = 10
    max_interval: int = 60
    
    # Source port range for randomization
    min_sport: int = 50000
    max_sport: int = 65535
    
    # Enable protocols
    enable_telnet: bool = True
    enable_ssh: bool = True
    enable_snmp: bool = True
    
    # Honey-token credentials
    fake_usernames: list = None
    fake_passwords: list = None
    
    def __post_init__(self):
        """Initialize default honey-tokens if not provided."""
        if self.fake_usernames is None:
            self.fake_usernames = [
                "admin_01",
                "admin_02",
                "root",
                "network_admin",
                "config_manager"
            ]
        
        if self.fake_passwords is None:
            self.fake_passwords = [
                "*********",
                "P@ssw0rd123",
                "admin123!",
                "secure_pass",
                "router_config"
            ]
