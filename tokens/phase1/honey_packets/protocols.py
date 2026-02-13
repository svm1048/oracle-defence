"""
Protocol-specific honey-packet payload generators.

Implements F-1.2: Protocol Mimicry for Telnet (23), SSH (22), and SNMP (161).
"""

import random
from typing import Optional
from scapy.all import IP, TCP, UDP, Raw

# Try to import Scapy's SNMP support if available
try:
    from scapy.contrib.snmp import SNMP
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False


class TelnetHoney:
    """Generates Telnet (port 23) honey-packets with credential baiting."""
    
    @staticmethod
    def generate_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        username: str,
        password: str
    ):
        """
        Generate a Telnet honey-packet with login sequence.
        
        Args:
            src_ip: Source IP address (fake admin)
            dst_ip: Destination IP address (router)
            src_port: Source port
            username: Honey-token username
            password: Honey-token password
            
        Returns:
            Scapy packet ready for injection
        """
        # Telnet login sequence simulation
        # Format: Login prompt -> username -> password prompt -> password attempt
        payload = f"Login: {username}\nPassword: {password}\n"
        
        # Build OSI layers: L3 (IP) -> L4 (TCP) -> L7 (Raw payload)
        packet = (
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=src_port, dport=23, flags="PA", seq=random.randint(1000, 999999)) /
            Raw(load=payload)
        )
        
        return packet
    
    @staticmethod
    def generate_config_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int
    ):
        """Generate a Telnet configuration command packet."""
        commands = [
            "configure terminal\n",
            "interface gigabitEthernet 0/0\n",
            "ip address 192.168.1.1 255.255.255.0\n",
            "no shutdown\n",
            "exit\n"
        ]
        payload = "".join(commands)
        
        packet = (
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=src_port, dport=23, flags="PA", seq=random.randint(1000, 999999)) /
            Raw(load=payload)
        )
        
        return packet


class SSHHoney:
    """Generates SSH (port 22) honey-packets with credential baiting."""
    
    @staticmethod
    def generate_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        username: str,
        password: str
    ):
        """
        Generate an SSH honey-packet with authentication attempt.
        
        Args:
            src_ip: Source IP address (fake admin)
            dst_ip: Destination IP address (router)
            src_port: Source port
            username: Honey-token username
            password: Honey-token password
            
        Returns:
            Scapy packet ready for injection
        """
        # SSH authentication attempt simulation
        # SSH protocol typically uses binary format, but we'll simulate
        # a text-based login attempt that would be visible in logs
        payload = f"SSH-2.0-OpenSSH_7.4\n{username}:{password}\n"
        
        packet = (
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=src_port, dport=22, flags="PA", seq=random.randint(1000, 999999)) /
            Raw(load=payload)
        )
        
        return packet
    
    @staticmethod
    def generate_key_exchange_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int
    ):
        """Generate an SSH key exchange packet."""
        payload = "SSH-2.0-OpenSSH_7.4\nKey Exchange Init\n"
        
        packet = (
            IP(src=src_ip, dst=dst_ip) /
            TCP(sport=src_port, dport=22, flags="PA", seq=random.randint(1000, 999999)) /
            Raw(load=payload)
        )
        
        return packet


class SNMPHoney:
    """Generates SNMP (port 161) honey-packets with community string baiting."""
    
    @staticmethod
    def generate_packet(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        community: str = "public"
    ):
        """
        Generate an SNMP honey-packet with community string.
        
        Args:
            src_ip: Source IP address (fake admin)
            dst_ip: Destination IP address (router)
            src_port: Source port
            community: SNMP community string (honey-token)
            
        Returns:
            Scapy packet ready for injection
        """
        # Try to use Scapy's SNMP support for better Wireshark compatibility
        if SNMP_AVAILABLE:
            try:
                # Create a proper SNMP GET request packet
                # This will be properly decoded by Wireshark
                # Note: Scapy's SNMP implementation may vary, so we use a simple approach
                snmp_pdu = SNMP(community=community.encode())
                packet = (
                    IP(src=src_ip, dst=dst_ip) /
                    UDP(sport=src_port, dport=161) /
                    snmp_pdu
                )
                return packet
            except Exception:
                # Fall back to raw payload if SNMP construction fails
                pass
        
        # Fallback: Create SNMP-like payload that includes community string
        # This ensures the honey-token is visible even if SNMP parsing fails
        payload = f"SNMPv2-MIB::sysDescr.0 = {community}\n"
        
        packet = (
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=src_port, dport=161) /
            Raw(load=payload)
        )
        
        return packet
    
    @staticmethod
    def generate_get_request(
        src_ip: str,
        dst_ip: str,
        src_port: int,
        community: str = "private"
    ):
        """Generate an SNMP GET request with community string."""
        # Try to use Scapy's SNMP support for better Wireshark compatibility
        if SNMP_AVAILABLE:
            try:
                # Create a proper SNMP GET request
                snmp_pdu = SNMP(community=community.encode())
                packet = (
                    IP(src=src_ip, dst=dst_ip) /
                    UDP(sport=src_port, dport=161) /
                    snmp_pdu
                )
                return packet
            except Exception:
                # Fall back to raw payload
                pass
        
        # Fallback: Include community string in payload for honey-token visibility
        payload = f"GET REQUEST: community={community}, OID=1.3.6.1.2.1.1.1.0\n"
        
        packet = (
            IP(src=src_ip, dst=dst_ip) /
            UDP(sport=src_port, dport=161) /
            Raw(load=payload)
        )
        
        return packet
