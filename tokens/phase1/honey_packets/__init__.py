"""
Oracle Defense - Phase 1: Router Honey-Packets

This module synthesizes and injects Honey-Packets into a network stream.
These packets simulate high-value "Management Plane" sessions on a router,
creating "ghost" traffic as a tripwire for threat detection.
"""

from .injector import HoneyPacketInjector
from .protocols import TelnetHoney, SSHHoney, SNMPHoney
from .config import HoneyPacketConfig

__all__ = ['HoneyPacketInjector', 'TelnetHoney', 'SSHHoney', 'SNMPHoney', 'HoneyPacketConfig']
