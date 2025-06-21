"""
Author: Petr Kalabis (kalabpe4)
File: src/protocol_analysis/protocols/eth.py

Implements the Ethernet protocol analyzer for packet inspection.
This module detects Ethernet frames, extracts MAC addresses, and delegates
further parsing to encapsulated protocols like ARP and IP.
"""

from dataclasses import dataclass

from scapy.layers.l2 import Ether
from manuf import manuf

from src.protocol_analysis.protocols.protocol import Protocol
from src.protocol_analysis.protocols.ip import IPProtocol
from src.protocol_analysis.protocols.arp import ARPProtocol


@dataclass
class EthernetInfo:
    """
    Structured data representation for Ethernet header fields.

    Attributes:
        src_mac (str): Source MAC address with optional vendor.
        dst_mac (str): Destination MAC address with optional vendor.
        eth_type (str): Interpreted Ethernet type as string.
    """
    src_mac: str
    dst_mac: str
    eth_type: str


class EthernetProtocol(Protocol):
    """
    Protocol analyzer for Ethernet packets.

    Identifies Ethernet frames and extracts relevant header information,
    then delegates analysis to ARP or IP protocols as applicable.
    """

    ETHERTYPE_MAP = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "802.1Q VLAN",
        0x8847: "MPLS unicast",
        0x8848: "MPLS multicast",
        0x88CC: "LLDP",
        0x88E5: "MACsec",
        0x88F7: "PTP",
    }

    def identify(self) -> bool:
        """
        Check whether the packet contains an Ethernet layer.

        Return:
            bool: True if Ethernet layer is present.
        """
        return Ether in self.packet

    def parse_layer_details(self) -> dict:
        """
        Extract source/destination MAC addresses and ethertype.

        Return:
            dict: Dictionary of Ethernet header fields.
        """
        print("ETH\n")
        try:
            eth = self.packet[Ether]
            eth_type = eth.type
            eth_type_hex = f"0x{eth_type:04x}"
            eth_type_desc = self.ETHERTYPE_MAP.get(eth_type, "Unknown")

            info = EthernetInfo(
                src_mac=self.format_mac_with_vendor(eth.src),
                dst_mac=self.format_mac_with_vendor(eth.dst),
                eth_type=f"{eth_type_desc} ({eth_type_hex})"
            )
            return info.__dict__
        except (AttributeError, TypeError) as e:
            return {
                "src_mac": "ERROR",
                "dst_mac": "ERROR",
                "eth_type": f"ParseError ({type(e).__name__})"
            }

    def get_summary(self) -> dict:
        """
        Generate a simple summary string from Ethernet frame.

        Return:
            dict: Summary including source and destination MAC addresses.
        """
        try:
            eth = self.packet[Ether]
            return {
                "protocol": "Ethernet",
                "src": eth.src,
                "dst": eth.dst,
                "src_port": "",
                "dst_port": "",
                "summary": f"Ethernet frame from {eth.src} to {eth.dst}"
            }
        except (AttributeError, TypeError):
            return {
                "protocol": "Ethernet",
                "src": "ERROR",
                "dst": "ERROR",
                "src_port": "",
                "dst_port": "",
                "summary": "Malformed Ethernet frame"
            }

    def next_protocol(self):
        """
        Determine the next protocol analyzer (ARP or IP) based on ethertype.

        Return:
            Protocol | None: An instance of the next protocol analyzer, or None.
        """
        next_protocols = [ARPProtocol, IPProtocol]
        for protocol_name in next_protocols:
            protocol = protocol_name(self.packet)
            if protocol.identify():
                return protocol
        return None

    @staticmethod
    def format_mac_with_vendor(mac: str) -> str:
        """
        Format MAC address with resolved vendor name.

        Args:
            mac (str): MAC address string.

        Return:
            str: Uppercase MAC with vendor in parentheses.
        """
        parser = manuf.MacParser()
        mac_lower = mac.lower()
        try:
            if mac_lower == "ff:ff:ff:ff:ff:ff":
                vendor = "Broadcast"
            elif mac_lower.startswith(("33:33", "01:00:5e")):
                vendor = "Multicast"
            else:
                vendor = parser.get_manuf(mac) or "Unknown"
        except (ValueError, TypeError) as e:
            vendor = f"ParseError ({type(e).__name__})"
        return f"{mac.upper()} ({vendor})"
