# EthernetOverUDP_iface
#
# ethernet_frame.py
# Ethernet frame types and frame parser for logging and debugging purposes.
# EthernetFrameAnalyzer is not used in the forwarding path — parsing overhead
# is only acceptable for debug output.

import ipaddress
import socket
import struct
from enum import Enum, IntEnum


class EtherTypes(IntEnum):
    IPv4      = 0x0800
    ARP       = 0x0806
    AppleTalk = 0x809B
    AARP      = 0x80F3


# Generic Ethernet broadcast address (used for both IPv4 and AppleTalk)
# Address               Purpose
# --------------------  ----------------------------------
# ff:ff:ff:ff:ff:ff     Standard Ethernet broadcast

# AppleTalk multicast addresses (for reference, not all may be bridged depending on config)
# Address               Purpose
# --------------------  ----------------------------------
# 09:00:07:ff:ff:ff     AppleTalk all-zones broadcast
# 09:00:07:00:00:00-ff  Zone 0-255 multicast
# 09:00:07:00:00:fc     NBP forward request
# 09:00:07:00:00:fd     NBP lookup
# 09:00:07:00:00:fe     ZIP multicast
# 09:00:07:00:00:ff     AARP / general AppleTalk multicast

# IPv4 multicast addresses (for reference, not all may be bridged depending on config)
# Address               Purpose
# --------------------  ----------------------------------
# ff:ff:ff:ff:ff:ff     Broadcast (e.g. ARP requests)
# 01:00:5e:00:00:00     IPv4 multicast base
#   ...through...
# 01:00:5e:7f:ff:ff     IPv4 multicast top

class DstMacType(Enum):
    UNICAST                = 'unicast'
    BROADCAST              = 'broadcast'
    APPLETALK_ALLZONES     = 'AppleTalk all-zones broadcast'
    APPLETALK_ZONE         = 'AppleTalk zone multicast'
    APPLETALK_NBP_FORWARD  = 'AppleTalk NBP forward request'
    APPLETALK_NBP_LOOKUP   = 'AppleTalk NBP lookup'
    APPLETALK_ZIP          = 'AppleTalk ZIP multicast'
    APPLETALK_AARP         = 'AppleTalk AARP multicast'
    APPLETALK_MULTICAST    = 'AppleTalk multicast'
    IPV4_MULTICAST         = 'IPv4 multicast'
    IPV6_MULTICAST         = 'IPv6 multicast'
    MULTICAST              = 'multicast'


class EthernetFrameAnalyzer:
    """Represents a parsed Ethernet frame for logging/debugging purposes.
    Not used in the forwarding path — parsing overhead is acceptable only for debug output."""

    def __init__(self, buffer: bytes | bytearray, length: int):
        self.length  = length
        self.src_mac    = bytes(buffer[6:12])
        self.dst_mac    = bytes(buffer[0:6])
        self.dst_mac_type = self._classify_dst_mac(self.dst_mac)

        # Determine EtherType (Ethernet II or 802.3+LLC/SNAP)
        val = struct.unpack_from('!H', buffer, 12)[0]
        if val > 1500:
            self.ethertype = val
            payload = bytes(buffer[14:length])
        elif length >= 22 and buffer[14:17] == b'\xaa\xaa\x03':
            self.ethertype = struct.unpack_from('!H', buffer, 20)[0]
            payload = bytes(buffer[22:length])
        else:
            self.ethertype = 0
            payload = bytes(buffer[14:length])

        self.src_ip: ipaddress.IPv4Address | None = None
        self.dst_ip: ipaddress.IPv4Address | None = None
        self.src_atalk: str | None = None
        self.dst_atalk: str | None = None

        if self.ethertype == EtherTypes.IPv4 and len(payload) >= 20:
            self.src_ip = ipaddress.IPv4Address(payload[12:16])
            self.dst_ip = ipaddress.IPv4Address(payload[16:20])
        elif self.ethertype == EtherTypes.ARP and len(payload) >= 28:
            self.src_ip = ipaddress.IPv4Address(payload[14:18])
            self.dst_ip = ipaddress.IPv4Address(payload[24:28])
        elif self.ethertype == EtherTypes.AppleTalk and len(payload) >= 12:
            # DDP long header: dst_net(2), src_net(2), dst_node(1), src_node(1), ...
            dst_net, src_net, dst_node, src_node = struct.unpack_from('!HHBB', payload, 4)
            self.src_atalk = f'{src_net}.{src_node}'
            self.dst_atalk = f'{dst_net}.{dst_node}'
        elif self.ethertype == EtherTypes.AARP and len(payload) >= 28:
            # AARP: src_atalk at offset 14 (net+node), dst_atalk at offset 24 (net+node)
            src_net, src_node = struct.unpack_from('!HB', payload, 14)
            dst_net, dst_node = struct.unpack_from('!HB', payload, 24)
            self.src_atalk = f'{src_net}.{src_node}'
            self.dst_atalk = f'{dst_net}.{dst_node}'

    @property
    def ethertype_str(self) -> str:
        try:
            return EtherTypes(self.ethertype).name
        except ValueError:
            return f'0x{self.ethertype:04X}' if self.ethertype else 'UNKNOWN'

    @staticmethod
    def _classify_dst_mac(mac: bytes) -> DstMacType:
        if mac == b'\xff\xff\xff\xff\xff\xff':
            return DstMacType.BROADCAST
        if mac == b'\x09\x00\x07\xff\xff\xff':
            return DstMacType.APPLETALK_ALLZONES
        if mac[:5] == b'\x09\x00\x07\x00\x00':
            return {
                0xfc: DstMacType.APPLETALK_NBP_FORWARD,
                0xfd: DstMacType.APPLETALK_NBP_LOOKUP,
                0xfe: DstMacType.APPLETALK_ZIP,
                0xff: DstMacType.APPLETALK_AARP,
            }.get(mac[5], DstMacType.APPLETALK_ZONE)
        if mac[:3] == b'\x09\x00\x07':
            return DstMacType.APPLETALK_MULTICAST
        if mac[:3] == b'\x01\x00\x5e' and not (mac[3] & 0x80):
            return DstMacType.IPV4_MULTICAST
        if mac[:2] == b'\x33\x33':
            return DstMacType.IPV6_MULTICAST
        if mac[0] & 0x01:
            return DstMacType.MULTICAST
        return DstMacType.UNICAST

    @staticmethod
    def format_mac(mac: bytes) -> str:
        return ':'.join('%02x' % b for b in mac)

    def __str__(self) -> str:
        if self.dst_mac_type == DstMacType.UNICAST:
            dst_type = ''
        elif self.dst_mac_type == DstMacType.APPLETALK_ZONE:
            dst_type = f' (AppleTalk zone {self.dst_mac[5]} multicast)'
        else:
            dst_type = f' ({self.dst_mac_type.value})'
        s = (f'[{self.ethertype_str}] '
             f'{self.format_mac(self.src_mac)} → {self.format_mac(self.dst_mac)}{dst_type}  '
             f'len={self.length}')
        if self.src_ip is not None:
            s += f'  {self.src_ip} → {self.dst_ip}'
        elif self.src_atalk is not None:
            s += f'  {self.src_atalk} → {self.dst_atalk}'
        return s


class VmMacAddress:
    """ Utility class for handling VM MAC addresses.
        Basilisk II/SheepShaver just concatenates the 2-byte prefix VM_MAC_PREFIX directly with
        the 4 raw bytes of the host IP address.
        So for 172.29.0.33 (ac:1d:00:21), the MAC is simply 42:32:ac:1d:00:21.
        This is not a real OUI-based MAC — it's a private convention used by Basilisk II/SheepShaver
        specifically so the bridge can extract the destination IP directly from the destination MAC
        for unicast routing, without needing an ARP table.
        The 42 prefix has the locally-administered bit set (0x42 = 0100 0010), which is correct for a locally-assigned MAC."""

    VM_MAC_PREFIX = b'\x42\x32'  # First 2 bytes of a VM MAC address

    @classmethod
    def from_ip(cls, ip: str) -> bytes:
        return cls.VM_MAC_PREFIX + socket.inet_aton(ip)

    @classmethod
    def to_ip(cls, mac: bytes) -> str | None:
        if len(mac) != 6 or not mac.startswith(cls.VM_MAC_PREFIX):
            return None
        return socket.inet_ntoa(mac[2:])


