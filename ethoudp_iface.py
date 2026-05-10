#!/usr/bin/env python3
"""
ethoudp_iface: Ethernet over UDP interface
==========================================
Based on sheep_bridge by VinDuv.
Creates an interface for Basilisk II / SheepShaver UDP tunnel to a Linux TAP device.

IMPORTANT: This is not a generic L2 bridge
Basilisk II is hardcoded to only send unicast frames to 42:32:xx:xx:xx MACs — meaning it can only talk 
directly to other Basilisk II/SheepShaver instances or to our interface (which has a 42:32 MAC). 
Any other host on the network is unreachable to it at the Ethernet level.

Do not attach ethoudp_tap to a Linux bridge, it never works — the other hosts on it have normal MACs 
that Basilisk II would never send to. So the 42:32 convention isn't just a clever trick for IP extraction — 
it's actually a hard requirement imposed by Basilisk II's networking code.

Instead, use the TAP interface in a router, either for IPv4 (e.g. by the Linux kernel) and 
EtherTalk (e.g. by atalkd from netatalk).

That is the reason why this project is called EthernetOverUdp_iface, not _bridge!

Extensions over the original:
    - Massively refactored code structure
    - Bugfixes
    - EtherType filtering (--no-bridge-ipv4, --no-bridge-appletalk)
    - Signal handling (SIGHUP, SIGINT, SIGTERM) for clean shutdown
    - Carrier on for the TAP interface
    - Performance improvements (e.g. using memoryview for zero-copy UDP socket writes, pre-computing masked MAC values for efficient matching in MacAddressFilter)
"""

import argparse
import logging
import asyncio
import errno
import fcntl
import ipaddress
import copy
from ethernet_frame import EtherTypes, EthernetFrameAnalyzer, VmMacAddress
from mac_address_filter import MacAddressFilter
import os
import signal
import socket
import struct
import sys


allowed_mcast = MacAddressFilter([
    (b'\xff\xff\xff\xff\xff\xff', b'\xff\xff\xff\xff\xff\xff'),  # Broadcast
    (b'\x09\x00\x07\x00\x00\x00', b'\xff\xff\xff\x00\x00\x00'),  # AppleTalk zone multicast
    (b'\x01\x00\x5e\x00\x00\x00', b'\xff\xff\xff\x80\x00\x00'),  # IPv4 multicast
])


class LinuxNetConstants:
    TUNSETIFF      = 0x400454CA
    IFF_TAP        = 0x0002
    IFF_NO_PI      = 0x1000
    TUNSETCARRIER  = 0x400454E2
    SIOCSIFFLAGS   = 0x8914
    SIOCGIFFLAGS   = 0x8913
    IFF_PROMISC    = 0x0100
    IFF_UP         = 0x0001
    SIOCSIFHWADDR  = 0x8924
    ARPHRD_ETHER   = 1
    SIOCGIFADDR    = 0x8915
    SIOCGIFNETMASK = 0x891b
    SIOCGIFHWADDR  = 0x8927

# Maximum Ethernet frame size (1522 = 1500 payload + 14 header + 4 FCS + 4 VLAN tag)
MAX_FRAME_SIZE = 1522


class NetworkStatistics:
    def __init__(self):
        self.error_wrong_length      = 0
        self.error_wrong_ethertype   = 0
        self.error_vmmac_ip_mismatch = 0
        self.error_illegal_dest_mac  = 0

    def __str__(self) -> str:
        return (f'wrong_length={self.error_wrong_length}  '
                f'wrong_ethertype={self.error_wrong_ethertype}  '
                f'vmmac_ip_mismatch={self.error_vmmac_ip_mismatch}  '
                f'illegal_dest_mac={self.error_illegal_dest_mac}')


class BridgeDevice:
    @staticmethod
    def _addr_from_iface(iface: str) -> ipaddress.IPv4Interface:
        """Derive IPv4Interface from a network interface name using SIOCGIFADDR/SIOCGIFNETMASK."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifreq = struct.pack('256s', iface.encode()[:15])
                ip_packed   = fcntl.ioctl(s, LinuxNetConstants.SIOCGIFADDR,    ifreq)[20:24]
                mask_packed = fcntl.ioctl(s, LinuxNetConstants.SIOCGIFNETMASK, ifreq)[20:24]
                ip   = ipaddress.IPv4Address(ip_packed)
                mask = ipaddress.IPv4Address(mask_packed)
                return ipaddress.IPv4Interface(f'{ip}/{mask}')
        except OSError:
            raise RuntimeError('Failed to determine IP address for interface %s' % iface)

    @staticmethod
    def _mac_from_iface(iface: str) -> bytes:
        """Return the hardware MAC address of a network interface."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                ifreq = struct.pack('256s', iface.encode()[:15])
                result = fcntl.ioctl(s, LinuxNetConstants.SIOCGIFHWADDR, ifreq)
                return result[18:24]
        except OSError:
            raise RuntimeError('Failed to determine MAC address for interface %s' % iface)

    def __init__(self, bridge: 'NetworkBridge', iface: str, evt_loop: asyncio.AbstractEventLoop):
        self.stats:NetworkStatistics = NetworkStatistics()
        self._bridge: NetworkBridge               = bridge
        self._evt_loop: asyncio.AbstractEventLoop = evt_loop
        self._iface: str                          = iface
        self._iface_addr: ipaddress.IPv4Interface = BridgeDevice._addr_from_iface(iface)
        self._iface_mac: bytes                    = BridgeDevice._mac_from_iface(iface)
        self._buf: bytearray                      = bytearray(MAX_FRAME_SIZE)

    @property
    def iface(self) -> str:
        return self._iface
    
    @property
    def iface_addr(self) -> ipaddress.IPv4Interface:
        return self._iface_addr
    
    @property
    def iface_mac(self) -> bytes:
        return self._iface_mac


class TapDevice(BridgeDevice):
    """A TAP device to send and receive raw Ethernet frames."""

    def __init__(self, bridge: 'NetworkBridge', tap_iface: str, tunnel_ip: ipaddress.IPv4Address, evt_loop: asyncio.AbstractEventLoop):
        super().__init__(bridge, tap_iface, evt_loop)

        self._fd: int = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)

        ifreq = struct.pack('@16sh', bytes(tap_iface, 'utf-8'), LinuxNetConstants.IFF_TAP | LinuxNetConstants.IFF_NO_PI)
        fcntl.ioctl(self._fd, LinuxNetConstants.TUNSETIFF, ifreq)

        # Set VM-style MAC address
        self._iface_mac: bytes = VmMacAddress.from_ip(str(tunnel_ip))
        ifreq = struct.pack('@16sh6s', b'', LinuxNetConstants.ARPHRD_ETHER, self._iface_mac)
        fcntl.ioctl(self._fd, LinuxNetConstants.SIOCSIFHWADDR, ifreq)

        # Set promiscuous + up
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            ifreq_flags = struct.pack('16sH', bytes(tap_iface, 'utf-8'), 0)
            ifreq_flags = fcntl.ioctl(s, LinuxNetConstants.SIOCGIFFLAGS, ifreq_flags)
            flags = struct.unpack('16sH', ifreq_flags)[1] | LinuxNetConstants.IFF_PROMISC | LinuxNetConstants.IFF_UP
            fcntl.ioctl(s, LinuxNetConstants.SIOCSIFFLAGS, struct.pack('16sH', bytes(tap_iface, 'utf-8'), flags))

        # Set carrier "on" so br0 (if member) treats port as active
        fcntl.ioctl(self._fd, LinuxNetConstants.TUNSETCARRIER, struct.pack('I', 1))

        self._evt_loop.add_reader(self._fd, self._data_available)

    def write_from(self, buffer: bytes | bytearray, length: int) -> None:
        try:
            os.write(self._fd, memoryview(buffer)[:length])
        except OSError as err:
            if err.errno != errno.EIO:
                raise
            logging.error('Unable to write to TAP device. Is interface up?')

    def close(self) -> None:
        self._evt_loop.remove_reader(self._fd)
        os.close(self._fd)

    def _data_available(self) -> None:
        length: int = os.readv(self._fd, [self._buf])
        self._bridge.handle_tap_data(self._buf, length)


class NetworkSockets(BridgeDevice):
    """Manages UDP sockets for communicating with VMs."""

    def __init__(self, bridge: 'NetworkBridge', bcast_iface: str, bcast_port: int, evt_loop: asyncio.AbstractEventLoop):
        super().__init__(bridge, bcast_iface, evt_loop)

        self._port: int = bcast_port

        self._ucast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._ucast_sock.bind((str(self._iface_addr.ip), self._port))

        self._bcast_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._bcast_sock.bind(('<broadcast>', self._port))
        self._bcast_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

        self._evt_loop.add_reader(self._bcast_sock, self._data_available, self._bcast_sock)
        self._evt_loop.add_reader(self._ucast_sock, self._data_available, self._ucast_sock)

    def send_broadcast(self, buffer: bytes | bytearray, length: int) -> None:
        self._bcast_sock.sendto(memoryview(buffer)[:length], ('<broadcast>', self._port))

    def send_unicast(self, address: str, buffer: bytes | bytearray, length: int) -> None:
        self._ucast_sock.sendto(memoryview(buffer)[:length], (address, self._port))

    def close(self) -> None:
        for sock in (self._ucast_sock, self._bcast_sock):
            self._evt_loop.remove_reader(sock)
            sock.close()

    def _data_available(self, sock: socket.socket) -> None:
        length: int
        addr_port: tuple[str, int]
        length, addr_port = sock.recvfrom_into(self._buf)
        self._bridge.handle_sock_data(addr_port[0], self._buf, length)


class NetworkBridge():
    """Bridges the TAP device and network sockets with EtherType filtering."""

    def __init__(self, tap_iface: str, bcast_iface: str, bcast_port: int, bridge_ipv4: bool, bridge_appletalk: bool, evt_loop: asyncio.AbstractEventLoop):
        self.net_sockets: NetworkSockets  = NetworkSockets(self, bcast_iface, bcast_port, evt_loop)
        self.tap_device: TapDevice        = TapDevice(self, tap_iface, self.net_sockets.iface_addr.ip, evt_loop)

        self._tunnel_ip: str            = str(self.net_sockets.iface_addr.ip)
        self._tunnel_net_addr_int:  int = int.from_bytes(self.net_sockets.iface_addr.network.network_address.packed, 'big')
        self._tunnel_net_mask_int:  int = int.from_bytes(self.net_sockets.iface_addr.network.netmask.packed, 'big')
        self._tunnel_net_bcast_int: int = self._tunnel_net_addr_int | (~self._tunnel_net_mask_int & 0xFFFFFFFF)

        self._allowed_dest_macs_sock = copy.copy(allowed_mcast)
        self._allowed_dest_macs_sock.add(self.tap_device.iface_mac, b'\xff\xff\xff\xff\xff\xff')

        self._allowed_dest_macs_tap = copy.copy(allowed_mcast)

        # Build allowed EtherType set
        etypes: set[int] = set()
        if bridge_ipv4:
            etypes |= {EtherTypes.IPv4, EtherTypes.ARP}
        if bridge_appletalk:
            etypes |= {EtherTypes.AppleTalk, EtherTypes.AARP}
        self._allowed_etypes: frozenset[int] = frozenset(etypes)

    def close(self) -> None:
        self.net_sockets.close()
        self.tap_device.close()

    def _is_allowed_frame(self, buffer: bytes | bytearray, length: int, stats: NetworkStatistics) -> bool:
        if length < 14 or length > MAX_FRAME_SIZE:
            stats.error_wrong_length += 1
            return False
        # check ethertype for both Ethernet II and 802.3+LLC/SNAP frames
        val = struct.unpack_from('!H', buffer, 12)[0]
        ethertype = 0
        if val > 1500:  # Ethernet II framing with EtherType in bytes 12-13
            ethertype = val
        elif length >= 22 and buffer[14:17] == b'\xaa\xaa\x03':  # 802.3+LLC/SNAP with EtherType in bytes 20-21
            ethertype = struct.unpack_from('!H', buffer, 20)[0]
        if ethertype in self._allowed_etypes:
            return True
        stats.error_wrong_ethertype += 1
        return False

    def handle_tap_data(self, buffer: bytes | bytearray, length: int) -> None:
        if not self._is_allowed_frame(buffer, length, self.tap_device.stats):
            # stats are updated in _is_allowed_frame, so we can just ignore the frame here
            return

        dest_mac = buffer[0:6]

        # Unicast: VM MAC encodes the target IP in bytes 2-5; validate it's a usable host in our subnet
        if dest_mac[:2] == VmMacAddress.VM_MAC_PREFIX:
            addr_int = int.from_bytes(dest_mac[2:6], 'big')
            if ((addr_int & self._tunnel_net_mask_int) != self._tunnel_net_addr_int
                    or addr_int == self._tunnel_net_addr_int
                    or addr_int == self._tunnel_net_bcast_int):
                self.tap_device.stats.error_vmmac_ip_mismatch += 1
                logging.warning('Incorrect destination MAC %s: %s not a valid local IPv4 address',
                                EthernetFrameAnalyzer.format_mac(dest_mac), socket.inet_ntoa(dest_mac[2:6]))
                return
            #logging.debug('Sending frame to ucast socket: %s', EthernetFrameAnalyzer(buffer, length))
            self.net_sockets.send_unicast(socket.inet_ntoa(dest_mac[2:6]), buffer, length)
            return

        # From here on, it's either broadcast or multicast. Both are sent via broadcast socket, but we can still filter them.

        if not self._allowed_dest_macs_tap.matches(dest_mac):
            logging.warning('Unrecognized destination MAC: %s', EthernetFrameAnalyzer.format_mac(dest_mac))
            return

        #logging.debug('Sending frame to socket: %s', EthernetFrameAnalyzer(buffer, length))
        self.net_sockets.send_broadcast(buffer, length)

    def handle_sock_data(self, source_ip: str, buffer: bytes | bytearray, length: int) -> None:
        if not self._is_allowed_frame(buffer, length, self.net_sockets.stats):
            # stats are updated in _is_allowed_frame, so we can just ignore the frame here
            return

        if source_ip == self._tunnel_ip: # Own rebroadcasted frame, ignore
            # No error stats update here since this is expected behavior, not a malformed frame
            # logging.debug('Dropping frame from address %s: %s', source_ip, EthernetFrameAnalyzer(buffer, length))
            return

        source_mac   = buffer[6:12]
        expected_mac = VmMacAddress.from_ip(source_ip)
        if source_mac != expected_mac:
            self.net_sockets.stats.error_vmmac_ip_mismatch += 1
            # Basilisk sometimes picks up the wrong IP from the host, therefore this check is useful.
            logging.warning('Mismatch source MAC/IP: %s; expected %s', EthernetFrameAnalyzer(buffer, length), EthernetFrameAnalyzer.format_mac(expected_mac))
            return

        dest_mac = buffer[0:6]
        if not self._allowed_dest_macs_sock.matches(dest_mac):
            self.net_sockets.stats.error_illegal_dest_mac += 1
            logging.warning('Illegal destination MAC: %s', EthernetFrameAnalyzer.format_mac(dest_mac))
            return

        # logging.debug('Sending frame to tap: %s', EthernetFrameAnalyzer(buffer, length))
        self.tap_device.write_from(buffer, length)


def main() -> int:
    def _request_stop(sig: int) -> None:
        logging.info('Received %s — shutting down', signal.Signals(sig).name)
        stop.set()
    
    async def _wait_for_stop():
        await stop.wait()

    async def _log_stats_periodically():
        while True:
            try:
                await asyncio.wait_for(stop.wait(), timeout=config.stats_interval)
                break
            except asyncio.TimeoutError:
                logging.info('TAP stats:   %s', bridge.tap_device.stats)
                logging.info('Bcast stats: %s', bridge.net_sockets.stats)

    parser = argparse.ArgumentParser(
        description='ethoudp_iface: Linux Ethernet over UDP interface for Basilisk II / SheepShaver'
    )
    parser.add_argument('--tap-iface', type=str, default='ethoudp_tap', help='TAP interface name')
    parser.add_argument('--bcast-iface', type=str, default='eth0', help='Network interface to derive IP/mask from (default: eth0)')
    parser.add_argument('--bcast-port', type=int, default=6066, help="UDP port matching Basilisk II 'udpport' pref")
    parser.add_argument('--no-bridge-ipv4', dest='bridge_ipv4',
                        action='store_false', default=True,
                        help='Disable IPv4/ARP bridging')
    parser.add_argument('--no-bridge-appletalk', dest='bridge_appletalk',
                        action='store_false', default=True,
                        help='Disable AppleTalk/AARP bridging')
    parser.add_argument('--log-level', default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                        help='Set the logging level (default: INFO)')
    parser.add_argument('--statistics', action='store_true', default=False,
                        help='Periodically log error statistics for TAP and Bcast devices')
    parser.add_argument('--stats-interval', type=int, default=60, metavar='SECONDS',
                        help='Statistics logging interval in seconds (default: 60)')
    config = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, config.log_level),
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%H:%M:%S',
    )

    for iface, hint in (
        (config.tap_iface,   'check --tap-iface'),
        (config.bcast_iface, 'check --bcast-iface'),
    ):
        try:
            socket.if_nametoindex(iface)
        except OSError:
            logging.error('Interface %r does not exist (%s)', iface, hint.format(iface=iface))
            return 1

    try:
        evt_loop = asyncio.new_event_loop()

        bridge = NetworkBridge(config.tap_iface, config.bcast_iface, config.bcast_port, config.bridge_ipv4, config.bridge_appletalk, evt_loop)
        logging.info('TAP setup: Iface: %s  IPv4: %s/%s  MAC: %s', 
                     bridge.tap_device.iface, bridge.tap_device.iface_addr.ip, bridge.tap_device.iface_addr.network.netmask, EthernetFrameAnalyzer.format_mac(bridge.tap_device.iface_mac))
        logging.info('Bcast setup: Iface: %s  IPv4: %s/%s  MAC: %s', 
                     bridge.net_sockets.iface, bridge.net_sockets.iface_addr.ip, bridge.net_sockets.iface_addr.network.netmask, EthernetFrameAnalyzer.format_mac(bridge.net_sockets.iface_mac))

        # Signal handling for clean shutdown
        stop = asyncio.Event()

        for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            evt_loop.add_signal_handler(sig, _request_stop, sig)

        try:
            coros = [_wait_for_stop()]
            if config.statistics:
                coros.append(_log_stats_periodically())
            evt_loop.run_until_complete(asyncio.gather(*coros))
        finally:
            bridge.close()
            evt_loop.close()
    except Exception:
        logging.exception('Fatal error')
        return 1
    
    return 0

if __name__ == '__main__':
    exit_code = main()
    logging.info('ethoudp_iface shutdown complete')
    sys.exit(exit_code)