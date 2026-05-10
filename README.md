
# ethoudp_iface: Ethernet over UDP interface
Creates an interface for Basilisk II / SheepShaver UDP tunnel to a Linux TAP device.

The SheepShaver and Basilisk II classic Mac emulators implement a simple, UDP-broadcast network protocol that allows virtual machines to communicate. ethoudp_iface allows a physical or virtual, Linux-based machine to communicate with the virtual machines using a TAP interface.

This allows the Linux machine to provide Internet access to the virtual machines, or other services like AppleTalk.

# IMPORTANT: This is not a full generic L2 bridge
SheepShaver/Basilisk II is hardcoded to only send unicast frames to 42:32:xx:xx:xx MACs — meaning it can only talk directly to other SheepShaver/Basilisk II instances or to our interface (which has a 42:32 MAC). 
Any other host on the network is unreachable to it at the Ethernet level.

Do not attach ethoudp_tap to a Linux bridge, it never works — the other hosts on it have normal MACs that SheepShaver/Basilisk II would never send to. So the 42:32 convention isn't just a clever trick for IP extraction — 
it's actually a hard requirement imposed by SheepShaver/Basilisk II's networking code.

Instead, use the TAP interface in a router context, either for IPv4 (e.g. by the Linux kernel) and EtherTalk (e.g. by atalkd from netatalk).

That is the reason why this project is called ethoudp_iface, not _bridge!

# Changes over the original
This code is based on sheep_bridge (https://github.com/VinDuv/sheep-bridge) by VinDuv.

Extensions include but are not limited to:
- Massively refactored code structure
- Many bugfixes
- Fixes for newr Python versions
- EtherType filtering (`--no-bridge-ipv4`, `--no-bridge-appletalk`)
- Performance improvements, e.g.:
    - using memoryview for zero-copy UDP socket writes
    - pre-computing masked MAC values for efficient matching in MacAddressFilter
    - avoid any object creation on the hot path
- Signal handling (SIGHUP, SIGINT, SIGTERM) for clean shutdown
- Statistics

Removed features:
- Creating TAP devices
- Waiting on devices to come up, have IP addresses etc.
