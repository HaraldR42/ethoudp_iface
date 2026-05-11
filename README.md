
# ethoudp_iface: Ethernet over UDP interface
Creates an interface for Basilisk II / SheepShaver UDP tunnel to a Linux TAP device.

## Motivation
Running vintage Mac emulators on top of macOS, I wanted to have networking support with the following requirements:
- Use "official" builds of Basilisk II / SheepShaver. No special patches.
- Use solely mechanisms that are present in the builds.
- Work in a LAN environment, but support WiFi and wired networking.
- No additional kernel modules etc. on the host.
- No additional OpenVPN tunnels etc. on the host.
- Support of AppleTalk and IP.
- Having an additional Linux machine (at least a virtual one) is acceptable.

Current builds for macOS (based on [kanjitalk755/macemu](https://github.com/kanjitalk755/macemu)) SheepShaver/Basilisk II classic Mac emulators implement a simple, UDP-broadcast network protocol that allows virtual machines to communicate.

ethoudp_iface allows a physical or virtual, Linux-based machine to communicate with the virtual machines using a TAP interface. This allows the Linux machine to provide Internet access to the virtual machines, or other services like AppleTalk.

## IMPORTANT: This is not a full generic L2 bridge
SheepShaver/Basilisk II is hardcoded to only send unicast frames to 42:32:xx:xx:xx MACs — meaning it can only talk directly to other SheepShaver/Basilisk II instances or to our interface (which has a 42:32 MAC). 
Any other host on the network is unreachable to it at the Ethernet level.

Do not attach ethoudp_tap to a Linux bridge — it never works — the other hosts on it have normal MACs that SheepShaver/Basilisk II would never send to. So the 42:32 convention isn't just a clever trick for IP extraction — 
it's actually a hard requirement imposed by SheepShaver/Basilisk II's networking code.

Instead, use the TAP interface in a router context, both for IPv4 (e.g. by the Linux kernel) and EtherTalk (e.g. by atalkd from netatalk).

That is the reason why this project is called ethoudp_iface, not _bridge!

## Changes over the original
This code is based on sheep_bridge (https://github.com/VinDuv/sheep-bridge) by VinDuv.

Extensions include but are not limited to:
- Massively refactored code structure
- Many bugfixes
- Fixes for newer Python versions
- EtherType filtering (`--no-bridge-ipv4`, `--no-bridge-appletalk`)
- Performance improvements, e.g.:
    - using memoryview for zero-copy UDP socket writes
    - pre-computing masked MAC values for efficient matching in MacAddressFilter
    - avoiding any object creation on the hot path
- Signal handling (SIGHUP, SIGINT, SIGTERM) for clean shutdown
- Statistics

Removed features:
- Creating TAP devices
- Waiting on devices to come up, have IP addresses etc.
---
---
# Running ethoudp_iface

## Prerequisites

A Linux machine is needed with:
- Kernel supporting AppleTalk. Use Linux 6.9 or later, all prior versions are probably [affected by a bug](https://gist.github.com/VinDuv/4db433b6dce39d51a5b7847ee749b2a4).
- TAP interface support
- Python3

Overall, e.g. Debian Trixie fullfills all prerequisites.

ethoudp_iface expects two network interfaces to be present:
1) Broadcast traffic interface: Here your host running the emulator lives. *Must have an IP address before starting ethoudp_iface.*
2) ethoudp tap interface: This is the interface where the vintage Macs' traffic is made available. *Must have an IP address in the range used by the vintage Macs.*

See XXX for an example on how to configure especially the tap interface.

## Usage

Once the two required interfaces are configured and up, simply start ethoudp_iface
```
python3 ethoudp_iface.py --tap-iface ethoudp_tap --bcast-iface eth0
```

For other options, see: 
```
python3 ethoudp_iface.py --help
```
