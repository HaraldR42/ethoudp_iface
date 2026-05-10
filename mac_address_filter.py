"""
ethoudp_iface: Ethernet over UDP interface for SheepShaver/Basilisk II
======================================================================

(c) 2026 by Harald Roelle
"""

# Bitmask-based MAC address matching for use in the Ethernet forwarding path.
# Each entry is a (mac, mask) pair; only bits set in the mask are compared,
# allowing prefix and wildcard matches without per-packet string slicing.

class MacAddressFilter:
    """Holds a list of (mac, mask) tuples and efficiently matches MAC addresses.
    Only bits set in the mask are compared. For use in the forwarding path."""

    __slots__ = ('_entries',)

    def __init__(self, entries: list[tuple[bytes, bytes]]):
        # Pre-compute masked values: (masked_mac, mask) for fast matching
        self._entries: tuple[tuple[int, int], ...] = tuple(
            self._encode(mac, mask) for mac, mask in entries
        )

    def add(self, mac: bytes, mask: bytes) -> None:
        """Add a (mac, mask) entry. Only bits set in mask are compared on match."""
        self._entries = self._entries + (self._encode(mac, mask),)

    @staticmethod
    def _encode(mac: bytes, mask: bytes) -> tuple[int, int]:
        m = int.from_bytes(mask, 'big')
        return int.from_bytes(mac, 'big') & m, m

    def matches(self, mac: bytes) -> bool:
        """Return True if mac matches any (mac, mask) entry."""
        val = int.from_bytes(mac, 'big')
        return any((val & mask) == masked for masked, mask in self._entries)
