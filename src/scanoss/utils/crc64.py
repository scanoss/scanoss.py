import struct
from typing import List


class CRC64:
    """
    CRC64 ECMA implementation matching Go's hash/crc64 package.
    Uses polynomial: 0xC96C5795D7870F42
    """

    POLY = 0xC96C5795D7870F42
    _TABLE = None

    def __init__(self):
        if CRC64._TABLE is None:
            CRC64._TABLE = self._make_table()
        self.crc = 0xFFFFFFFFFFFFFFFF  # Initial value

    def _make_table(self) -> list[int]:
        """Generate the CRC64 lookup table."""
        table = []
        for i in range(256):
            crc = i
            for _ in range(8):
                if crc & 1:
                    crc = (crc >> 1) ^ self.POLY
                else:
                    crc >>= 1
            table.append(crc)
        return table

    def update(self, data: bytes) -> None:
        """Update the CRC with new data."""
        if isinstance(data, str):
            data = data.encode('utf-8')

        crc = self.crc
        for b in data:
            crc = (crc >> 8) ^ CRC64._TABLE[(crc ^ b) & 0xFF]  # Use class-level table
        self.crc = crc

    def digest(self) -> int:
        """Get the current CRC value."""
        return self.crc ^ 0xFFFFFFFFFFFFFFFF  # Final XOR value

    def hexdigest(self):
        """Get the current CRC value as a hexadecimal string."""
        return format(self.digest(), '016x')

    def checksum(cls, data: bytes) -> int:
        """Calculate CRC64 checksum for the given data."""
        crc = cls()
        crc.update(data)
        return crc.digest()

    @classmethod
    def get_hash_buff(cls, buff: bytes) -> List[bytes]:
        """
        Get the hash value of the given buffer, and converts it to 8 bytes in big-endian order.

        Args:
            buff (bytes): The buffer to get the hash value of.

        Returns:
            bytes: The hash value of the given buffer, and converts it to 8 bytes in big-endian order.
        """
        crc = cls()
        crc.update(buff)
        hash_val = crc.digest()

        return list(struct.pack('>Q', hash_val))


print(CRC64.get_hash_buff('Hello, World!'))
