import os
from typing import Optional

from scanoss.scanners.scanner_config import ScannerConfig
from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc


class ScannerHFH(ScanossBase):
    """
    SCANOSS Folder Hashing Scanner
    Handle the folder hashing scan of a directory
    """

    def __init__(
        self,
        scan_dir: str,
        config: Optional[ScannerConfig],
        client: Optional[ScanossGrpc],
    ):
        super().__init__(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )

        self.scan_dir = scan_dir
        self.client = client

    def scan(self):
        """
        Given a folder path, recursively collect all file names (without path),
        compute a CRC64 hash for each filename, sort them for deterministic results,
        and concatenate the resulting hex strings.
        """

        file_hashes = self._get_file_hashes()
        file_hashes_str = ''.join(file_hashes)

        print(file_hashes_str)

    def _get_file_hashes(self):
        """
        Given a folder path, recursively collect all file names (without path),
        compute a CRC64 hash for each filename, sort them for deterministic results,
        and concatenate the resulting hex strings.
        """

        file_hashes = []
        for _, _, files in os.walk(self.scan_dir):
            for file in files:
                file_hashes.append(self._get_file_hash(file))

        return sorted(file_hashes)

    def _get_file_hash(self, filename: str) -> str:
        """
        Compute a CRC64 hash (as a 16-character hex string) for a given filename
        """
        from crc import Calculator, Crc64

        calculator = Calculator(Crc64.CRC64)
        result = calculator.checksum(filename.encode('utf-8'))
        return format(result, '016x')
