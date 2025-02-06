import os
from pathlib import Path
from typing import Dict, List, Optional

import crc
from simhash import Simhash

from scanoss.file_filters import FileFilters
from scanoss.scanners.scanner_config import ScannerConfig
from scanoss.scanoss_settings import ScanossSettings
from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc


class DirectoryNode:
    """
    Represents a node in the directory tree for folder hashing.
    """

    def __init__(self, path: str):
        self.path = path
        self.is_dir = True
        self.children: Dict[str, DirectoryNode] = {}
        self.files: List[dict] = []


def head_calc(sim_hash: int) -> int:
    """
    Compute the head value from a simhash integer.

    The function extracts each byte from the simhash, multiplies it by 2,
    sums these values, then shifts the result right by 4 bits and returns the lowest 8 bits.

    Args:
        sim_hash (int): The input simhash value.

    Returns:
        int: The computed head value as an 8-bit integer.
    """
    total = 0
    for i in range(8):
        # Extract each byte and multiply by 2
        b = (sim_hash >> (i * 8)) & 0xFF
        total += b * 2
    # Shift right by 4 bits and extract the lowest 8 bits
    return (total >> 4) & 0xFF


class ScannerHFH(ScanossBase):
    """
    Folder Hashing Scanner.

    This scanner processes a directory, computes CRC64 hashes for the files,
    and calculates simhash values based on file names and content to detect folder-level similarities.
    """

    def __init__(
        self,
        scan_dir: str,
        config: ScannerConfig,
        client: ScanossGrpc,
        scanoss_settings: Optional[ScanossSettings] = None,
    ):
        """
        Initialize the ScannerHFH.

        Args:
            scan_dir (str): The directory to be scanned.
            config (ScannerConfig): Configuration parameters for the scanner.
            client (ScanossGrpc): gRPC client for communicating with the scanning service.
            scanoss_settings (Optional[ScanossSettings]): Optional settings for Scanoss.
        """
        super().__init__(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )

        self.scan_dir = scan_dir
        self.client = client
        self.file_filters = FileFilters(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
            scanoss_settings=scanoss_settings,
        )
        self.crc_calculator = crc.Calculator(
            crc.Crc64.CRC64,
            optimized=True,
        )

    def scan(self) -> Optional[Dict]:
        """
        Scan the provided directory using the folder hashing algorithm.

        Returns:
            Optional[Dict]: The folder hash response from the gRPC client, or None if an error occurs.
        """
        hfh_request = {
            'root': self.hfh_request_from_path(self.scan_dir),
            'threshold': 100,
            'best_match': False,
        }

        response = self.client.folder_hash_scan(hfh_request)
        return response

    def _crc64_hash(self, data: bytes) -> bytes:
        """
        Calculate the CRC64 hash using the ECMA-182 standard.

        Args:
            data (bytes): The data to hash.

        Returns:
            bytes: The 8-byte binary representation of the CRC64 hash.
        """
        checksum = self.crc_calculator.checksum(data)
        return checksum.to_bytes(8, byteorder='big')

    def hfh_request_from_path(self, path: str) -> dict:
        """
        Generate the folder hashing request structure from a directory path.

        This method builds a directory tree (DirectoryNode) and computes the associated
        hash data for the folder.

        Args:
            path (str): The root directory path.

        Returns:
            dict: The folder hash request structure.
        """
        absolute_path = str(Path(path).resolve())
        self.root_node = self._build_root_node(absolute_path)
        return self._hash_calc_from_node(self.root_node)

    def _build_root_node(self, path: str) -> DirectoryNode:
        """
        Build a directory tree from the given path with file information.

        The tree includes DirectoryNode objects populated with filtered file items,
        each containing their relative path and CRC64 hash key.

        Args:
            path (str): The directory path to build the tree from.

        Returns:
            DirectoryNode: The root node representing the directory.
        """
        root = Path(path).resolve()
        root_node = DirectoryNode(str(root))

        # Get filtered files using FileFilters
        filtered_files = [Path(f) for f in self.file_filters.get_filtered_files_from_folder(path)]

        for file_path in filtered_files:
            try:
                full_file_path = file_path if file_path.is_absolute() else root / file_path

                # Apply additional validation checks
                if not self._validate_file(full_file_path):
                    continue

                file_bytes = full_file_path.read_bytes()
                key = self._crc64_hash(file_bytes)
                rel_path = str(full_file_path.relative_to(root))

                file_item = {'path': rel_path, 'key': key, 'key_str': key.hex(), 'actions': {'store_in_file': True}}

                current_node = root_node
                for part in Path(rel_path).parent.parts:
                    child_path = str(Path(current_node.path) / part)
                    if child_path not in current_node.children:
                        current_node.children[child_path] = DirectoryNode(child_path)
                    current_node = current_node.children[child_path]
                    current_node.files.append(file_item)

                root_node.files.append(file_item)

            except Exception as e:
                self.print_debug(f'Skipping file {full_file_path}: {str(e)}')

        return root_node

    def _hash_calc_from_node(self, node: DirectoryNode) -> dict:
        """
        Recursively compute folder hash data for a directory node.

        The hash data includes the path identifier, simhash for file names,
        simhash for file content, and children node hash information.

        Args:
            node (DirectoryNode): The directory node to compute the hash for.

        Returns:
            dict: The computed hash data for the node.
        """
        hash_data = self._hash_calc(node)
        return {
            'path_id': node.path,
            'sim_hash_names': f'{hash_data["name_hash"]:02x}',
            'sim_hash_content': f'{hash_data["content_hash"]:02x}',
            'children': [self._hash_calc_from_node(child) for child in node.children.values()],
        }

    def _hash_calc(self, node: DirectoryNode) -> dict:
        """
        Compute folder hash values for a given directory node.

        The method aggregates unique file keys and sorted file names to generate
        simhash-based hash values for both file names and file contents.

        The most significant byte of the name simhash is then replaced by a computed head value.

        Args:
            node (DirectoryNode): The directory node containing file items.

        Returns:
            dict: A dictionary with 'name_hash' and 'content_hash' keys.
        """
        processed = set()
        file_hashes = []
        sorted_names = []

        for file_item in node.files:
            if not file_item['actions']['store_in_file']:
                continue
            if file_item['key_str'] in processed:
                continue
            processed.add(file_item['key_str'])
            sorted_names.append(os.path.basename(file_item['path']))
            file_hashes.append(file_item['key'])

        sorted_names.sort()
        concatenated_names = ''.join(sorted_names)

        # Compute simhash for file names.
        name_simhash = Simhash(concatenated_names).value

        # Compute simhash for file contents by vectorizing each file key.
        tokens = []
        for key in file_hashes:
            for i, byte in enumerate(key):
                tokens.append(f'{i}:{byte:02x}')
        content_simhash = Simhash(tokens).value

        head = head_calc(name_simhash)
        name_simhash = (name_simhash & 0x00FFFFFFFFFFFFFF) | (head << 56)

        return {
            'name_hash': name_simhash,
            'content_hash': content_simhash,
        }

    def _validate_file(self, file_path: Path) -> bool:
        """
        Validate whether a file should be included in the folder hash scan.

        The validation includes checks for text files that end with a null byte and
        whether the filename contains a comma.

        Args:
            file_path (Path): The file path to validate.

        Returns:
            bool: True if the file is valid, False otherwise.
        """
        # Exclude text files that end with a null byte
        if self._is_text_file(file_path) and self._ends_with_null(file_path):
            return False

        # Exclude files whose names contain a comma
        if ',' in file_path.name:
            self.print_debug(f'File contains comma: {file_path}')
            return False

        return True

    def _is_text_file(self, file_path: Path) -> bool:
        """
        Determine if a file is a text file by examining its initial bytes.

        Args:
            file_path (Path): The file path to check.

        Returns:
            bool: True if the file appears to be a text file, False otherwise.
        """
        try:
            with open(file_path, 'rb') as f:
                sample = f.read(1024)
            text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})
            return not bool(sample.translate(None, text_chars))
        except IOError:
            return False

    def _ends_with_null(self, file_path: Path) -> bool:
        """
        Check if a file ends with a null byte.

        Args:
            file_path (Path): The path of the file to check.

        Returns:
            bool: True if the file ends with a null byte, False otherwise.
        """
        try:
            with open(file_path, 'rb') as f:
                f.seek(-1, os.SEEK_END)
                return f.read(1) == b'\x00'
        except (OSError, ValueError):
            return False
