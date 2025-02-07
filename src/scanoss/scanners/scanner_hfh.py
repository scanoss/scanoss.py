import os
from pathlib import Path
from typing import Dict, List, Optional

from simhash import Simhash

from scanoss.file_filters import FileFilters
from scanoss.scanners.scanner_config import ScannerConfig
from scanoss.scanoss_settings import ScanossSettings
from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.utils.crc64 import CRC64


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

        root_node = self._build_root_node(path)
        tree = self._hash_calc_from_node(root_node)

        return tree

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

        filtered_files = [Path(f) for f in self.file_filters.get_filtered_files_from_folder(path)]

        for file_path in filtered_files:
            try:
                full_file_path = file_path if file_path.is_absolute() else root / file_path

                file_bytes = full_file_path.read_bytes()
                key = CRC64.get_hash_buff(file_bytes)
                key_str = ''.join(f'{b:02x}' for b in key)
                rel_path = str(full_file_path.relative_to(root))

                file_item = {'path': rel_path, 'key': key, 'key_str': key_str, 'actions': {'store_in_file': True}}

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
            file_hashes.append(file_item['key_str'])

        sorted_names.sort()
        concatenated_names = ''.join(sorted_names)

        name_simhash = Simhash(concatenated_names).value
        content_simhash = Simhash(' '.join(file_hashes)).value

        # Calculate head and overwrite MS byte
        head = head_calc(name_simhash)
        name_simhash = (name_simhash & 0x00FFFFFFFFFFFFFF) | (head << 56)

        return {
            'name_hash': name_simhash,
            'content_hash': content_simhash,
        }
