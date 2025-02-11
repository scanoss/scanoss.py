"""
SPDX-License-Identifier: MIT

  Copyright (c) 2025, SCANOSS

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from scanoss.file_filters import FileFilters
from scanoss.scanners.scanner_config import ScannerConfig
from scanoss.scanoss_settings import ScanossSettings
from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.utils.abstract_presenter import AbstractPresenter
from scanoss.utils.crc64 import CRC64
from scanoss.utils.simhash import WordFeatureSet, fingerprint, simhash, vectorize_bytes


class DirectoryNode:
    """
    Represents a node in the directory tree for folder hashing.
    """

    def __init__(self, path: str):
        self.path = path
        self.is_dir = True
        self.children: Dict[str, DirectoryNode] = {}
        self.files: List[DirectoryFile] = []


class DirectoryFile:
    """
    Represents a file in the directory tree for folder hashing.
    """

    def __init__(self, path: str, key: bytes, key_str: str):
        self.path = path
        self.key = key
        self.key_str = key_str


class ScannerHFH(AbstractPresenter, ScanossBase):
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
        AbstractPresenter.__init__(
            self,
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
        ScanossBase.__init__(
            self,
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
        self.file_filters = FileFilters(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
            scanoss_settings=scanoss_settings,
        )

        self.scan_dir = scan_dir
        self.client = client
        self.scan_results = None

    def scan(self) -> Optional[Dict]:
        """
        Scan the provided directory using the folder hashing algorithm.

        Returns:
            Optional[Dict]: The folder hash response from the gRPC client, or None if an error occurs.
        """
        hfh_request = {
            'root': self.hfh_request_from_path(self.scan_dir),
            'threshold': 100,
            'best_match': True,
        }

        response = self.client.folder_hash_scan(hfh_request)
        self.scan_results = response

        return self.scan_results

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
        # Sort the files by name to ensure the hash is the same for the same folder
        filtered_files.sort()

        for file_path in filtered_files:
            try:
                full_file_path = file_path if file_path.is_absolute() else root / file_path

                file_bytes = full_file_path.read_bytes()
                key = CRC64.get_hash_buff(file_bytes)
                key_str = ''.join(f'{b:02x}' for b in key)
                rel_path = str(full_file_path.relative_to(root))

                file_item = DirectoryFile(rel_path, key, key_str)

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
        processed_hashes = set()
        file_hashes = []
        selected_names = []

        for file in node.files:
            key_str = file.key_str
            if key_str in processed_hashes:
                continue
            processed_hashes.add(key_str)

            selected_names.append(os.path.basename(file.path))

            file_key = bytes(file.key)
            file_hashes.append(file_key)

        selected_names.sort()
        concatenated_names = ''.join(selected_names)

        names_simhash = simhash(WordFeatureSet(concatenated_names.encode('utf-8')))
        content_simhash = fingerprint(vectorize_bytes(file_hashes))

        # Calculate head and overwrite MS byte
        head = self._head_calc(names_simhash)
        names_simhash = (names_simhash & 0x00FFFFFFFFFFFFFF) | (head << 56)

        return {
            'name_hash': names_simhash,
            'content_hash': content_simhash,
        }

    def _head_calc(self, sim_hash: int) -> int:
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

    def _format_json_output(self) -> str:
        """
        Format the scan output data into a JSON object

        Returns:
            str: The formatted JSON string
        """
        return json.dumps(self.scan_results, indent=2)

    def _format_plain_output(self) -> str:
        """
        Format the scan output data into a plain text string
        """
        return (
            json.dumps(self.scan_results, indent=2) if isinstance(self.scan_results, dict) else str(self.scan_results)
        )
