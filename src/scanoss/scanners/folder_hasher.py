import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Literal, Optional

from progress.bar import Bar

from scanoss.constants import DEFAULT_HFH_DEPTH
from scanoss.file_filters import FileFilters
from scanoss.scanoss_settings import ScanossSettings
from scanoss.scanossbase import ScanossBase
from scanoss.utils.abstract_presenter import AbstractPresenter
from scanoss.utils.crc64 import CRC64
from scanoss.utils.simhash import WordFeatureSet, fingerprint, simhash, vectorize_bytes

MINIMUM_FILE_COUNT = 8
MINIMUM_CONCATENATED_NAME_LENGTH = 32

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

    def __init__(self, path: str, key: List[bytes], key_str: str):
        self.path = path
        self.key = key
        self.key_str = key_str


@dataclass
class FolderHasherConfig:
    debug: bool = False
    trace: bool = False
    quiet: bool = False
    output_file: Optional[str] = None
    output_format: Literal['json'] = 'json'
    settings_file: Optional[str] = None
    skip_settings_file: bool = False


def create_folder_hasher_config_from_args(args) -> FolderHasherConfig:
    return FolderHasherConfig(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        output_file=getattr(args, 'output', None),
        output_format=getattr(args, 'format', 'json'),
        settings_file=getattr(args, 'settings', None),
        skip_settings_file=getattr(args, 'skip_settings_file', False),
    )


class FolderHasher:
    """
    Folder Hasher.

    This class is used to produce a folder hash for a given directory.

    It builds a directory tree (DirectoryNode) and computes the associated
    hash data for the folder.

    Args:
        scan_dir (str): The directory to be hashed.
        config (FolderHasherConfig): Configuration parameters for the folder hasher.
        scanoss_settings (Optional[ScanossSettings]): Optional settings for Scanoss.
        depth (int): How many levels to hash from the root directory (default: 1).
    """

    def __init__(
        self,
        scan_dir: str,
        config: FolderHasherConfig,
        scanoss_settings: Optional[ScanossSettings] = None,
        depth: int = DEFAULT_HFH_DEPTH,
    ):
        self.base = ScanossBase(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
        self.file_filters = FileFilters(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
            scanoss_settings=scanoss_settings,
            is_folder_hashing_scan=True,
        )
        self.presenter = FolderHasherPresenter(
            self,
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )

        self.scan_dir = scan_dir
        self.tree = None
        self.depth = depth

    def hash_directory(self, path: str) -> dict:
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

        self.tree = tree

        return tree

    def _build_root_node(
        self,
        path: str,
    ) -> DirectoryNode:
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

        all_files = [
            f for f in root.rglob('*') if f.is_file()
        ]
        filtered_files = self.file_filters.get_filtered_files_from_files(all_files, str(root))

        # Sort the files by name to ensure the hash is the same for the same folder
        filtered_files.sort()

        bar_ctx = Bar('Hashing files...', max=len(filtered_files))

        with bar_ctx as bar:
            full_file_path = ''
            for file_path in filtered_files:
                try:
                    file_path_obj = Path(file_path) if isinstance(file_path, str) else file_path
                    full_file_path = file_path_obj if file_path_obj.is_absolute() else root / file_path_obj

                    self.base.print_debug(f'\nHashing file {str(full_file_path)}')

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
                    self.base.print_debug(f'Skipping file {full_file_path}: {str(e)}')

                bar.next()
        return root_node

    def _hash_calc_from_node(self, node: DirectoryNode, current_depth: int = 1) -> dict:
        """
        Recursively compute folder hash data for a directory node.

        The hash data includes the path identifier, simhash for file names,
        simhash for file content, directory hash, language extensions, and children node hash information.

        Args:
            node (DirectoryNode): The directory node to compute the hash for.
            current_depth (int): The current depth level (1-based, root is depth 1).

        Returns:
            dict: The computed hash data for the node.
        """
        hash_data = self._hash_calc(node)

        # Safely calculate relative path
        try:
            node_path = Path(node.path).resolve()
            scan_dir_path = Path(self.scan_dir).resolve()
            rel_path = node_path.relative_to(scan_dir_path)
        except ValueError:
            # If relative_to fails, use the node path as is or a fallback
            rel_path = Path(node.path).name if node.path else Path('.')

        # Only process children if we haven't reached the depth limit
        children = []
        if current_depth < self.depth:
            children = [self._hash_calc_from_node(child, current_depth + 1) for child in node.children.values()]

        return {
            'path_id': str(rel_path),
            'sim_hash_names': f'{hash_data["name_hash"]:02x}' if hash_data['name_hash'] is not None else None,
            'sim_hash_content': f'{hash_data["content_hash"]:02x}' if hash_data['content_hash'] is not None else None,
            'sim_hash_dir_names': f'{hash_data["dir_hash"]:02x}' if hash_data['dir_hash'] is not None else None,
            'lang_extensions': hash_data['lang_extensions'],
            'children': children,
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
            dict: A dictionary with 'name_hash', 'content_hash', 'dir_hash', and 'lang_extensions' keys.
        """
        processed_hashes = set()
        unique_file_names = set()
        unique_directories = set()
        extension_map = {}
        file_hashes = []
        selected_names = []

        for file in node.files:
            key_str = file.key_str

            file_name = os.path.basename(file.path)

            file_name_without_extension, extension = os.path.splitext(file_name)
            current_directory = os.path.dirname(file.path)

            if extension and len(extension) > 1:
                ext_without_dot = extension[1:]
                extension_map[ext_without_dot] = extension_map.get(ext_without_dot, 0) + 1

            current_directory.replace(self.scan_dir, '', 1).lstrip(os.path.sep)
            parts = current_directory.split(os.path.sep)
            for d in parts:
                if d in {'', '.', '..'}:
                    continue
                unique_directories.add(d)

            processed_hashes.add(key_str)
            unique_file_names.add(file_name_without_extension)
            selected_names.append(file_name)
            file_hashes.append(file.key)

        if len(selected_names) < MINIMUM_FILE_COUNT:
            return {'name_hash': None, 'content_hash': None, 'dir_hash': None, 'lang_extensions': None}

        selected_names.sort()
        concatenated_names = ''.join(selected_names)

        if len(concatenated_names.encode('utf-8')) < MINIMUM_CONCATENATED_NAME_LENGTH:
            return {'name_hash': None, 'content_hash': None, 'dir_hash': None, 'lang_extensions': None}

        # Concatenate the unique file names without the extensions, adding a space and sorting them alphabetically
        unique_file_names_list = list(unique_file_names)
        unique_file_names_list.sort()
        concatenated_names = ' '.join(unique_file_names_list)

        # We do the same for the directory names, adding a space and sorting them alphabetically
        unique_directories_list = list(unique_directories)
        unique_directories_list.sort()
        concatenated_directories = ' '.join(unique_directories_list)

        names_simhash = simhash(WordFeatureSet(concatenated_names.encode('utf-8')))
        dir_simhash = simhash(WordFeatureSet(concatenated_directories.encode('utf-8')))
        content_simhash = fingerprint(vectorize_bytes(file_hashes))

        # Debug logging similar to Go implementation
        self.base.print_debug(f'Unique file names: {unique_file_names_list}')
        self.base.print_debug(f'Unique directories: {unique_directories_list}')
        self.base.print_debug(f'{dir_simhash:x}/{names_simhash:x} - {content_simhash:x} - {extension_map}')

        return {
            'name_hash': names_simhash,
            'content_hash': content_simhash,
            'dir_hash': dir_simhash,
            'lang_extensions': extension_map,
        }

    def present(self, output_format: Optional[str] = None, output_file: Optional[str] = None):
        """Present the hashed tree in the selected format"""
        self.presenter.present(output_format=output_format, output_file=output_file)


class FolderHasherPresenter(AbstractPresenter):
    """
    FolderHasher presenter class
    Handles the presentation of the folder hashing scan results
    """

    def __init__(self, folder_hasher: FolderHasher, **kwargs):
        super().__init__(**kwargs)
        self.folder_hasher = folder_hasher

    def _format_json_output(self) -> str:
        """
        Format the scan output data into a JSON object

        Returns:
            str: The formatted JSON string
        """
        return json.dumps(self.folder_hasher.tree, indent=2)

    def _format_plain_output(self) -> str:
        """
        Format the scan output data into a plain text string
        """
        return (
            json.dumps(self.folder_hasher.tree, indent=2)
            if isinstance(self.folder_hasher.tree, dict)
            else str(self.folder_hasher.tree)
        )

    def _format_cyclonedx_output(self) -> str:
        raise NotImplementedError('CycloneDX output is not implemented')

    def _format_spdxlite_output(self) -> str:
        raise NotImplementedError('SPDXlite output is not implemented')

    def _format_csv_output(self) -> str:
        raise NotImplementedError('CSV output is not implemented')

    def _format_raw_output(self) -> str:
        raise NotImplementedError('Raw output is not implemented')
