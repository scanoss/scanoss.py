from pathlib import Path
from typing import Dict, Optional

from crc import Calculator, Crc64

from scanoss.scanners.scanner_config import ScannerConfig
from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.utils.file import get_all_files_from_dir


class ScannerHFH(ScanossBase):
    """

    SCANOSS Folder Hashing Scanner
    Handle the folder hashing scan of a directory
    """

    def __init__(
        self,
        scan_dir: str,
        config: ScannerConfig,
        client: ScanossGrpc,
    ):
        super().__init__(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )

        self.scan_dir = scan_dir
        self.client = client

        self.file_name_hash_cache: Dict[str, str] = {}
        self.file_content_hash_cache: Dict[str, str] = {}

    def scan(self) -> Optional[Dict]:
        """
        Scan given directory using high precision folder hashing algorithm

        Returns:
            Dict: Folder Hash Response or None if error
        """

        root_children = self._build_children(self.scan_dir)
        # TODO: get from config
        req_dict = {
            'best_match': False,
            'threshold': 60,
            'root': root_children,
        }

        response = self.client.folder_hash_scan(req_dict)

        return response

    def _build_children(self, dir_path: str) -> Dict:
        """
        Given a directory, recursively build the children tree computing the CRC64
        hash for each file in the directory.

        Returns:
            Dict: Children tree
        """

        self.print_debug(f'Building children for {dir_path}')

        all_files = get_all_files_from_dir(dir_path)

        sim_hash_names_str = ''
        sim_hash_content_str = ''
        for file_path in all_files:
            file_name = Path(file_path).name

            file_name_hash = self._get_file_name_hash(file_name)
            sim_hash_names_str += file_name_hash

            file_content_hash = self._get_file_content_hash(file_path)
            sim_hash_content_str += file_content_hash

        children = []
        for entry in sorted(Path(dir_path).iterdir(), key=lambda x: x.name):
            if entry.is_dir():
                child = self._build_children(str(entry))
                children.append(child)

        return {
            'path_id': Path(dir_path).name,
            'sim_hash_names': sim_hash_names_str,
            'sim_hash_content': sim_hash_content_str,
            'children': children,
        }

    def _get_file_name_hash(self, filename: str) -> str:
        """
        Compute a CRC64 hash (as a 16-character hex string) for a given filename
        """
        if filename in self.file_name_hash_cache:
            return self.file_name_hash_cache[filename]

        calculator = Calculator(Crc64.CRC64)
        result = calculator.checksum(filename.encode('utf-8'))
        hash_str = format(result, '016x')
        self.file_name_hash_cache[filename] = hash_str
        return hash_str

    def _get_file_content_hash(self, file_path: str) -> str:
        """
        Compute a CRC64 hash (as a 16-character hex string) for the contents of a given file.
        """

        if file_path in self.file_content_hash_cache:
            return self.file_content_hash_cache[file_path]

        calculator = Calculator(Crc64.CRC64)
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            result = calculator.checksum(content)
            hash_str = format(result, '016x')
        except Exception as e:
            self.print_stderr(f'Error reading file {file_path}: {e}')
            raise Exception(f'ERROR: failed to read file {file_path}')

        self.file_content_hash_cache[file_path] = hash_str
        return hash_str
