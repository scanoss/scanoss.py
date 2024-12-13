"""
SPDX-License-Identifier: MIT

  Copyright (c) 2024, SCANOSS

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

import os
from pathlib import Path
from typing import List

from pathspec import PathSpec

from scanoss.scanoss_settings import ScanossSettings
from scanoss.scanossbase import ScanossBase

DEFAULT_SKIPPED_FILES = {
    'gradlew',
    'gradlew.bat',
    'mvnw',
    'mvnw.cmd',
    'gradle-wrapper.jar',
    'maven-wrapper.jar',
    'thumbs.db',
    'babel.config.js',
    'license.txt',
    'license.md',
    'copying.lib',
    'makefile',
}

DEFAULT_SKIPPED_DIRS = {  # Folders to skip
    'nbproject',
    'nbbuild',
    'nbdist',
    '__pycache__',
    'venv',
    '_yardoc',
    'eggs',
    'wheels',
    'htmlcov',
    '__pypackages__',
}
DEFAULT_SKIPPED_DIR_EXT = {  # Folder endings to skip
    '.egg-info'
}
DEFAULT_SKIPPED_EXT = {  # File extensions to skip
    '.1',
    '.2',
    '.3',
    '.4',
    '.5',
    '.6',
    '.7',
    '.8',
    '.9',
    '.ac',
    '.adoc',
    '.am',
    '.asciidoc',
    '.bmp',
    '.build',
    '.cfg',
    '.chm',
    '.class',
    '.cmake',
    '.cnf',
    '.conf',
    '.config',
    '.contributors',
    '.copying',
    '.crt',
    '.csproj',
    '.css',
    '.csv',
    '.dat',
    '.data',
    '.doc',
    '.docx',
    '.dtd',
    '.dts',
    '.iws',
    '.c9',
    '.c9revisions',
    '.dtsi',
    '.dump',
    '.eot',
    '.eps',
    '.geojson',
    '.gdoc',
    '.gif',
    '.glif',
    '.gmo',
    '.gradle',
    '.guess',
    '.hex',
    '.htm',
    '.html',
    '.ico',
    '.iml',
    '.in',
    '.inc',
    '.info',
    '.ini',
    '.ipynb',
    '.jpeg',
    '.jpg',
    '.json',
    '.jsonld',
    '.lock',
    '.log',
    '.m4',
    '.map',
    '.markdown',
    '.md',
    '.md5',
    '.meta',
    '.mk',
    '.mxml',
    '.o',
    '.otf',
    '.out',
    '.pbtxt',
    '.pdf',
    '.pem',
    '.phtml',
    '.plist',
    '.png',
    '.po',
    '.ppt',
    '.prefs',
    '.properties',
    '.pyc',
    '.qdoc',
    '.result',
    '.rgb',
    '.rst',
    '.scss',
    '.sha',
    '.sha1',
    '.sha2',
    '.sha256',
    '.sln',
    '.spec',
    '.sql',
    '.sub',
    '.svg',
    '.svn-base',
    '.tab',
    '.template',
    '.test',
    '.tex',
    '.tiff',
    '.toml',
    '.ttf',
    '.txt',
    '.utf-8',
    '.vim',
    '.wav',
    '.woff',
    '.woff2',
    '.xht',
    '.xhtml',
    '.xls',
    '.xlsx',
    '.xml',
    '.xpm',
    '.xsd',
    '.xul',
    '.yaml',
    '.yml',
    '.wfp',
    '.editorconfig',
    '.dotcover',
    '.pid',
    '.lcov',
    '.egg',
    '.manifest',
    '.cache',
    '.coverage',
    '.cover',
    '.gem',
    '.lst',
    '.pickle',
    '.pdb',
    '.gml',
    '.pot',
    '.plt',
    # File endings
    '-doc',
    'changelog',
    'config',
    'copying',
    'license',
    'authors',
    'news',
    'licenses',
    'notice',
    'readme',
    'swiftdoc',
    'texidoc',
    'todo',
    'version',
    'ignore',
    'manifest',
    'sqlite',
    'sqlite3',
}


class FileFilters(ScanossBase):
    """
    Filter for determining which files to process during scanning, fingerprinting, etc.
    Handles both inclusion and exclusion rules based on file paths, extensions, and sizes.
    """

    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        scanoss_settings: 'ScanossSettings | None' = None,
        all_extensions: bool = False,
        all_folders: bool = False,
        hidden_files_folders: bool = False,
    ):
        """
        Initialize scan filters based on default settings. Optionally append custom settings.

        Args:
            debug (bool): Enable debug output
            trace (bool): Enable trace output
            quiet (bool): Suppress output
            scanoss_settings (ScanossSettings): Custom settings to override defaults
            all_extensions (bool): Include all file extensions
            all_folders (bool): Include all folders
            hidden_files_folders (bool): Include hidden files and folders
        """
        super().__init__(debug, trace, quiet)

        self.hidden_files_folders = hidden_files_folders
        self.scanoss_settings = scanoss_settings

        self.default_skip_patterns = []
        self.default_skip_patterns.extend(DEFAULT_SKIPPED_FILES)
        if not all_extensions:
            self.default_skip_patterns.extend(f'*{ext}' for ext in DEFAULT_SKIPPED_EXT)
            self.default_skip_patterns.extend(f'*{ext}/' for ext in DEFAULT_SKIPPED_DIR_EXT)
        if not all_folders:
            self.default_skip_patterns.extend(f'{dir_path}/' for dir_path in DEFAULT_SKIPPED_DIRS)

    def get_filtered_files_from_folder(self, root: str, operation_type: str) -> List[str]:
        """Retrieve a list of files to scan or fingerprint from a given directory root based on filter settings.

        Args:
            root (str): Root directory to scan or fingerprint
            operation_type (str): Type of operation ('scanning' or 'fingerprinting')

        Returns:
            list[str]: Filtered list of files to scan or fingerprint
        """
        skip_patterns = self._get_operation_patterns(operation_type)
        path_spec = PathSpec.from_lines('gitwildmatch', skip_patterns)

        filtered_files = []
        for dirpath, _, filenames in self._walk_with_ignore(root):
            if self._should_skip_dir(os.path.relpath(dirpath, root)):
                continue

            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                rel_path = os.path.relpath(file_path, root)

                if not self.hidden_files_folders and (filename.startswith('.') or '/.' in rel_path):
                    continue

                if path_spec.match_file(rel_path):
                    continue

                try:
                    file_size = os.path.getsize(file_path)
                    min_size, max_size = self._get_operation_size_limits(operation_type, file_path)
                    if min_size <= file_size <= max_size:
                        filtered_files.append(file_path)
                except OSError as e:
                    self.print_debug(f'Error getting size for {file_path}: {e}')

        return filtered_files

    def get_filtered_files_from_files(self, files: List[str], operation_type: str) -> List[str]:
        """Retrieve a list of files to scan or fingerprint from a given list of files based on filter settings.

        Args:
            files (List[str]): List of files to scan or fingerprint
            operation_type (str): Type of operation ('scanning' or 'fingerprinting')

        Returns:
            list[str]: Filtered list of files to scan or fingerprint
        """
        skip_patterns = self._get_operation_patterns(operation_type)
        path_spec = PathSpec.from_lines('gitwildmatch', skip_patterns)

        filtered_files = []
        for file_path in files:
            if not os.path.isfile(file_path):
                continue

            filename = os.path.basename(file_path)
            if not self.hidden_files_folders and filename.startswith('.'):
                continue

            if path_spec.match_file(filename):
                continue

            try:
                file_size = os.path.getsize(file_path)
                min_size, max_size = self._get_operation_size_limits(operation_type, file_path)
                if min_size <= file_size <= max_size:
                    filtered_files.append(file_path)
            except OSError as e:
                self.print_debug(f'Error getting size for {file_path}: {e}')

        return filtered_files

    def _get_operation_patterns(self, operation_type: str) -> List[str]:
        """Get patterns specific to the operation type, combining defaults with settings.

        Args:
            operation_type (str): Type of operation ('scanning' or 'fingerprinting')

        Returns:
            List[str]: Combined list of patterns to skip
        """
        patterns = self.default_skip_patterns.copy()

        if self.scanoss_settings:
            settings_patterns = self.scanoss_settings.get_skip_patterns(operation_type)
            if settings_patterns:
                patterns.extend(settings_patterns)

        return patterns

    def _get_operation_size_limits(self, operation_type: str, file_path: str = None) -> tuple:
        """Get size limits specific to the operation type and file path.

        Args:
            operation_type (str): Type of operation ('scanning' or 'fingerprinting')
            file_path (str, optional): Path to the file to check against patterns. If None, returns default limits.

        Returns:
            tuple: (min_size, max_size) tuple for the given file path and operation type
        """
        min_size = 0
        max_size = float('inf')

        if not self.scanoss_settings or not file_path:
            return min_size, max_size

        size_rules = self.scanoss_settings.get_skip_sizes(operation_type)
        if not size_rules:
            return min_size, max_size

        # Convert file path to relative path for pattern matching
        try:
            rel_path = os.path.relpath(file_path)
        except ValueError:
            # If file_path is on a different drive, just use the basename
            rel_path = os.path.basename(file_path)

        # Check each size rule against the file path
        for rule in size_rules:
            patterns = rule.get('patterns', [])
            if not patterns:
                continue

            # Create a PathSpec for the rule's patterns
            path_spec = PathSpec.from_lines('gitwildmatch', patterns)

            # If the file matches any pattern in this rule, use its size limits
            if path_spec.match_file(rel_path):
                return (rule.get('min', min_size), rule.get('max', max_size))

        return min_size, max_size

    def _walk_with_ignore(self, scan_root: str) -> List[str]:
        files = []
        root = Path(scan_root).resolve()

        for dirpath, dirnames, filenames in os.walk(root):
            dirpath = Path(dirpath)
            rel_path = dirpath.relative_to(root)

            if self._should_skip_dir(str(rel_path)):
                self.print_debug(f'Skipping directory: {rel_path}')
                dirnames.clear()
                continue

            for filename in filenames:
                if not self.hidden_files_folders and filename.startswith('.'):
                    self.print_debug(f'Skipping file: {filename} (hidden file)')
                    continue

                file_path = dirpath / filename
                file_rel_path = rel_path / filename
                file_size = file_path.stat().st_size

                if file_size < 0 or file_size > float('inf'):
                    self.print_debug(f'Skipping file: {file_rel_path} (size: {file_size})')
                    continue
                if PathSpec.from_lines('gitwildmatch', self.default_skip_patterns).match_file(
                    str(file_rel_path).lower()
                ):
                    self.print_debug(f'Skipping file: {file_rel_path}')
                    continue
                else:
                    files.append(str(file_rel_path))

        return files

    def _should_skip_dir(self, dir_rel_path: str) -> bool:
        dir_path = Path(dir_rel_path)
        is_hidden = dir_path != Path('.') and any(part.startswith('.') for part in dir_path.parts)
        return (
            (is_hidden and not self.hidden_files_folders)
            or any(dir_rel_path.lower() == p.rstrip('/').lower() for p in self.default_skip_patterns)
            or PathSpec.from_lines('gitwildmatch', self.default_skip_patterns).match_file(dir_rel_path.lower() + '/')
        )
