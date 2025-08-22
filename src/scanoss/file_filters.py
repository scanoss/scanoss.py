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
import sys
from pathlib import Path
from typing import List, Optional

from pathspec import GitIgnoreSpec

from .scanossbase import ScanossBase

# Files to skip
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

DEFAULT_SKIPPED_FILES_HFH = {
    'gradlew',
    'gradlew.bat',
    'mvnw',
    'mvnw.cmd',
    'gradle-wrapper.jar',
    'maven-wrapper.jar',
    'thumbs.db',
    'babel.config.js',
}


# Folders to skip
DEFAULT_SKIPPED_DIRS = {
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
    'example',
    'examples'
}

DEFAULT_SKIPPED_DIRS_HFH = {
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
    'example',
    'examples',
}


# Folder endings to skip
DEFAULT_SKIPPED_DIR_EXT = {'.egg-info'}
DEFAULT_SKIPPED_DIR_EXT_HFH = {'.egg-info'}

# File extensions to skip
DEFAULT_SKIPPED_EXT = {
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
    '.whml',
    '.pom',
    '.smtml',
    '.min.js',
    '.mf',
    '.base64',
    '.s',
    '.diff',
    '.patch',
    '.rules',
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

    def __init__(self, debug: bool = False, trace: bool = False, quiet: bool = False, **kwargs):
        """
        Initialize scan filters based on default settings. Optionally append custom settings.

        Args:
            debug (bool): Enable debug output
            trace (bool): Enable trace output
            quiet (bool): Suppress output
            **kwargs: Additional arguments including:
                scanoss_settings (ScanossSettings): Custom settings to override defaults
                all_extensions (bool): Include all file extensions
                all_folders (bool): Include all folders
                hidden_files_folders (bool): Include hidden files and folders
                operation_type (str): Operation type ('scanning' or 'fingerprinting')
                skip_size (int): Size to skip
                skip_extensions (list): Extensions to skip
                skip_folders (list): Folders to skip
                is_folder_hashing_scan (bool): Whether the operation is a folder hashing scan
        """
        super().__init__(debug, trace, quiet)

        self.hidden_files_folders = kwargs.get('hidden_files_folders', False)
        self.scanoss_settings = kwargs.get('scanoss_settings')
        self.all_extensions = kwargs.get('all_extensions', False)
        self.all_folders = kwargs.get('all_folders', False)
        self.skip_folders = kwargs.get('skip_folders', [])
        self.skip_size = kwargs.get('skip_size', 0)
        self.skip_extensions = kwargs.get('skip_extensions', [])
        self.is_folder_hashing_scan = kwargs.get('is_folder_hashing_scan', False)
        self.file_folder_pat_spec = self._get_file_folder_pattern_spec(kwargs.get('operation_type', 'scanning'))
        self.size_pat_rules = self._get_size_limit_pattern_rules(kwargs.get('operation_type', 'scanning'))

    def get_filtered_files_from_folder(self, root: str) -> List[str]:
        """
        Retrieve a list of files to scan or fingerprint from a given directory root based on filter settings.

        Args:
            root (str): Root directory to scan or fingerprint

        Returns:
            list[str]: Filtered list of files to scan or fingerprint
        """
        if self.debug:
            if self.file_folder_pat_spec:
                self.print_stderr(f'Running with {len(self.file_folder_pat_spec)} pattern filters.')
            if self.size_pat_rules:
                self.print_stderr(f'Running with {len(self.size_pat_rules)} size pattern rules.')
            if self.skip_size:
                self.print_stderr(f'Running with global skip size: {self.skip_size}')
            if self.skip_extensions:
                self.print_stderr(f'Running with extra global skip extensions: {self.skip_extensions}')
            if self.skip_folders:
                self.print_stderr(f'Running with extra global skip folders: {self.skip_folders}')
        all_files = []
        root_path = Path(root).resolve()
        if not root_path.exists() or not root_path.is_dir():
            self.print_stderr(f'ERROR: Specified root directory {root} does not exist or is not a directory.')
            return all_files
        # Walk the tree looking for files to process. While taking into account files/folders to skip
        for dirpath, dirnames, filenames in os.walk(root_path):
            dir_path = Path(dirpath)
            rel_path = dir_path.relative_to(root_path)
            if dir_path.is_symlink():  # TODO should we skip symlink folders?
                self.print_msg(f'WARNING: Found symbolic link folder: {dir_path}')

            if self.should_skip_dir(str(rel_path)):  # Current directory should be skipped
                dirnames.clear()
                continue
            for filename in filenames:
                file_path = dir_path / filename
                all_files.append(str(file_path))
        # End os.walk loop
        # Now filter the files and return the reduced list
        return self.get_filtered_files_from_files(all_files, str(root_path))

    def get_filtered_files_from_files(self, files: List[str], scan_root: Optional[str] = None) -> List[str]:
        """
        Retrieve a list of files to scan or fingerprint from a given list of files based on filter settings.

        Args:
            files (List[str]): List of files to scan or fingerprint
            scan_root (str): Root directory to scan or fingerprint

        Returns:
            list[str]: Filtered list of files to scan or fingerprint
        """
        filtered_files = []
        for file_path in files:
            path_obj = Path(file_path)
            try:
                if scan_root:
                    rel_path = path_obj.relative_to(scan_root)
                else:
                    rel_path = str(path_obj)
            except ValueError:
                self.print_debug(f'Ignoring file: {file_path} (broken symlink)')
                continue

            if not path_obj.exists() or not path_obj.is_file() or path_obj.is_symlink():
                self.print_debug(
                    f'WARNING: File {rel_path} does not exist, is not a file, or is a symbolic link. Ignoring.'
                )
                continue

            if not self.hidden_files_folders and any(part.startswith('.') for part in path_obj.parts):
                self.print_debug(f'Skipping file: {rel_path} (in hidden directory or is hidden file)')
                continue

            if self._should_skip_file(rel_path):
                continue
            try:
                file_size = path_obj.stat().st_size
                if file_size == 0:
                    self.print_debug(f'Skipping file: {rel_path} (empty file)')
                    continue
                min_size, max_size = self._get_operation_size_limits(file_path)
                if min_size <= file_size <= max_size:
                    filtered_files.append(str(rel_path))
                else:
                    self.print_debug(
                        f'Skipping file: {rel_path} (size {file_size} outside limits {min_size}-{max_size})'
                    )
            except OSError as e:
                self.print_debug(f'Error getting size for {rel_path}: {e}')
        # End file loop
        return filtered_files

    def _get_file_folder_pattern_spec(self, operation_type: str = 'scanning'):
        """
        Get file path pattern specification.

        Args:
            operation_type (str): Type of operation ('scanning' or 'fingerprinting')

        Returns:
            GitIgnoreSpec: GitIgnoreSpec object containing the file path patterns
        """
        patterns = self._get_operation_patterns(operation_type)
        if patterns:
            return GitIgnoreSpec.from_lines(patterns)
        return None

    def _get_size_limit_pattern_rules(self, operation_type: str = 'scanning'):
        """
        Get size limit pattern rules.

        Args:
            operation_type (str): Type of operation ('scanning' or 'fingerprinting')

        Returns:
            List of size limit pattern rules
        """
        if self.scanoss_settings:
            size_rules = self.scanoss_settings.get_skip_sizes(operation_type)
            if size_rules:
                size_rules_with_patterns = []
                for rule in size_rules:
                    patterns = rule.get('patterns', [])
                    if not patterns:
                        continue
                    size_rules_with_patterns.append(rule)
                return size_rules_with_patterns
        return None

    def _get_operation_patterns(self, operation_type: str) -> List[str]:
        """
        Get patterns specific to the operation type, combining defaults with settings.

        Args:
            operation_type (str): Type of operation ('scanning' or 'fingerprinting')

        Returns:
            List[str]: Combined list of patterns to skip
        """
        patterns = []

        # Default patterns for skipping directories
        if not self.all_folders:
            DEFAULT_SKIPPED_DIR_LIST = DEFAULT_SKIPPED_DIRS_HFH if self.is_folder_hashing_scan else DEFAULT_SKIPPED_DIRS
            DEFAULT_SKIPPED_DIR_EXT_LIST = (
                DEFAULT_SKIPPED_DIR_EXT_HFH if self.is_folder_hashing_scan else DEFAULT_SKIPPED_DIR_EXT
            )
            for dir_name in DEFAULT_SKIPPED_DIR_LIST:
                patterns.append(f'{dir_name}/')
            for dir_extension in DEFAULT_SKIPPED_DIR_EXT_LIST:
                patterns.append(f'*{dir_extension}/')

        # Custom patterns added in SCANOSS settings file
        if self.scanoss_settings:
            patterns.extend(self.scanoss_settings.get_skip_patterns(operation_type))
        return patterns

    def _get_operation_size_limits(self, file_path: str = None) -> tuple:
        """
        Get size limits specific to the operation type and file path.

        Args:
            file_path (str, optional): Path to the file to check against patterns. If None, returns default limits.

        Returns:
            tuple: (min_size, max_size) tuple for the given file path and operation type
        """
        min_size = 0
        max_size = sys.maxsize
        # Apply global minimum file size if specified
        if self.skip_size > 0:
            min_size = self.skip_size
            return min_size, max_size
        # Return default size limits if no settings specified
        if not self.scanoss_settings or not file_path or not self.size_pat_rules:
            return min_size, max_size
        try:
            rel_path = os.path.relpath(file_path)
        except ValueError:
            rel_path = os.path.basename(file_path)
        rel_path_lower = rel_path.lower()
        # Cycle through each rule looking for a match
        for rule in self.size_pat_rules:
            patterns = rule.get('patterns', [])
            if patterns:
                path_spec = GitIgnoreSpec.from_lines(patterns)
                if path_spec.match_file(rel_path_lower):
                    return rule.get('min', min_size), rule.get('max', max_size)
        # End rules loop
        return min_size, max_size

    def should_skip_dir(self, dir_rel_path: str) -> bool:  # noqa: PLR0911
        """
        Check if a directory should be skipped based on operation type and default rules.

        Args:
            dir_rel_path (str): Relative path to the directory

        Returns:
            bool: True if directory should be skipped, False otherwise
        """
        dir_name = os.path.basename(dir_rel_path)
        dir_path = Path(dir_rel_path)
        if (
            not self.hidden_files_folders
            and dir_path != Path('.')
            and any(part.startswith('.') for part in dir_path.parts)
        ):
            self.print_debug(f'Skipping directory: {dir_rel_path} (hidden directory)')
            return True
        if self.all_folders:
            return False
        dir_name_lower = dir_name.lower()
        if dir_name_lower in DEFAULT_SKIPPED_DIRS:
            self.print_debug(f'Skipping directory: {dir_rel_path} (matches default skip directory)')
            return True
        if self.skip_folders and dir_name in self.skip_folders:
            self.print_debug(f'Skipping directory: {dir_rel_path} (matches skip folder)')
            return True
        for ext in DEFAULT_SKIPPED_DIR_EXT:
            if dir_name_lower.endswith(ext):
                self.print_debug(f'Skipping directory: {dir_rel_path} (matches default skip extension: {ext})')
                return True

        if self.file_folder_pat_spec and self.file_folder_pat_spec.match_file(dir_rel_path):
            self.print_debug(f'Skipping directory: {dir_rel_path} (matches custom pattern)')
            return True
        return False

    def _should_skip_file(self, file_rel_path: str) -> bool:  # noqa: PLR0911
        """
        Check if a file should be skipped based on operation type and default rules.

        Args:
            file_rel_path (str): Relative path to the file

        Returns:
            bool: True if file should be skipped, False otherwise
        """
        file_name = os.path.basename(file_rel_path)
        DEFAULT_SKIPPED_EXT_LIST = {} if self.is_folder_hashing_scan else DEFAULT_SKIPPED_EXT
        DEFAULT_SKIPPED_FILES_LIST = DEFAULT_SKIPPED_FILES_HFH if self.is_folder_hashing_scan else DEFAULT_SKIPPED_FILES

        if not self.hidden_files_folders and file_name.startswith('.'):
            self.print_debug(f'Skipping file: {file_rel_path} (hidden file)')
            return True
        if self.all_extensions:
            return False
        file_name_lower = file_name.lower()
        # Look for exact files
        if file_name_lower in DEFAULT_SKIPPED_FILES_LIST:
            self.print_debug(f'Skipping file: {file_rel_path} (matches default skip file)')
            return True
        # Look for file endings
        for ending in DEFAULT_SKIPPED_EXT_LIST:
            if file_name_lower.endswith(ending):
                self.print_debug(f'Skipping file: {file_rel_path} (matches default skip ending: {ending})')
                return True
        # Look for custom (extra) endings
        if self.skip_extensions:
            for ending in self.skip_extensions:
                if file_name_lower.endswith(ending):
                    self.print_debug(f'Skipping file: {file_rel_path} (matches skip extension)')
                    return True
        # Check for file patterns
        if self.file_folder_pat_spec and self.file_folder_pat_spec.match_file(file_rel_path):
            self.print_debug(f'Skipping file: {file_rel_path} (matches custom pattern)')
            return True
        return False
