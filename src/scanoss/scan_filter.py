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
DEFAULT_SKIPPED_EXT = [  # File extensions to skip
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
]


class ScanFilter(ScanossBase):
    """
    Filter for determining which files to process during scanning.
    Handles both inclusion and exclusion rules based on file paths, extensions, and sizes.
    """

    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        scanoss_settings: 'ScanossSettings' = None,
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

        self.min_size = 0
        self.max_size = float('inf')
        self.hidden_files_folders = hidden_files_folders

        skip_patterns = []

        skip_patterns.extend(DEFAULT_SKIPPED_FILES)
        if not all_extensions:
            skip_patterns.extend(f'*{ext}' for ext in DEFAULT_SKIPPED_EXT)
            skip_patterns.extend(f'*{ext}/' for ext in DEFAULT_SKIPPED_DIR_EXT)
        if not all_folders:
            skip_patterns.extend(f'{dir_path}/' for dir_path in DEFAULT_SKIPPED_DIRS)

        if scanoss_settings:
            skip_patterns.extend(scanoss_settings.get_skip_patterns())
            self.min_size = scanoss_settings.get_skip_sizes().get('min', 0)
            self.max_size = scanoss_settings.get_skip_sizes().get('max', float('inf'))

        self.skip_patterns = skip_patterns
        self.path_spec = PathSpec.from_lines('gitwildmatch', self.skip_patterns)

    def get_filtered_files_from_folder(self, root: str) -> List[str]:
        """Retrieve a list of files to scan or fingerprint from a given directory root based on filter settings.

        Args:
            root (str): Root directory to scan

        Returns:
            list[str]: List of files to scan
        """
        files = self._walk_with_ignore(root)
        return files

    def get_filtered_files_from_files(self, files: List[str]) -> List[str]:
        """Retrieve a list of files to scan or fingerprint from a given list of files based on filter settings.

        Args:
            files (List[str]): List of files to scan

        Returns:
            list[str]: List of files to scan
        """
        filtered_files = []
        for file in files:
            if not self.hidden_files_folders and file.startswith('.'):
                self.print_debug(f'Skipping file: {file} (hidden file)')
                continue

            file_path = Path(file).resolve()
            file_rel_path = file_path.relative_to(Path.cwd())

            if not file_path.exists():
                self.print_debug(f'Skipping file: {file_rel_path} (does not exist)')
                continue

            file_size = file_path.stat().st_size

            if file_size < self.min_size or file_size > self.max_size:
                self.print_debug(f'Skipping file: {file} (size: {file_size})')
                continue

            if self.path_spec.match_file(str(file_rel_path).lower()):
                self.print_debug(f'Skipping file: {file}')
                continue

            filtered_files.append(str(file))
        return filtered_files

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

                if file_size < self.min_size or file_size > self.max_size:
                    self.print_debug(f'Skipping file: {file_rel_path} (size: {file_size})')
                    continue
                if self.path_spec.match_file(str(file_rel_path).lower()):
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
            or any(dir_rel_path.lower() == p.rstrip('/').lower() for p in self.skip_patterns)
            or self.path_spec.match_file(dir_rel_path.lower() + '/')
        )
