import os
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
    ):
        """
        Initialize scan filters based on default settings. Optionally append custom settings.

        Args:
            debug (bool): Enable debug output
            trace (bool): Enable trace output
            quiet (bool): Suppress output
            scanoss_settings (ScanossSettings): Custom settings to override defaults
        """
        super().__init__(debug, trace, quiet)

        self.min_size = 0
        self.max_size = float('inf')

        skip_patterns = []

        skip_patterns.extend(DEFAULT_SKIPPED_FILES)
        skip_patterns.extend(f'{dir_path}/' for dir_path in DEFAULT_SKIPPED_DIRS)
        skip_patterns.extend(f'*{ext}' for ext in DEFAULT_SKIPPED_EXT)
        skip_patterns.extend(f'*{ext}/' for ext in DEFAULT_SKIPPED_DIR_EXT)

        if scanoss_settings:
            skip_patterns.extend(scanoss_settings.get_skip_patterns())
            self.min_size = scanoss_settings.get_skip_sizes().get('min', 0)
            self.max_size = scanoss_settings.get_skip_sizes().get('max', float('inf'))

        self.skip_patterns = skip_patterns
        self.path_spec = PathSpec.from_lines('gitwildmatch', self.skip_patterns)

    def get_filtered_files(self, root: str) -> List[str]:
        """Get a list of files to scan based on the filter settings.

        Args:
            root (str): Root directory to scan

        Returns:
            list[str]: List of files to scan
        """
        files = self._walk_with_ignore(root)
        return files

    def _walk_with_ignore(self, scan_root: str) -> List[str]:
        files = []
        root = os.path.abspath(scan_root)

        for dirpath, dirnames, filenames in os.walk(root):
            rel_path = os.path.relpath(dirpath, root)

            # Early skip directories if they match any of the patterns
            if self._should_skip_dir(rel_path):
                self.print_debug(f'Skipping directory: {rel_path}')
                dirnames.clear()
                continue

            for filename in filenames:
                file_rel_path = os.path.join(rel_path, filename)
                file_path = os.path.join(dirpath, filename)
                file_size = os.path.getsize(file_path)

                if file_size < self.min_size or file_size > self.max_size:
                    self.print_debug(f'Skipping file: {file_rel_path} (size: {file_size})')
                    continue
                if self.path_spec.match_file(file_rel_path):
                    self.print_debug(f'Skipping file: {file_rel_path}')
                    continue
                else:
                    files.append(file_rel_path)

        return files

    def _should_skip_dir(self, dir_rel_path: str) -> bool:
        return any(dir_rel_path.startswith(p) for p in self.skip_patterns) or self.path_spec.match_file(
            dir_rel_path + '/'
        )
