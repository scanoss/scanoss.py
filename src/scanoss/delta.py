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
import os
import shutil
import tempfile

from .scanossbase import ScanossBase


class Delta(ScanossBase):
    """
    Handle delta scan operations by copying files into a dedicated delta directory.

    This class manages the creation of delta directories and copying of specified files
    while preserving directory structure. Files are read from an input file where each
    line contains a file path to copy.
    """
    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        filepath: str = None,
        folder: str = None,
        output: str = None,
    ):
        """
        Initialise the Delta instance.

        :param debug: Enable debug logging
        :param trace: Enable trace logging
        :param quiet: Enable quiet mode (suppress non-essential output)
        :param filepath: Path to input file containing list of files to copy
        :param folder: Target delta directory path (auto-generated if not provided)
        :param output: Output file path for delta directory location (stdout if not provided)
        """
        super().__init__(debug, trace, quiet)
        self.filepath = filepath
        self.folder = folder
        self.output = output

    def copy(self):
        """
        Copy files listed in the input file to the delta directory.

        Reads the input file line by line, where each line contains a file path.
        Creates the delta directory if it doesn't exist, then copies each file
        while preserving its directory structure.

        :return: Tuple of (status_code, folder_path) where status_code is 0 for success,
                 1 for error, and folder_path is the delta directory path
        """
        # Validate that input file exists
        if not os.path.exists(self.filepath):
            self.print_stderr(f'ERROR: Input file {self.filepath} does not exist')
            return 1, ''
        # Create delta dir (folder)
        folder = self.delta_dir(self.folder)
        if not folder:
            self.print_stderr(f'ERROR: Input folder {self.folder} already exists')
            return 1, ''
        self.print_to_file_or_stdout(folder, self.output)
        # Read files from filepath
        try:
            with open(self.filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    source_file = line.rstrip('\n\r')
                    # Skip empty lines
                    if not source_file:
                        continue

                    # Normalise the source path to handle '..' and redundant separators
                    normalised_source = os.path.normpath(source_file)

                    # Resolve to the absolute path for source validation
                    abs_source = os.path.abspath(normalised_source)

                    # Check if the source file exists and is a file
                    if not os.path.exists(abs_source):
                        self.print_stderr(f'WARNING: File {source_file} does not exist, skipping')
                        continue
                    if not os.path.isfile(abs_source):
                        self.print_stderr(f'WARNING: {source_file} is not a file, skipping')
                        continue

                    # Copy files into delta dir
                    try:
                        # Use a normalised source for destination to prevent traversal
                        # Remove leading path separators and '..' components from destination
                        safe_dest_path = normalised_source.lstrip(os.sep).lstrip('/')
                        while safe_dest_path.startswith('..'):
                            safe_dest_path = safe_dest_path[2:].lstrip(os.sep).lstrip('/')

                        dest_path = os.path.join(folder, safe_dest_path)

                        # Final safety check: ensure destination is within delta folder
                        abs_dest = os.path.abspath(dest_path)
                        abs_folder = os.path.abspath(folder)
                        if not abs_dest.startswith(abs_folder + os.sep):
                            self.print_stderr(f'ERROR: Destination path escapes delta directory for {source_file},'
                                              f' skipping')
                            continue

                        dest_dir = os.path.dirname(dest_path)
                        if dest_dir:
                            os.makedirs(dest_dir, exist_ok=True)
                        shutil.copy(abs_source, dest_path)
                    except (OSError, shutil.Error) as copy_err:
                        self.print_stderr(f'ERROR: Failed to copy {source_file}: {copy_err}')
                        continue
        except (OSError, IOError) as read_err:
            self.print_stderr(f'ERROR: Failed to read input file: {read_err}')
            return 1, ''
        return 0, folder

    def delta_dir(self, folder):
        """
        Create or validate the delta directory.

        If no folder is specified, creates a unique temporary directory with
        a 'delta-' prefix in the current directory. If a folder is specified,
        validates that it doesn't already exist before creating it.

        :param folder: Optional target directory path
        :return: Path to the delta directory, or empty string if folder already exists or creation fails
        """
        if folder and os.path.exists(folder):
            self.print_stderr(f'Folder {folder} already exists')
            return ''
        elif folder:
            try:
                os.makedirs(folder)
            except (OSError, IOError) as e:
                self.print_stderr(f'ERROR: Failed to create directory {folder}: {e}')
                return ''
        else:
            try:
                folder = tempfile.mkdtemp(prefix="delta-", dir='.')
            except (OSError, IOError) as e:
                self.print_stderr(f'ERROR: Failed to create temporary directory: {e}')
                return ''
        return folder

