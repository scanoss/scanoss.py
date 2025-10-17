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
from typing import Optional

from .scanossbase import ScanossBase


class Delta(ScanossBase):
    """
    Handle delta scan operations by copying files into a dedicated delta directory.

    This class manages the creation of delta directories and copying of specified files
    while preserving the directory structure. Files are read from an input file where each
    line contains a file path to copy.
    """

    def __init__(  # noqa: PLR0913
            self,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False,
            filepath: str = None,
            folder: str = None,
            output: str = None,
            root_dir: str = None,
    ):
        """
        Initialise the Delta instance.

        :param debug: Enable debug logging.
        :param trace: Enable trace logging.
        :param quiet: Enable quiet mode (suppress non-essential output).
        :param filepath: Path to an input file containing a list of files to copy.
        :param folder: A target delta directory path (auto-generated if not provided).
        :param output: Output file path for the delta directory location (stdout if not provided).
        """
        super().__init__(debug, trace, quiet)
        self.filepath = filepath
        self.folder = folder
        self.output = output
        self.root_dir = root_dir if root_dir else '.'

    def copy(self, input_file: str = None):
        """
        Copy files listed in the input file to the delta directory.

        Reads the input file line by line, where each line contains a file path.
        Creates the delta directory if it doesn't exist, then copies each file
        while preserving its directory structure.

        :return: Tuple of (status_code, folder_path) where status_code is 0 for success,
                 1 for error, and folder_path is the delta directory path
        """
        input_file = input_file if input_file else self.filepath
        if not input_file:
            self.print_stderr('ERROR: No input file specified')
            return 1, ''
        # Validate that an input file exists
        if not os.path.isfile(input_file):
            self.print_stderr(f'ERROR: Input file {input_file} does not exist or is not a file')
            return 1, ''
        # Load the input file and validate it contains valid file paths
        files = self.load_input_file(input_file)
        if files is None:
            return 1, ''
        # Create delta dir (folder)
        delta_folder = self.create_delta_dir(self.folder, self.root_dir)
        if not delta_folder:
            return 1, ''
        # Print delta folder location to output
        self.print_to_file_or_stdout(delta_folder, self.output)
        # Process each file and copy it to the delta dir
        for source_file in files:
            # Normalise the source path to handle ".." and redundant separators
            normalised_source = os.path.normpath(source_file)
            if '..' in normalised_source:
                self.print_stderr(f'WARNING: Source path escapes root directory for {source_file}. Skipping.')
                continue
            # Resolve to the absolute path for source validation
            abs_source = os.path.abspath(os.path.join(self.root_dir, normalised_source))
            # Check if the source file exists and is a file
            if not os.path.exists(abs_source) or not os.path.isfile(abs_source):
                self.print_stderr(f'WARNING: File {source_file} does not exist or is not a file, skipping')
                continue
            # Use a normalised source for destination to prevent traversal
            dest_path = os.path.normpath(os.path.join(self.root_dir, delta_folder, normalised_source.lstrip(os.sep)))
            # Final safety check: ensure destination is within the delta folder
            abs_dest = os.path.abspath(dest_path)
            abs_folder = os.path.abspath(os.path.join(self.root_dir, delta_folder))
            if not abs_dest.startswith(abs_folder + os.sep):
                self.print_stderr(
                    f'WARNING: Destination path ({abs_dest}) escapes delta directory for {source_file}. Skipping.')
                continue
            # Create the destination directory if it doesn't exist and copy the file
            try:
                dest_dir = os.path.dirname(dest_path)
                if dest_dir:
                    self.print_trace(f'Creating directory {dest_dir}...')
                    os.makedirs(dest_dir, exist_ok=True)
                self.print_debug(f'Copying {source_file} to {dest_path} ...')
                shutil.copy(abs_source, dest_path)
            except (OSError, shutil.Error) as e:
                self.print_stderr(f'ERROR: Failed to copy {source_file} to {dest_path}: {e}')
                return 1, ''
        return 0, delta_folder

    def create_delta_dir(self, folder: str, root_dir: str = '.') -> str or None:
        """
        Create the delta directory.

        If no folder is specified, creates a unique temporary directory with
        a 'delta-' prefix in the current directory. If a folder is specified,
        validates that it doesn't already exist before creating it.

        :param root_dir: Root directory to create the delta directory in (default: current directory)
        :param folder: Optional target directory
        :return: Path to the delta directory, or None if it already exists or creation fails
        """
        if folder:
            # Resolve a relative folder under root_dir so checks/creation apply to the right place
            resolved = folder if os.path.isabs(folder) else os.path.join(root_dir, folder)
            resolved = os.path.normpath(resolved)
            # Validate the target directory doesn't already exist and create it
            if os.path.exists(resolved):
                self.print_stderr(f'ERROR: Folder {resolved} already exists.')
                return None
            else:
                try:
                    self.print_debug(f'Creating delta directory {resolved}...')
                    os.makedirs(resolved)
                except (OSError, IOError) as e:
                    self.print_stderr(f'ERROR: Failed to create directory {resolved}: {e}')
                    return None
        else:
            # Create a unique temporary directory in the given root directory
            try:
                self.print_debug(f'Creating temporary delta directory in {root_dir} ...')
                folder = tempfile.mkdtemp(prefix="delta-", dir=root_dir)
                if folder:
                    folder = os.path.relpath(folder, start=root_dir)  # Get the relative path from root_dir
                self.print_debug(f'Created temporary delta directory: {folder}')
            except (OSError, IOError) as e:
                self.print_stderr(f'ERROR: Failed to create temporary directory in {root_dir}: {e}')
                return None
        return folder

    def load_input_file(self, input_file: str) -> Optional[list[str]]:
        """
        Loads and parses the input file line by line. Each line in the input
        file represents a source file path, which will be stripped of trailing
        whitespace and appended to the resulting list if it is not empty.

        :param input_file: The path to the input file to be read.
        :type input_file: String
        :return: A list of source file paths extracted from the input file,
            or None if an error occurs or the file path is invalid.
        :rtype: An array list[str] or None
        """
        files = []
        if input_file:
            try:
                with open(input_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        source_file = line.rstrip()
                        if source_file:
                            # Save the file path without any leading separators
                            files.append(source_file.lstrip(os.sep))
                    # End of for loop
            except (OSError, IOError) as e:
                self.print_stderr(f'ERROR: Failed to read input file; {input_file}: {e}')
                return None
        self.print_debug(f'Loaded {len(files)} files from input file.')
        return files
