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
        with open(self.filepath, 'r') as f:
            for line in f:
                source_file = line.rstrip('\n')
                # Skip empty lines
                if not source_file:
                    continue
                # Check if source file exists
                if not os.path.exists(source_file):
                    self.print_stderr(f'WARNING: File {source_file} does not exist, skipping')
                    continue
                # Copy files into delta dir
                dest_path = os.path.join(folder, source_file)
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                shutil.copy(source_file, dest_path)
        return 0, folder

    def delta_dir(self, folder):
        """
        Create or validate the delta directory.

        If no folder is specified, creates a unique temporary directory with
        a 'delta-' prefix in the current directory. If a folder is specified,
        validates that it doesn't already exist before creating it.

        :param folder: Optional target directory path
        :return: Path to the delta directory, or empty string if folder already exists
        """
        if folder and os.path.exists(folder):
            self.print_stderr(f'Folder {folder} already exists')
            return ''
        elif folder:
            os.makedirs(folder, exist_ok=True)
        else:
            folder = tempfile.mkdtemp(prefix="delta-", dir='.')
        return folder

