"""
SPDX-License-Identifier: MIT

  Copyright (c) 2022, SCANOSS

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

import csv
import os
import pathlib
import sys
from contextlib import nullcontext

from progress.spinner import Spinner

from .scanossbase import ScanossBase


class FileCount(ScanossBase):
    """
    SCANOSS File Type Count class
    Handle the scanning of files, snippets and dependencies
    """

    def __init__(
        self,
        scan_output: str = None,
        hidden_files_folders: bool = False,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
    ):
        """
        Initialise scanning class
        """
        super().__init__(debug, trace, quiet)
        self.scan_output = scan_output
        self.isatty = sys.stderr.isatty()
        self.hidden_files_folders = hidden_files_folders

    def __filter_files(self, files: list) -> list:
        """
        Filter which files should be considered for processing
        :param files: list of files to filter
        :return list of filtered files
        """
        file_list = []
        for f in files:
            ignore = False
            if f.startswith('.') and not self.hidden_files_folders:  # Ignore all . files unless requested
                ignore = True
            if not ignore:
                file_list.append(f)
        return file_list

    def __filter_dirs(self, dirs: list) -> list:
        """
        Filter which folders should be considered for processing
        :param dirs: list of directories to filter
        :return: list of filtered directories
        """
        dir_list = []
        for d in dirs:
            ignore = False
            if d.startswith('.') and not self.hidden_files_folders:  # Ignore all . folders unless requested
                ignore = True
            if not ignore:
                dir_list.append(d)
        return dir_list

    def __log_result(self, string, outfile=None):
        """
        Logs result to file or STDOUT
        """
        if not outfile and self.scan_output:
            outfile = self.scan_output
        if outfile:
            with open(outfile, 'a') as rf:
                rf.write(string + '\n')
        else:
            print(string)

    def count_files(self, scan_dir: str) -> bool:
        """
        Search the specified folder producing counting the file types found
        :param scan_dir str
                    Directory to scan
        :return True if successful, False otherwise
        """
        success = True
        if not scan_dir:
            raise Exception('ERROR: Please specify a folder to scan')
        if not os.path.exists(scan_dir) or not os.path.isdir(scan_dir):
            raise Exception(f'ERROR: Specified folder does not exist or is not a folder: {scan_dir}')

        self.print_msg(f'Searching {scan_dir} for files to count...')
        spinner_ctx = Spinner('Searching ') if (not self.quiet and self.isatty) else nullcontext()

        with spinner_ctx as spinner:
            file_types = {}
            file_count = 0
            file_size = 0
            for root, dirs, files in os.walk(scan_dir):
                self.print_trace(f'U Root: {root}, Dirs: {dirs}, Files {files}')
                dirs[:] = self.__filter_dirs(dirs)  # Strip out unwanted directories
                filtered_files = self.__filter_files(files)  # Strip out unwanted files
                self.print_trace(f'F Root: {root}, Dirs: {dirs}, Files {filtered_files}')
                for file in filtered_files:  # Cycle through each filtered file
                    path = os.path.join(root, file)
                    f_size = 0
                    try:
                        f_size = os.stat(path).st_size
                    except Exception as e:
                        self.print_trace(f'Ignoring missing symlink file: {file} ({e})')  # broken symlink
                    if f_size > 0:  # Ignore broken links and empty files
                        file_count = file_count + 1
                        file_size = file_size + f_size
                        f_suffix = pathlib.Path(file).suffix
                        if not f_suffix or f_suffix == '':
                            f_suffix = 'no_suffix'
                        self.print_trace(f'Counting {path} ({f_suffix} - {f_size})..')
                        fc = file_types.get(f_suffix)
                        if not fc:
                            fc = [1, f_size]
                        else:
                            fc[0] = fc[0] + 1
                            fc[1] = fc[1] + f_size
                        file_types[f_suffix] = fc
                        if spinner:
                            spinner.next()
            # End for loop
        self.print_stderr(f'Found {file_count:,.0f} files with a total size of {file_size / (1 << 20):,.2f} MB.')
        if file_types:
            csv_dict = []
            for k in file_types:
                d = file_types[k]
                csv_dict.append({'extension': k, 'count': d[0], 'size(MB)': f'{d[1] / (1 << 20):,.2f}'})
            fields = ['extension', 'count', 'size(MB)']
            file = sys.stdout
            if self.scan_output:
                file = open(self.scan_output, 'w')
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()  # writing headers (field names)
            writer.writerows(csv_dict)  # writing data rows
            if self.scan_output:
                file.close()
        else:
            FileCount.print_stderr(f'Warning: No files found to count in folder: {scan_dir}')
        return success


#
# End of ScanOSS Class
#
