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
import shutil
import tempfile
import unittest

from scanoss.file_filters import FileFilters
from scanoss.scanoss_settings import ScanossSettings


class TestFileFilters(unittest.TestCase):
    def setUp(self):
        self.file_filters = FileFilters(debug=True, hidden_files_folders=True, operation_type='scanning')
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def create_files(self, files):
        for file in files:
            file_path = os.path.join(self.test_dir, file)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                f.write('test')

    def test_default_extensions(self):
        files = [
            'file1.js',
            'file2.go',
            'file3.py',
            'file4.css',  # Should be skipped by default
            'file5.doc',  # Should be skipped by default
            'dir1/file6.py',
            'dir1/file7.go',
            'dir2/file8.js',
            'dir2/file9.csv',  # Should be skipped by default
        ]
        self.create_files(files)

        expected_files = [
            'file1.js',
            'file2.go',
            'file3.py',
            'dir1/file6.py',
            'dir1/file7.go',
            'dir2/file8.js',
        ]

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(expected_files))

    def test_default_folders(self):
        files = [
            '__pycache__/file1.pyc',
            'venv/file2.py',
            'dir1/nbdist/test.py',
            'dir1/eggs/test1.py',
            'dir1/file3.py',
            'dir1/file4.go',
            'dir2/wheels/test.js',
            'dir2/file5.js',
            'package.egg-info/file6.py',
        ]
        self.create_files(files)

        expected_files = [
            'dir1/file3.py',
            'dir1/file4.go',
            'dir2/file5.js',
        ]

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(expected_files))

    def test_default_skipped_files(self):
        files = [
            'gradlew',
            'gradlew.bat',
            'mvnw',
            'license.txt',
            'makefile',
            'normal_file.py',
            'dir1/gradle-wrapper.jar',
            'dir1/normal_file.js',
        ]
        self.create_files(files)

        expected_files = [
            'normal_file.py',
            'dir1/normal_file.js',
        ]

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(expected_files))

    def test_size_limits(self):
        settings = ScanossSettings()
        settings.data = {
            'settings': {
                'skip': {
                    'sizes': {
                        'scanning': [{'patterns': ['*.py'], 'min': 150, 'max': 450}],
                        'fingerprinting': [{'patterns': ['*'], 'min': 150, 'max': 450}],
                    }
                }
            }
        }
        files = [
            'file1.js',  # 100 bytes
            'file2.py',  # 200 bytes - within limits
            'file3.py',  # 500 bytes - exceeds max
            'file4.py',  # 100 bytes - below min
        ]

        for file in files:
            file_path = os.path.join(self.test_dir, file)
            with open(file_path, 'w') as f:
                if 'file1' in file:
                    f.write('a' * 100)
                elif 'file2' in file:
                    f.write('a' * 200)
                elif 'file3' in file:
                    f.write('a' * 500)
                else:
                    f.write('a' * 100)

        file_filters = FileFilters(
            debug=True, scanoss_settings=settings, hidden_files_folders=True, operation_type='scanning'
        )

        # For scanning, only *.py files have size limits
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), ['file1.js', 'file2.py'])

        file_filters = FileFilters(
            debug=True, scanoss_settings=settings, hidden_files_folders=True, operation_type='fingerprinting'
        )

        # For fingerprinting, all files have size limits
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), ['file2.py'])

    def test_all_extensions_flag(self):
        file_filters = FileFilters(
            debug=True, all_extensions=True, hidden_files_folders=True, operation_type='scanning'
        )
        files = [
            'file1.js',
            'file2.css',  # Would normally be skipped
            'file3.doc',  # Would normally be skipped
            'dir1/file4.csv',  # Would normally be skipped
        ]
        self.create_files(files)

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(files))

    def test_all_folders_flag(self):
        file_filters = FileFilters(debug=True, all_folders=True, hidden_files_folders=True, operation_type='scanning')

        files = [
            '__pycache__/file1.py',  # Would normally be skipped
            'venv/file2.py',  # Would normally be skipped
            'dir1/nbdist/file3.py',  # Would normally be skipped
            'dir1/file4.py',
        ]
        self.create_files(files)

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(files))

    def test_get_filtered_files_from_files(self):
        files = [
            os.path.join(self.test_dir, 'file1.js'),
            os.path.join(self.test_dir, 'file2.css'),  # Should be skipped
            os.path.join(self.test_dir, 'dir1/file3.py'),
            os.path.join(self.test_dir, 'dir1/__pycache__/file4.py'), # Should be skipped
        ]
        self.create_files(files)

        filtered_files = self.file_filters.get_filtered_files_from_files(files, self.test_dir)

        expected_files = [
            'file1.js',
            'dir1/file3.py',
        ]
        self.assertEqual(sorted(filtered_files), sorted(expected_files))

    def test_hidden_files_and_folders_enabled(self):
        files = [
            '.hidden_file.py',
            '.hidden_dir/visible_file.py',
            '.hidden_dir/.nested_hidden_file.js',
            'visible_dir/.hidden_file.go',
            '.git/config',
            '.hidden_dir/nested_dir/.hidden_nested_file.py',
        ]
        self.create_files(files)

        expected_files = [
            '.hidden_file.py',
            '.hidden_dir/visible_file.py',
            '.hidden_dir/.nested_hidden_file.js',
            'visible_dir/.hidden_file.go',
            '.hidden_dir/nested_dir/.hidden_nested_file.py',
        ]

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(expected_files))

    def test_hidden_files_and_folders_disabled(self):
        file_filters = FileFilters(debug=True, hidden_files_folders=False, operation_type='scanning')
        files = [
            '.hidden_file.py',
            '.hidden_dir/visible_file.py',
            '.hidden_dir/.nested_hidden_file.js',
            'visible_dir/.hidden_file.go',
            'visible_file.py',
            '.git/config',
        ]
        self.create_files(files)

        expected_files = ['visible_file.py']

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(expected_files))

    def test_all_extensions_mode(self):
        file_filters = FileFilters(debug=True, all_extensions=True, hidden_files_folders=True)
        files = [
            'file1.css',
            'file2.doc',
            'file3.csv',
            '.hidden_file.dat',
            'dir1/file4.bmp',
            'dir1/.hidden/file5.class',
            'file6.py',
        ]
        self.create_files(files)

        expected_files = [
            'file1.css',
            'file2.doc',
            'file3.csv',
            '.hidden_file.dat',
            'dir1/file4.bmp',
            'dir1/.hidden/file5.class',
            'file6.py',
        ]

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(expected_files))

    def test_all_folders_mode(self):
        file_filters = FileFilters(debug=True, all_folders=True, hidden_files_folders=True, operation_type='scanning')
        files = [
            '__pycache__/cache.py',
            'venv/lib.py',
            'eggs/module.py',
            'wheels/util.py',
            'normal_dir/file.py',
            '.git/config.py',
        ]
        self.create_files(files)

        expected_files = [
            '__pycache__/cache.py',
            'venv/lib.py',
            'eggs/module.py',
            'wheels/util.py',
            'normal_dir/file.py',
            '.git/config.py',
        ]

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(expected_files))

    def test_combined_all_modes(self):
        file_filters = FileFilters(
            debug=True, all_extensions=True, all_folders=True, hidden_files_folders=True, operation_type='scanning'
        )
        files = [
            '.hidden_dir/file1.css',
            '__pycache__/cache.dat',
            'venv/.hidden_file.class',
            'normal_dir/file.py',
            '.config/settings.bmp',
        ]
        self.create_files(files)

        expected_files = [
            '.hidden_dir/file1.css',
            '__pycache__/cache.dat',
            'venv/.hidden_file.class',
            'normal_dir/file.py',
            '.config/settings.bmp',
        ]

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(sorted(filtered_files), sorted(expected_files))


if __name__ == '__main__':
    unittest.main()
