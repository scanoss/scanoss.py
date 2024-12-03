import os
import shutil
import tempfile
import unittest

from scanoss.scan_filter import ScanFilter


class TestScanFilter(unittest.TestCase):
    def setUp(self):
        self.scan_filter = ScanFilter(debug=True)
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
            'file1.go',
            'file2.js',
            'dir1/file3.py',
            'dir1/file4.go',
            'dir2/file5.js',
            'dir2/file6.png',
        ]
        self.create_files(files)

        expected_files = [
            'file2.js',
            'file1.go',
            'dir2/file5.js',
            'dir1/file3.py',
            'dir1/file4.go',
        ]

        filtered_files = self.scan_filter.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(filtered_files, expected_files)

    def test_default_folders(self):
        files = [
            '__pycache__/file1.pyc',
            '__pycache__/file2.pyc',
            'dir1/nbdist/test.py',
            'dir1/nbdist/test1.py',
            'dir1/file3.py',
            'dir1/file4.go',
        ]
        self.create_files(files)

        expected_files = [
            'dir1/file3.py',
            'dir1/file4.go',
        ]

        filtered_files = self.scan_filter.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(filtered_files, expected_files)

    def test_skip_files_by_size(self):
        self.scan_filter.min_size = 150
        self.scan_filter.max_size = 450

        files = [
            'file1.js',
            'file2.go',
            'file3.py',
        ]
        self.create_files(files)

        for file in files:
            file_path = os.path.join(self.test_dir, file)
            with open(file_path, 'w') as f:
                f.write('a' * (100 if 'file1' in file else 200 if 'file2' in file else 300))

        expected_files = ['file3.py', 'file2.go']

        filtered_files = self.scan_filter.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(filtered_files, expected_files)

    def test_skip_directories(self):
        files = [
            'file1.js',
            'dir1/file2.js',
            'dir2/file3.py',
        ]
        self.create_files(files)

        self.scan_filter.skip_patterns.append('dir2/')

        expected_files = ['file1.js', 'dir1/file2.js']

        filtered_files = self.scan_filter.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(filtered_files, expected_files)

    def test_custom_skip_patterns(self):
        files = [
            'file1.txt',
            'file2.md',
            'file3.py',
            'file4.rst',
        ]
        self.create_files(files)

        self.scan_filter.skip_patterns.append('*.rst')

        expected_files = ['file3.py']

        filtered_files = self.scan_filter.get_filtered_files_from_folder(self.test_dir)
        self.assertEqual(filtered_files, expected_files)


if __name__ == '__main__':
    unittest.main()
