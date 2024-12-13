import os
import shutil
import tempfile
import unittest

from scanoss.file_filters import FileFilters
from scanoss.scanoss_settings import ScanossSettings


class TestFileFilters(unittest.TestCase):
    def setUp(self):
        self.file_filters = FileFilters(debug=True, hidden_files_folders=True)
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

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
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

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
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

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
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
        file_filters = FileFilters(debug=True, scanoss_settings=settings, hidden_files_folders=True)

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

        # For scanning, only *.py files have size limits
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(filtered_files), ['file1.js', 'file2.py'])

        # For fingerprinting, all files have size limits
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'fingerprinting')
        self.assertEqual(sorted(filtered_files), ['file2.py'])

    def test_all_extensions_flag(self):
        file_filters = FileFilters(debug=True, all_extensions=True, hidden_files_folders=True)

        files = [
            'file1.js',
            'file2.css',  # Would normally be skipped
            'file3.doc',  # Would normally be skipped
            'dir1/file4.csv',  # Would normally be skipped
        ]
        self.create_files(files)

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(filtered_files), sorted(files))

    def test_all_folders_flag(self):
        file_filters = FileFilters(debug=True, all_folders=True, hidden_files_folders=True)

        files = [
            '__pycache__/file1.py',  # Would normally be skipped
            'venv/file2.py',  # Would normally be skipped
            'dir1/nbdist/file3.py',  # Would normally be skipped
            'dir1/file4.py',
        ]
        self.create_files(files)

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(filtered_files), sorted(files))

    def test_get_filtered_files_from_files(self):
        files = [
            'file1.js',
            'file2.css',  # Should be skipped
            'dir1/file3.py',
            'dir1/__pycache__/file4.py',  # Should be skipped
        ]
        self.create_files(files)

        file_paths = [os.path.join(self.test_dir, f) for f in files]
        filtered_files = self.file_filters.get_filtered_files_from_files(file_paths, 'scanning', self.test_dir)

        expected_files = [
            'file1.js',
            'dir1/file3.py',
        ]
        self.assertEqual(sorted(filtered_files), sorted(expected_files))


if __name__ == '__main__':
    unittest.main()
