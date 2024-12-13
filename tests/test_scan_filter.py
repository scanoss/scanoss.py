import os
import shutil
import tempfile
import unittest
from pathlib import Path

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

    def get_relative_paths(self, filtered_files):
        test_dir_path = Path(self.test_dir).resolve()
        return [str(Path(f).resolve().relative_to(test_dir_path)) for f in filtered_files]

    def test_default_extensions(self):
        files = [
            'file2.js',
            'file1.go',
            'dir1/file3.py',
            'dir1/file4.go',
            'dir2/file5.js',
            'dir2/file6.png',
        ]
        self.create_files(files)

        expected_files = [
            'file2.js',
            'file1.go',
            'dir1/file3.py',
            'dir1/file4.go',
            'dir2/file5.js',
        ]

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), sorted(expected_files))

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

        filtered_files = self.file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), sorted(expected_files))

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
            'file1.js',
            'file2.go',
            'file3.py',
        ]
        self.create_files(files)

        for file in files:
            file_path = os.path.join(self.test_dir, file)
            with open(file_path, 'w') as f:
                f.write('a' * (100 if 'file1' in file else 200 if 'file2' in file else 300))

        # For scanning, only *.py files have size limits
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), ['file1.js', 'file2.go', 'file3.py'])

        # For fingerprinting, all files have size limits
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'fingerprinting')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), ['file2.go', 'file3.py'])

    def test_all_extensions(self):
        file_filters = FileFilters(debug=True, all_extensions=True, hidden_files_folders=True)
        files = [
            'file1.txt',
            'file2.md',
            'file3.py',
            'file4.rst',
            'file5.png',
        ]
        self.create_files(files)

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), sorted(files))

    def test_all_folders(self):
        file_filters = FileFilters(debug=True, all_folders=True, hidden_files_folders=True)
        files = [
            '__pycache__/file1.py',
            'nbdist/file2.py',
            'venv/file3.py',
            'normal_dir/file4.py',
        ]
        self.create_files(files)

        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), sorted(files))

    def test_custom_patterns(self):
        settings = ScanossSettings()
        settings.data = {'settings': {'skip': {'patterns': {'scanning': ['*.rst', '*.md', '*.txt']}}}}
        file_filters = FileFilters(debug=True, scanoss_settings=settings, hidden_files_folders=True)

        files = [
            'file1.txt',
            'file2.md',
            'file3.py',
            'file4.rst',
        ]
        self.create_files(files)

        expected_files = ['file3.py']
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), sorted(expected_files))

    def test_different_patterns_per_operation(self):
        settings = ScanossSettings()
        settings.data = {
            'settings': {'skip': {'patterns': {'scanning': ['*.rst', '*.md', '*.txt'], 'fingerprinting': ['*.md']}}}
        }
        file_filters = FileFilters(debug=True, scanoss_settings=settings, hidden_files_folders=True)

        files = [
            'file1.txt',
            'file2.md',
            'file3.py',
            'file4.rst',
        ]
        self.create_files(files)

        # Test scanning patterns
        expected_files = ['file3.py']
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'scanning')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), sorted(expected_files))

        # Test fingerprinting patterns
        expected_files = ['file1.txt', 'file3.py', 'file4.rst']
        filtered_files = file_filters.get_filtered_files_from_folder(self.test_dir, 'fingerprinting')
        self.assertEqual(sorted(self.get_relative_paths(filtered_files)), sorted(expected_files))


if __name__ == '__main__':
    unittest.main()
