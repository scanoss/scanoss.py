import unittest
from unittest.mock import patch

from scanoss.scan_filter import ScanFilter


class TestScanFilter(unittest.TestCase):
    def setUp(self):
        self.scan_filter = ScanFilter(debug=True)

    @patch('os.walk')
    @patch('os.path.getsize')
    def test_default_extensions(self, mock_getsize, mock_walk):
        mock_walk.return_value = [
            ('/scan_root', ['dir1', 'dir2'], ['file1.go', 'file2.js']),
            ('/scan_root/dir1', [], ['file3.py', 'file4.go']),
            ('/scan_root/dir2', [], ['file5.js', 'file6.png']),
        ]
        mock_getsize.side_effect = [100, 200, 300, 400, 500, 600]

        # All the other files should be removed by the filter because they are in default skipped extensions
        expected_files = [
            './file1.go',
            './file2.js',
            'dir1/file3.py',
            'dir1/file4.go',
            'dir2/file5.js',
        ]

        filtered_files = self.scan_filter.get_filtered_files('/scan_root')
        self.assertEqual(filtered_files, expected_files)

    @patch('os.walk')
    @patch('os.path.getsize')
    def test_default_folders(self, mock_getsize, mock_walk):
        mock_walk.return_value = [
            ('/scan_root', ['__pycache__', 'dir1'], []),
            ('/scan_root/__pycache__', [], ['file1.pyc', 'file2.pyc']),
            ('/scan_root/dir1', ['nbdist'], ['file3.py', 'file4.go']),
            ('/scan_root/dir1/nbdist', [], ['test.py', 'test1.py']),
        ]
        mock_getsize.side_effect = [100, 200, 300, 400, 500, 600]

        # All the other files should be removed by the filter because they are in default skipped extensions
        expected_files = [
            'dir1/file3.py',
            'dir1/file4.go',
        ]

        filtered_files = self.scan_filter.get_filtered_files('/scan_root')
        self.assertEqual(filtered_files, expected_files)

    @patch('os.walk')
    @patch('os.path.getsize')
    def test_skip_files_by_size(self, mock_getsize, mock_walk):
        self.scan_filter.min_size = 150
        self.scan_filter.max_size = 450

        mock_walk.return_value = [
            ('/scan_root', [], ['file1.js', 'file2.go', 'file3.py']),
        ]
        mock_getsize.side_effect = [100, 200, 300]

        expected_files = ['./file2.go', './file3.py']

        filtered_files = self.scan_filter.get_filtered_files('/scan_root')
        self.assertEqual(filtered_files, expected_files)

    @patch('os.walk')
    @patch('os.path.getsize')
    def test_skip_directories(self, mock_getsize, mock_walk):
        mock_walk.return_value = [
            ('/scan_root', ['dir1', 'dir2'], ['file1.js']),
            ('/scan_root/dir1', [], ['file2.js']),
            ('/scan_root/dir2', [], ['file3.py']),
        ]

        mock_getsize.side_effect = [100, 200, 300]

        self.scan_filter.skip_patterns.append('dir2/')

        expected_files = ['./file1.js', 'dir1/file2.js']

        filtered_files = self.scan_filter.get_filtered_files('/scan_root')
        self.assertEqual(filtered_files, expected_files)

    @patch('os.walk')
    @patch('os.path.getsize')
    def test_custom_skip_patterns(self, mock_getsize, mock_walk):
        mock_walk.return_value = [
            ('/scan_root', [], ['file1.txt', 'file2.md', 'file3.py', 'file4.rst']),
        ]

        mock_getsize.side_effect = [100, 200, 300, 400]

        self.scan_filter.skip_patterns.append('*.rst')

        expected_files = ['./file3.py']

        filtered_files = self.scan_filter.get_filtered_files('/scan_root')
        self.assertEqual(filtered_files, expected_files)


if __name__ == '__main__':
    unittest.main()
