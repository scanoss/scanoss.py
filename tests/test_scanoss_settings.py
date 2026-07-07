"""
SPDX-License-Identifier: MIT

  Copyright (c) 2026, SCANOSS

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

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from src.scanoss.scanner import Scanner
from src.scanoss.scanoss_settings import ScanossSettings
from src.scanoss.scantype import ScanType


class TestScanossSettingsLoadJsonFile(unittest.TestCase):
    def setUp(self):
        self.settings_payload = {
            "settings": {},
            "bom": {
                "include": [],
                "exclude": [],
                "remove": [],
                "replace": []
            }
        }
        self.original_cwd = os.getcwd()
        self.tests_dir = Path(__file__).resolve().parent
        os.chdir(self.tests_dir)

    def tearDown(self):
        os.chdir(self.original_cwd)

    def _write_settings_file(self, directory: Path, filename: str = "scanoss.json") -> Path:
        file_path = directory / filename
        file_path.write_text(json.dumps(self.settings_payload), encoding="utf-8")
        return file_path

    def test_loads_settings_from_scan_root_folder_first(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            scan_root = tmp_path / "project"
            scan_root.mkdir()

            settings_file = self._write_settings_file(scan_root)

            settings = ScanossSettings(debug=True)
            result = settings.load_json_file(None, str(scan_root))

            self.assertIs(result, settings)
            self.assertEqual(settings.data, self.settings_payload)
            self.assertTrue(settings_file.exists())

    def test_falls_back_to_cwd_when_missing_in_scan_root_folder(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            scan_root = tmp_path / "project"
            scan_root.mkdir()

            cwd_settings = tmp_path / "scanoss.json"
            cwd_settings.write_text(json.dumps(self.settings_payload), encoding="utf-8")

            settings = ScanossSettings(debug=True)
            with patch("os.getcwd", return_value=str(tmp_path)):
                with patch("pathlib.Path.cwd", return_value=tmp_path):
                    result = settings.load_json_file(None, str(scan_root))

            self.assertIs(result, settings)
            self.assertEqual(settings.data, self.settings_payload)

    def test_loads_settings_from_parent_directory_for_file_target(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            target_dir = tmp_path / "project"
            target_dir.mkdir()

            target_file = target_dir / "foo.c"
            target_file.write_text("int main() {}", encoding="utf-8")

            settings_file = self._write_settings_file(target_dir)

            settings = ScanossSettings()
            result = settings.load_json_file(None, str(target_file))

            self.assertIs(result, settings)
            self.assertEqual(settings.data, self.settings_payload)
            self.assertTrue(settings_file.exists())

    def test_returns_empty_settings_when_no_file_found(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            scan_root = tmp_path / "project"
            scan_root.mkdir()

            settings = ScanossSettings(debug=True)
            result = settings.load_json_file(None, str(scan_root))

            self.assertIs(result, settings)
            self.assertEqual(settings.data, {})


class TestScanFolderWithOptionsDependencyScope(unittest.TestCase):
    """Regression tests: with --scan-root <root> <subdir>, dependency scanning must be
    scoped to <root>/<subdir> (via filter_path), matching fingerprinting's scope -
    not the whole scan root, which would pull in dependencies from sibling paths."""

    def _make_scanner(self):
        scanner = Scanner(
            quiet=True,
            nb_threads=0,
            scan_options=ScanType.SCAN_DEPENDENCIES.value,
        )
        scanner.threaded_deps.run = MagicMock(return_value=True)
        return scanner

    def test_dependency_scan_scoped_to_filter_path(self):
        scanner = self._make_scanner()
        scanner.scan_folder_with_options('.', filter_path='subdir')

        scanner.threaded_deps.run.assert_called_once()
        self.assertEqual(
            scanner.threaded_deps.run.call_args.kwargs['what_to_scan'],
            os.path.join('.', 'subdir'),
        )

    def test_dependency_scan_uses_scan_dir_when_no_filter_path(self):
        scanner = self._make_scanner()
        scanner.scan_folder_with_options('.')

        scanner.threaded_deps.run.assert_called_once()
        self.assertEqual(scanner.threaded_deps.run.call_args.kwargs['what_to_scan'], '.')
