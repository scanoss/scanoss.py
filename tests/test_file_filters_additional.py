"""
Additional unit tests for FileFilters using unittest, aligned with existing project conventions.

Testing library/framework: unittest
- Discovered via existing tests (tests/test_file_filters.py) and absence of pytest in requirements/configs.
- These tests expand coverage on hidden files/dirs, default/custom skip rules, size limits,
  custom patterns, symlink handling, invalid inputs, and edge cases around scan roots.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path

from scanoss.file_filters import FileFilters


class DummyScanossSettings:
    def __init__(self, patterns=None, size_rules=None):
        self._patterns = patterns or []
        self._size_rules = size_rules or []

    def get_skip_patterns(self, operation_type: str):
        return list(self._patterns)

    def get_skip_sizes(self, operation_type: str):
        return list(self._size_rules)


def _write_file(p: Path, size: int = None, content: bytes | str = "x"):
    p.parent.mkdir(parents=True, exist_ok=True)
    if size is None:
        data = content if isinstance(content, (bytes, bytearray)) else str(content).encode()
        p.write_bytes(data)
        return
    with p.open("wb") as fh:
        chunk = b"a" * min(4096, size or 0)
        remaining = size or 0
        while remaining > 0:
            n = min(len(chunk), remaining)
            fh.write(chunk[:n])
            remaining -= n


class TestFileFiltersAdditional(unittest.TestCase):
    def setUp(self):
        self.tmpdir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmpdir, ignore_errors=True))

    def test_hidden_items_skipped_by_default(self):
        hidden_dir = self.tmpdir / ".hidden"
        hidden_dir.mkdir()
        hidden_file = hidden_dir / "f.txt"
        _write_file(hidden_file, size=1)
        dotfile = self.tmpdir / ".env"
        _write_file(dotfile, size=1)
        normal = self.tmpdir / "ok.txt"
        _write_file(normal, size=1)

        ff = FileFilters(quiet=True)
        res = ff.get_filtered_files_from_files(
            [str(hidden_file), str(dotfile), str(normal)],
            scan_root=str(self.tmpdir),
        )
        self.assertIn("ok.txt", res)
        self.assertNotIn(".hidden/f.txt", res)
        self.assertNotIn(".env", res)

    def test_hidden_included_when_flag_true(self):
        hidden_dir = self.tmpdir / ".config"
        hidden_dir.mkdir()
        f = hidden_dir / "a.txt"
        _write_file(f, size=5)

        ff = FileFilters(hidden_files_folders=True, quiet=True)
        res = ff.get_filtered_files_from_files([str(f)], scan_root=str(self.tmpdir))
        self.assertIn(".config/a.txt", res)

    def test_all_extensions_all_folders_override(self):
        pycache_file = self.tmpdir / "__pycache__" / "mod.pyc"
        pycache_file.parent.mkdir()
        _write_file(pycache_file, size=2)
        license_file = self.tmpdir / "license.txt"
        _write_file(license_file, size=2)

        ff = FileFilters(all_folders=True, all_extensions=True, quiet=True)
        res = ff.get_filtered_files_from_files(
            [str(pycache_file), str(license_file)],
            scan_root=str(self.tmpdir),
        )
        self.assertIn("__pycache__/mod.pyc", res)
        self.assertIn("license.txt", res)

    def test_default_exact_files_skipped(self):
        names = [
            "gradlew",
            "gradlew.bat",
            "mvnw",
            "mvnw.cmd",
            "gradle-wrapper.jar",
            "maven-wrapper.jar",
            "thumbs.db",
            "babel.config.js",
            "license.txt",
            "license.md",
            "copying.lib",
            "makefile",
        ]
        paths = []
        for n in names:
            p = self.tmpdir / n
            _write_file(p, size=1)
            paths.append(str(p))

        ff = FileFilters(quiet=True, hidden_files_folders=True)
        res = ff.get_filtered_files_from_files(paths, scan_root=str(self.tmpdir))
        for n in names:
            self.assertNotIn(n, res, msg=f"{n} should be skipped")

    def test_default_endings_skipped(self):
        suffixes = [".json", ".png", ".md", ".yml", ".min.js", ".xml", ".csv", ".pdf", ".po", ".ipynb"]
        ff = FileFilters(quiet=True, hidden_files_folders=True)
        paths = []
        for s in suffixes:
            p = self.tmpdir / f"data{s}"
            _write_file(p, size=1)
            paths.append(str(p))

        res = ff.get_filtered_files_from_files(paths, scan_root=str(self.tmpdir))
        for s in suffixes:
            self.assertNotIn(f"data{s}", res)

    def test_custom_skip_extensions(self):
        p1 = self.tmpdir / "a.zzz"
        p2 = self.tmpdir / "b.foo"
        p3 = self.tmpdir / "c.bar"
        for p in (p1, p2, p3):
            _write_file(p, size=1)

        ff = FileFilters(skip_extensions=[".zzz", ".foo"], quiet=True)
        res = ff.get_filtered_files_from_files([str(p1), str(p2), str(p3)], scan_root=str(self.tmpdir))
        self.assertNotIn("a.zzz", res)
        self.assertNotIn("b.foo", res)
        self.assertIn("c.bar", res)

    def test_zero_size_skipped(self):
        p = self.tmpdir / "empty.txt"
        _write_file(p, size=0)
        ff = FileFilters(quiet=True)
        res = ff.get_filtered_files_from_files([str(p)], scan_root=str(self.tmpdir))
        self.assertNotIn("empty.txt", res)

    def test_global_skip_size_minimum(self):
        small = self.tmpdir / "small.dat"
        big = self.tmpdir / "big.dat"
        _write_file(small, size=9)
        _write_file(big, size=10)

        ff = FileFilters(skip_size=10, all_extensions=True, quiet=True)
        res = ff.get_filtered_files_from_files([str(small), str(big)], scan_root=str(self.tmpdir))
        self.assertNotIn("small.dat", res)
        self.assertIn("big.dat", res)

    def test_size_rules_from_settings(self):
        size_rules = [
            {"patterns": ["*.png"], "min": 0, "max": 1024},
            {"patterns": ["**/*.bin"], "min": 100, "max": 200},
        ]
        settings = DummyScanossSettings(patterns=[], size_rules=size_rules)
        ff = FileFilters(scanoss_settings=settings, all_extensions=True, quiet=True)

        small_png = self.tmpdir / "image.png"
        large_png = self.tmpdir / "large" / "image.png"
        large_png.parent.mkdir(parents=True, exist_ok=True)
        _write_file(small_png, size=100)
        _write_file(large_png, size=2048)

        small_bin = self.tmpdir / "a.bin"
        ok_bin = self.tmpdir / "b.bin"
        big_bin = self.tmpdir / "c.bin"
        _write_file(small_bin, size=50)
        _write_file(ok_bin, size=150)
        _write_file(big_bin, size=250)

        res = ff.get_filtered_files_from_files(
            [str(small_png), str(large_png), str(small_bin), str(ok_bin), str(big_bin)],
            scan_root=str(self.tmpdir),
        )
        self.assertIn("image.png", res)
        self.assertNotIn("large/image.png", res)
        self.assertNotIn("a.bin", res)
        self.assertIn("b.bin", res)
        self.assertNotIn("c.bin", res)

    def test_custom_patterns_skip_files_and_dirs(self):
        settings = DummyScanossSettings(patterns=["docs/", "*.secret"], size_rules=[])
        ff = FileFilters(scanoss_settings=settings, quiet=True)

        docs_file = self.tmpdir / "docs" / "guide.txt"
        _write_file(docs_file, size=10)
        secret_file = self.tmpdir / "src" / "config.secret"
        _write_file(secret_file, size=10)
        keep_file = self.tmpdir / "src" / "keep.txt"
        _write_file(keep_file, size=10)

        files = [str(docs_file), str(secret_file), str(keep_file)]
        res = ff.get_filtered_files_from_files(files, scan_root=str(self.tmpdir))
        self.assertNotIn("docs/guide.txt", res)
        self.assertNotIn("src/config.secret", res)
        self.assertIn("src/keep.txt", res)

    def test_should_skip_dir_hidden_defaults_and_extensions(self):
        hidden = self.tmpdir / ".git"
        hidden.mkdir()
        pycache = self.tmpdir / "__pycache__"
        pycache.mkdir()
        egginfo = self.tmpdir / "pkg.egg-info"
        egginfo.mkdir()

        ff = FileFilters(quiet=True)
        self.assertTrue(ff.should_skip_dir(str(hidden.relative_to(self.tmpdir))))
        self.assertTrue(ff.should_skip_dir(str(pycache.relative_to(self.tmpdir))))
        self.assertTrue(ff.should_skip_dir(str(egginfo.relative_to(self.tmpdir))))

    def test_should_skip_dir_respects_all_folders(self):
        d = self.tmpdir / "__pycache__"
        d.mkdir()
        ff = FileFilters(all_folders=True, quiet=True)
        self.assertFalse(ff.should_skip_dir(str(d.relative_to(self.tmpdir))))

    def test_skip_folders_custom_list_case_sensitive(self):
        d1 = self.tmpdir / "SkipMe"
        d1.mkdir()
        d2 = self.tmpdir / "skipme"
        d2.mkdir()
        ff = FileFilters(skip_folders=["SkipMe"], quiet=True)
        self.assertTrue(ff.should_skip_dir(str(d1.relative_to(self.tmpdir))))
        self.assertFalse(ff.should_skip_dir(str(d2.relative_to(self.tmpdir))))

    def test_symlink_files_ignored(self):
        target = self.tmpdir / "real.txt"
        _write_file(target, size=3)
        link = self.tmpdir / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported on this platform")

        ff = FileFilters(quiet=True)
        res = ff.get_filtered_files_from_files([str(link), str(target)], scan_root=str(self.tmpdir))
        self.assertIn("real.txt", res)
        self.assertNotIn("link.txt", res)

    def test_nonexistent_and_nonfile_paths_skipped(self):
        missing = self.tmpdir / "missing.txt"
        directory = self.tmpdir / "adir"
        directory.mkdir()
        ff = FileFilters(quiet=True)
        res = ff.get_filtered_files_from_files([str(missing), str(directory)], scan_root=str(self.tmpdir))
        self.assertNotIn("missing.txt", res)
        self.assertNotIn("adir", res)

    def test_files_outside_scan_root_are_ignored(self):
        outside_dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(outside_dir, ignore_errors=True))
        outside_file = outside_dir / "ext.txt"
        _write_file(outside_file, size=5)

        ff = FileFilters(quiet=True)
        res = ff.get_filtered_files_from_files([str(outside_file)], scan_root=str(self.tmpdir))
        self.assertEqual(res, [])

    def test_get_filtered_files_from_folder_integration(self):
        (self.tmpdir / "src").mkdir()
        keep = self.tmpdir / "src" / "app.py"
        _write_file(keep, size=5)
        hidden_dir = self.tmpdir / ".hidden"
        hidden_dir.mkdir()
        _write_file(hidden_dir / "x.py", size=5)
        pycache = self.tmpdir / "__pycache__"
        pycache.mkdir()
        _write_file(pycache / "c.pyc", size=1)
        zero = self.tmpdir / "keep" / ".keep"
        zero.parent.mkdir()
        _write_file(zero, size=0)

        ff = FileFilters(quiet=True, all_extensions=True)
        res = ff.get_filtered_files_from_folder(str(self.tmpdir))

        self.assertIn("src/app.py", res)
        self.assertNotIn(".hidden/x.py", res)
        # __pycache__ is default-skipped by should_skip_dir; ensure it's not present
        self.assertNotIn("__pycache__/c.pyc", res)
        self.assertNotIn("keep/.keep", res)

    def test_folder_hashing_scan_file_lists(self):
        license_file = self.tmpdir / "license.txt"
        _write_file(license_file, size=3)
        ff = FileFilters(is_folder_hashing_scan=True, quiet=True)
        res = ff.get_filtered_files_from_files([str(license_file)], scan_root=str(self.tmpdir))
        self.assertIn("license.txt", res)

    def test_operation_size_limits_default(self):
        ff = FileFilters(quiet=True)
        p = self.tmpdir / "a.py"
        _write_file(p, size=1)
        mn, mx = ff._get_operation_size_limits(str(p))
        self.assertEqual(mn, 0)
        self.assertGreaterEqual(mx, 1)

    def test_operation_patterns_combines_defaults_and_settings(self):
        settings = DummyScanossSettings(patterns=["build/", "*.cache"], size_rules=[])
        ff = FileFilters(scanoss_settings=settings, quiet=True)
        patterns = ff._get_operation_patterns("scanning")
        self.assertTrue(any(p.endswith("/__pycache__/") or p == "__pycache__/" for p in patterns))
        self.assertTrue("build/" in patterns or any(p.endswith("/build/") for p in patterns))
        self.assertIn("*.cache", patterns)

    def test_file_folder_pattern_spec_and_skip_file(self):
        settings = DummyScanossSettings(patterns=["docs/", "*.secret"], size_rules=[])
        ff = FileFilters(scanoss_settings=settings, quiet=True)
        spec = ff._get_file_folder_pattern_spec("scanning")
        self.assertIsNotNone(spec)
        self.assertTrue(ff._should_skip_file("x/y/z.secret"))

    def test_size_limit_pattern_rules_filter(self):
        settings = DummyScanossSettings(
            patterns=[],
            size_rules=[
                {"patterns": ["*.a"], "min": 0, "max": 10},
                {"min": 0, "max": 10},  # should be filtered out
                {"patterns": [], "min": 0, "max": 10},  # filtered out
            ],
        )
        ff = FileFilters(scanoss_settings=settings, quiet=True)
        rules = ff._get_size_limit_pattern_rules("scanning")
        self.assertIsInstance(rules, list)
        self.assertTrue(all("patterns" in r and r["patterns"] for r in rules))
        self.assertEqual(len(rules), 1)

    # New targeted edge-case tests

    def test_get_operation_size_limits_with_none_and_global_skip(self):
        ff = FileFilters(skip_size=5, quiet=True)
        mn, mx = ff._get_operation_size_limits(None)
        self.assertEqual(mn, 5)
        self.assertGreater(mx, 1000)  # should reflect a large default upper bound

    def test_should_skip_dir_respects_custom_pattern_spec(self):
        settings = DummyScanossSettings(patterns=["docs/"], size_rules=[])
        ff = FileFilters(scanoss_settings=settings, quiet=True)
        d = self.tmpdir / "docs"
        d.mkdir()
        self.assertTrue(ff.should_skip_dir(str(d.relative_to(self.tmpdir))))

    def test_get_filtered_files_from_folder_with_non_directory_returns_empty(self):
        f = self.tmpdir / "somefile.txt"
        _write_file(f, size=10)
        ff = FileFilters(quiet=True)
        res = ff.get_filtered_files_from_folder(str(f))  # not a directory
        self.assertEqual(res, [])


if __name__ == "__main__":
    unittest.main()