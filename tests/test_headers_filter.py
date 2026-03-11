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
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

from scanoss.header_filter import HeaderFilter

TEST_FILES_TAR = Path(__file__).parent / 'data' / 'test_src_files.tar.gz'


class TestHeaderFilter(unittest.TestCase):
    """
    Test suite for HeaderFilter class functionality
    """

    @classmethod
    def setUpClass(cls):
        """Extract test data files from tar archive."""
        cls._temp_dir = tempfile.mkdtemp()
        with tarfile.open(TEST_FILES_TAR, 'r:gz') as tf:
            tf.extractall(cls._temp_dir)

    @classmethod
    def tearDownClass(cls):
        """Clean up extracted test data."""
        shutil.rmtree(cls._temp_dir)

    def setUp(self):
        """Set up test fixtures"""
        self.header_filter = HeaderFilter(debug=False, quiet=True)

    def _read_test_file(self, filename: str) -> str:
        """Read an extracted test file."""
        return (Path(self._temp_dir) / 'src' / filename).read_text(encoding='utf-8')

    # -------------------------------------------------------------------
    # File-based tests (mirrors scanoss.java TestHeaderFilter)
    # -------------------------------------------------------------------

    def test_java_file(self):
        """Test Java file with Apache license + imports"""
        contents = self._read_test_file('TokenVerifier.java')
        offset = self.header_filter.filter('TokenVerifier.java', contents)
        self.assertEqual(offset, 46, 'TokenVerifier.java offset should be 46')

    def test_python_file(self):
        """Test Python file with MIT license docstring + imports"""
        contents = self._read_test_file('results.py')
        offset = self.header_filter.filter('results.py', contents)
        self.assertEqual(offset, 31, 'results.py offset should be 31')

    def test_c_file(self):
        """Test C file with SPDX + license block + includes"""
        contents = self._read_test_file('crc32c.c')
        offset = self.header_filter.filter('crc32c.c', contents)
        self.assertEqual(offset, 50, 'crc32c.c offset should be 50')

    def test_typescript_file(self):
        """Test TypeScript file with imports (no license header)"""
        contents = self._read_test_file('FileModel.ts')
        offset = self.header_filter.filter('FileModel.ts', contents)
        self.assertEqual(offset, 7, 'FileModel.ts offset should be 7')

    def test_go_file(self):
        """Test Go file with license + import block"""
        contents = self._read_test_file('handler.go')
        offset = self.header_filter.filter('handler.go', contents)
        self.assertEqual(offset, 18, 'handler.go offset should be 18')

    def test_rust_file(self):
        """Test Rust file with license + use statements"""
        contents = self._read_test_file('config.rs')
        offset = self.header_filter.filter('config.rs', contents)
        self.assertEqual(offset, 21, 'config.rs offset should be 21')

    def test_kotlin_file(self):
        """Test Kotlin file with Apache license + imports"""
        contents = self._read_test_file('HttpClient.kt')
        offset = self.header_filter.filter('HttpClient.kt', contents)
        self.assertEqual(offset, 26, 'HttpClient.kt offset should be 26')

    def test_scala_file(self):
        """Test Scala file with ASF license + imports"""
        contents = self._read_test_file('DataFrame.scala')
        offset = self.header_filter.filter('DataFrame.scala', contents)
        self.assertEqual(offset, 27, 'DataFrame.scala offset should be 27')

    def test_cpp_file(self):
        """Test C++ header with license + guards + includes"""
        contents = self._read_test_file('StringUtils.hpp')
        offset = self.header_filter.filter('StringUtils.hpp', contents)
        self.assertEqual(offset, 16, 'StringUtils.hpp offset should be 16')

    def test_csharp_file(self):
        """Test C# file with MIT license + usings"""
        contents = self._read_test_file('ServiceProvider.cs')
        offset = self.header_filter.filter('ServiceProvider.cs', contents)
        self.assertEqual(offset, 12, 'ServiceProvider.cs offset should be 12')

    def test_php_file(self):
        """Test PHP file — <?php tag is not recognized as header/import, so offset is 0"""
        contents = self._read_test_file('Router.php')
        offset = self.header_filter.filter('Router.php', contents)
        self.assertEqual(offset, 0, 'Router.php offset should be 0')

    def test_swift_file(self):
        """Test Swift file with Apple license + imports"""
        contents = self._read_test_file('Package.swift')
        offset = self.header_filter.filter('Package.swift', contents)
        self.assertEqual(offset, 15, 'Package.swift offset should be 15')

    def test_ruby_file(self):
        """Test Ruby file with MIT license + requires"""
        contents = self._read_test_file('logger.rb')
        offset = self.header_filter.filter('logger.rb', contents)
        self.assertEqual(offset, 18, 'logger.rb offset should be 18')

    def test_perl_file(self):
        """Test Perl file with shebang + license + use statements"""
        contents = self._read_test_file('parser.pl')
        offset = self.header_filter.filter('parser.pl', contents)
        self.assertEqual(offset, 15, 'parser.pl offset should be 15')

    def test_r_file(self):
        """Test R file with GPL license + library() calls"""
        contents = self._read_test_file('analysis.r')
        offset = self.header_filter.filter('analysis.r', contents)
        self.assertEqual(offset, 23, 'analysis.r offset should be 23')

    def test_lua_file(self):
        """Test Lua file with Apache license + require"""
        contents = self._read_test_file('cache.lua')
        offset = self.header_filter.filter('cache.lua', contents)
        self.assertEqual(offset, 14, 'cache.lua offset should be 14')

    def test_dart_file(self):
        """Test Dart file with Flutter license + imports"""
        contents = self._read_test_file('widget.dart')
        offset = self.header_filter.filter('widget.dart', contents)
        self.assertEqual(offset, 12, 'widget.dart offset should be 12')

    def test_haskell_file(self):
        """Test Haskell file with BSD license + module/import"""
        contents = self._read_test_file('Parser.hs')
        offset = self.header_filter.filter('Parser.hs', contents)
        self.assertEqual(offset, 12, 'Parser.hs offset should be 12')

    def test_elixir_file(self):
        """Test Elixir file — uses # comments but defaults to c_style detection, so offset is 0"""
        contents = self._read_test_file('server.ex')
        offset = self.header_filter.filter('server.ex', contents)
        self.assertEqual(offset, 0, 'server.ex offset should be 0')

    def test_clojure_file(self):
        """Test Clojure file — uses ;; comments but defaults to c_style detection, so offset is 0"""
        contents = self._read_test_file('core.clj')
        offset = self.header_filter.filter('core.clj', contents)
        self.assertEqual(offset, 0, 'core.clj offset should be 0')

    def test_objectivec_file(self):
        """Test Objective-C file with Apple license + #import"""
        contents = self._read_test_file('ViewController.m')
        offset = self.header_filter.filter('ViewController.m', contents)
        self.assertEqual(offset, 6, 'ViewController.m offset should be 6')

    def test_shell_file(self):
        """Test Shell script with shebang + license comments"""
        contents = self._read_test_file('deploy.sh')
        offset = self.header_filter.filter('deploy.sh', contents)
        self.assertEqual(offset, 7, 'deploy.sh offset should be 7')

    def test_javascript_file(self):
        """Test JavaScript file with MIT license + require"""
        contents = self._read_test_file('server.js')
        offset = self.header_filter.filter('server.js', contents)
        self.assertEqual(offset, 23, 'server.js offset should be 23')

    def test_multiline_imports_python_file(self):
        """Test Python file with multiline imports — the exact scenario that was broken"""
        contents = self._read_test_file('multiline_imports.py')
        offset = self.header_filter.filter('multiline_imports.py', contents)
        self.assertEqual(offset, 91, 'multiline_imports.py offset should be 91')

    # -------------------------------------------------------------------
    # Utility / edge case tests
    # -------------------------------------------------------------------

    def test_unsupported_extension(self):
        """Test that unsupported file extensions return 0"""
        offset = self.header_filter.filter('file.unknown', 'some content\nwith lines\n')
        self.assertEqual(offset, 0, 'Unsupported extension should return 0')

    def test_empty_file(self):
        """Test handling of empty file"""
        offset = self.header_filter.filter('test.py', '')
        self.assertEqual(offset, 0, 'Empty file should have 0 offset')

    def test_no_header(self):
        """Test file with no header — implementation starts at line 1"""
        content = 'public class MyClass {\n    int x = 1;\n}\n'
        offset = self.header_filter.filter('test.java', content)
        self.assertEqual(offset, 0, 'File with no header should return 0')

    def test_file_with_only_license_and_comments(self):
        """Test file that contains only license and comments (no implementation)"""
        content = '# Copyright 2024\n# MIT License\n#\n# This is just a license file\n# with no actual code\n'
        offset = self.header_filter.filter('test.py', content)
        self.assertEqual(offset, 0, 'Line offset should be 0 when no implementation found')

    def test_max_lines_limit(self):
        """Test that max_lines parameter limits output"""
        content = (
            '// Copyright 2024\n'
            '// Licensed under MIT\n'
            '// All rights reserved\n'
            '\n'
            'import java.util.List;\n'
            'import java.io.File;\n'
            'import java.util.Map;\n'
            'import java.util.Set;\n'
            '\n'
            'public class Foo {}\n'
        )
        limited = HeaderFilter(skip_limit=5, debug=False, quiet=True)
        offset = limited.filter('test.java', content)
        self.assertEqual(offset, 5, 'Should cap at max_lines=5')

    def test_detect_language(self):
        """Test language detection from file extensions"""
        self.assertEqual(self.header_filter.detect_language('test.py'), 'python')
        self.assertEqual(self.header_filter.detect_language('test.js'), 'javascript')
        self.assertEqual(self.header_filter.detect_language('test.ts'), 'typescript')
        self.assertEqual(self.header_filter.detect_language('test.go'), 'go')
        self.assertEqual(self.header_filter.detect_language('test.rs'), 'rust')
        self.assertEqual(self.header_filter.detect_language('test.java'), 'java')
        self.assertEqual(self.header_filter.detect_language('test.cpp'), 'cpp')
        self.assertEqual(self.header_filter.detect_language('test.c'), 'cpp')
        self.assertEqual(self.header_filter.detect_language('test.rb'), 'ruby')
        self.assertEqual(self.header_filter.detect_language('test.php'), 'php')
        self.assertEqual(self.header_filter.detect_language('test.swift'), 'swift')
        self.assertEqual(self.header_filter.detect_language('test.kt'), 'kotlin')
        self.assertEqual(self.header_filter.detect_language('test.scala'), 'scala')
        self.assertEqual(self.header_filter.detect_language('test.cs'), 'csharp')
        self.assertEqual(self.header_filter.detect_language('test.pl'), 'perl')
        self.assertEqual(self.header_filter.detect_language('test.r'), 'r')
        self.assertEqual(self.header_filter.detect_language('test.lua'), 'lua')
        self.assertEqual(self.header_filter.detect_language('test.dart'), 'dart')
        self.assertEqual(self.header_filter.detect_language('test.hs'), 'haskell')
        self.assertEqual(self.header_filter.detect_language('test.ex'), 'elixir')
        self.assertEqual(self.header_filter.detect_language('test.clj'), 'clojure')
        self.assertEqual(self.header_filter.detect_language('test.m'), 'cpp')
        self.assertEqual(self.header_filter.detect_language('test.sh'), 'python')
        self.assertIsNone(self.header_filter.detect_language('test.unknown'))

    def test_utf8_decode_error_handling(self):
        """Test handling of files that cannot be decoded as UTF-8"""
        test_content = b'\xff\xfe' + b'some content'
        test_string = test_content.decode('utf-8', 'ignore')
        offset = self.header_filter.filter('test.py', test_string)
        self.assertEqual(offset, 0, 'Should return 0 offset on decode error')


if __name__ == '__main__':
    unittest.main()
