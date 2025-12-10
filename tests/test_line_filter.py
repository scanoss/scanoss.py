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
import unittest

from scanoss.line_filter import LineFilter


class TestLineFilter(unittest.TestCase):
    """
    Test suite for LineFilter class functionality
    """

    def setUp(self):
        """Set up test fixtures"""
        self.line_filter = LineFilter(debug=False, quiet=True)

    def test_python_basic_filtering(self):
        """Test basic Python file filtering with license and imports"""
        test_content = b"""# Copyright 2024
# Licensed under MIT
# All rights reserved

import os
import sys
from pathlib import Path

def main():
    print('Hello World')
    return 0

if __name__ == '__main__':
    main()
"""
        filtered_content, line_offset = self.line_filter.filter(
            'test.py', False, test_content
        )

        msg = "Should skip 8 lines (3 license + 1 blank + 3 imports + 1 blank)"
        self.assertEqual(line_offset, 8, msg)
        msg = "Filtered content should start with implementation"
        self.assertIn(b"def main():", filtered_content, msg)
        self.assertNotIn(
            b"Copyright", filtered_content, "License should be filtered out"
        )
        self.assertNotIn(
            b"import os", filtered_content, "Imports should be filtered out"
        )

    def test_javascript_multiline_comment(self):
        """Test JavaScript file with multiline license comment"""
        test_content = b"""/*
 * Copyright 2024
 * Licensed under MIT
 */

import React from 'react';
import { Component } from 'react';

class App extends Component {
    render() {
        return <div>Hello</div>;
    }
}

export default App;
"""
        filtered_content, line_offset = self.line_filter.filter(
                                            'test.js', False, test_content
                                        )

        self.assertEqual(line_offset, 8,
            "Should skip multiline comment, blank line and imports")
        self.assertIn(b"class App", filtered_content,
            "Should start with class definition")
        self.assertNotIn(b"Copyright", filtered_content,
            "License should be filtered")
        self.assertNotIn(b"import React", filtered_content,
            "Imports should be filtered")

    def test_go_import_block(self):
        """Test Go file with import block"""
        test_content = b"""// Copyright 2024
// Licensed under MIT

package main

import (
    "fmt"
    "os"
    _ "github.com/lib/pq"
)

func main() {
    fmt.Println("Hello")
}
"""
        filtered_content, line_offset = self.line_filter.filter(
                                            'test.go', False, test_content
                                        )

        self.assertEqual(line_offset, 11,
            "Should skip license, package, import block and blank line")
        self.assertIn(b"func main()", filtered_content,
            "Should start with func definition")
        self.assertNotIn(b"Copyright", filtered_content,
            "License should be filtered")
        self.assertNotIn(b"import (", filtered_content,
            "Import block should be filtered")

    def test_cpp_include_and_header_guards(self):
        """Test C++ file with includes and header guards"""
        test_content = b"""/*
 * Copyright (c) 2024
 * Licensed under MIT License
 */

#ifndef MY_HEADER_H
#define MY_HEADER_H

#include <iostream>
#include <vector>

class MyClass {
public:
    void doSomething();
};

#endif
"""
        filtered_content, line_offset = self.line_filter.filter(
                                            'test.cpp', False, test_content
                                        )

        self.assertGreater(line_offset, 0, "Should skip some header lines")
        self.assertIn(b"class MyClass", filtered_content,
            "Should include class definition")
        self.assertNotIn(b"Copyright", filtered_content,
            "License should be filtered")

    def test_java_package_and_imports(self):
        """Test Java file with package and imports"""
        test_content = b"""/**
 * Copyright 2024
 * Licensed under Apache License 2.0
 */

package com.example.myapp;

import java.util.List;
import java.util.ArrayList;
import javax.annotation.Nullable;

public class MyClass {
    private List<String> items;

    public MyClass() {
        items = new ArrayList<>();
    }
}
"""
        filtered_content, line_offset = self.line_filter.filter(
                                            'test.java', False, test_content
                                        )

        self.assertGreater(line_offset, 0,
            "Should skip license, package and imports")
        self.assertIn(b"public class MyClass", filtered_content,
            "Should start with class definition")
        self.assertNotIn(b"import java", filtered_content,
            "Imports should be filtered")

    def test_typescript_with_type_imports(self):
        """Test TypeScript file with type imports"""
        test_content = b"""// Copyright 2024
// MIT License

import type { User } from './types';
import { Component } from 'react';
import React from 'react';

interface Props {
    user: User;
}

class UserComponent extends Component<Props> {
    render() {
        return <div>{this.props.user.name}</div>;
    }
}
"""
        filtered_content, line_offset = self.line_filter.filter(
                                            'test.ts', False, test_content
                                        )

        self.assertGreater(line_offset, 0, "Should skip license and imports")
        self.assertIn(b"interface Props", filtered_content,
            "Should start with interface definition")
        self.assertNotIn(b"import type", filtered_content,
            "Type imports should be filtered")

    def test_rust_use_statements(self):
        """Test Rust file with use statements"""
        test_content = b"""// Copyright 2024
// Licensed under MIT

use std::io;
use std::fs::File;
extern crate serde;

fn main() {
    println!("Hello, world!");
}

fn another_function() {
    // Implementation
}
"""
        filtered_content, line_offset = self.line_filter.filter(
                                            'test.rs', False, test_content
                                        )

        self.assertGreater(line_offset, 0,
            "Should skip license and use statements")
        self.assertIn(b"fn main()", filtered_content,
            "Should start with main function")
        self.assertNotIn(b"use std", filtered_content,
            "Use statements should be filtered")

    def test_python_with_shebang(self):
        """Test Python file with shebang"""
        test_content = b"""#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2024

import sys

def main():
    pass
"""
        filtered_content, line_offset = self.line_filter.filter(
            'test.py', False, test_content
        )

        self.assertGreater(line_offset, 0,
            "Should skip shebang, encoding, license and imports")
        self.assertIn(b"def main()", filtered_content,
            "Should start with function definition")
        self.assertNotIn(b"#!/usr/bin", filtered_content,
            "Shebang should be filtered")

    def test_binary_file_no_filtering(self):
        """Test that binary files are not filtered"""
        test_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"

        filtered_content, line_offset = self.line_filter.filter(
                                            'test.png', True, test_content
                                        )

        self.assertEqual(line_offset, 0, "Binary files should not be filtered")
        self.assertEqual(filtered_content, test_content,
            "Binary content should remain unchanged")

    def test_unsupported_language_no_filtering(self):
        """Test that unsupported file extensions return original content"""
        test_content = b"""Some random content
in an unknown format
that should not be filtered
"""

        filtered_content, line_offset = self.line_filter.filter(
                                            'test.unknown', False, test_content
                                        )

        self.assertEqual(line_offset, 0,
            "Unsupported files should not be filtered")
        self.assertEqual(filtered_content, test_content,
            "Content should remain unchanged")

    def test_file_with_only_license_and_comments(self):
        """Test file that contains only license and comments (no implementation)"""
        test_content = b"""# Copyright 2024
# MIT License
#
# This is just a license file
# with no actual code
"""

        filtered_content, line_offset = self.line_filter.filter(
            'test.py', False, test_content
        )

        self.assertEqual(filtered_content, b'',
            "Should return empty content when no implementation found")
        self.assertEqual(line_offset, 0,
            "Line offset should be 0 when no implementation found")

    def test_max_lines_limit(self):
        """Test that max_lines parameter limits output"""
        test_content = b"""# Copyright 2024

import os

def func1():
    pass

def func2():
    pass

def func3():
    pass

def func4():
    pass
"""
        line_filter_limited = LineFilter(max_lines=5, debug=False, quiet=True)
        filtered_content, line_offset = line_filter_limited.filter('test.py', False, test_content)

        # Count lines in filtered content
        filtered_lines = filtered_content.split(b'\n')
        self.assertLessEqual(len(filtered_lines), 6,
            "Should respect max_lines limit (5 lines + potential empty)")

    def test_php_namespace_and_use(self):
        """Test PHP file with namespace and use statements"""
        test_content = b"""/**
 * Copyright 2024
 * MIT License
 */

namespace App\\Controllers;

use App\\Models\\User;
use Illuminate\\Http\\Request;

class UserController {
    public function index() {
        return User::all();
    }
}
"""
        filtered_content, line_offset = self.line_filter.filter(
            'test.php', False, test_content
        )

        msg = "Should skip license, namespace and use statements"
        self.assertGreater(line_offset, 0, msg)
        self.assertIn(
            b"class UserController",
            filtered_content,
            "Should start with class definition"
        )
        self.assertNotIn(
            b"use App",
            filtered_content,
            "Use statements should be filtered"
        )

    def test_ruby_require_statements(self):
        """Test Ruby file with require statements"""
        test_content = b"""# Copyright 2024
# MIT License

require 'json'
require_relative 'helper'

class MyClass
  def initialize
    @data = []
  end
end
"""
        filtered_content, line_offset = self.line_filter.filter(
                                            'test.rb', False, test_content
                                        )

        self.assertGreater(line_offset, 0,
            "Should skip license and require statements")
        self.assertIn(b"class MyClass", filtered_content,
            "Should start with class definition")
        self.assertNotIn(b"require", filtered_content,
            "Require statements should be filtered")

    def test_scala_package_and_imports(self):
        """Test Scala file with package and imports"""
        test_content = b"""/*
 * Copyright 2024
 * Apache License 2.0
 */

package com.example

import scala.collection.mutable.ArrayBuffer
import java.util.Date

object Main {
  def main(args: Array[String]): Unit = {
    println("Hello")
  }
}
"""
        filtered_content, line_offset = self.line_filter.filter(
                                            'test.scala', False, test_content
                                        )

        self.assertGreater(line_offset, 0,
            "Should skip license, package and imports")
        self.assertIn(b"object Main", filtered_content,
            "Should start with object definition")
        self.assertNotIn(b"import scala", filtered_content,
            "Imports should be filtered")

    def test_detect_language(self):
        """Test language detection from file extensions"""
        self.assertEqual(self.line_filter.detect_language('test.py'), 'python')
        self.assertEqual(self.line_filter.detect_language('test.js'), 'javascript')
        self.assertEqual(self.line_filter.detect_language('test.ts'), 'typescript')
        self.assertEqual(self.line_filter.detect_language('test.go'), 'go')
        self.assertEqual(self.line_filter.detect_language('test.rs'), 'rust')
        self.assertEqual(self.line_filter.detect_language('test.java'), 'java')
        self.assertEqual(self.line_filter.detect_language('test.cpp'), 'cpp')
        self.assertEqual(self.line_filter.detect_language('test.c'), 'cpp')
        self.assertEqual(self.line_filter.detect_language('test.rb'), 'ruby')
        self.assertEqual(self.line_filter.detect_language('test.php'), 'php')
        self.assertEqual(self.line_filter.detect_language('test.unknown'), None)

    def test_empty_file(self):
        """Test handling of empty file"""
        test_content = b""

        filtered_content, line_offset = self.line_filter.filter(
            'test.py', False, test_content
        )

        self.assertEqual(line_offset, 0, "Empty file should have 0 offset")
        self.assertEqual(filtered_content, b'',
            "Empty file should return empty content")

    def test_utf8_decode_error_handling(self):
        """Test handling of files that cannot be decoded as UTF-8"""
        # Create content with invalid UTF-8 sequences
        test_content = b"\xff\xfe" + b"some content"

        filtered_content, line_offset = self.line_filter.filter(
            'test.py', False, test_content
        )

        # Should return original content when UTF-8 decode fails
        self.assertEqual(line_offset, 0,
            "Should return 0 offset on decode error")
        self.assertEqual(filtered_content, test_content,
            "Should return original content on decode error")


if __name__ == '__main__':
    unittest.main()
