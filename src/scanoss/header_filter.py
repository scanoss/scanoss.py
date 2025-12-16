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

  Line Filter Module - Identifies where real source code implementation begins.

  This module analyzes source code files and determines which lines are:
  - License headers
  - Documentation comments
  - Imports/includes
  - Blank lines

  And returns the content from where the real implementation begins.
"""

import re
from pathlib import Path
from typing import Optional, Tuple

from .scanossbase import ScanossBase


class LanguagePatterns:
    """Regex patterns for different programming languages"""

    # Comment patterns (single-line and multi-line start/end)
    COMMENT_PATTERNS = {
        # C-style languages: C, C++, Java, JavaScript, TypeScript, Go,
        # Rust, C#, PHP, Kotlin, Scala, Dart, Objective-C
        'c_style': {
            'single_line': r'^\s*//.*$',
            'multi_start': r'^\s*/\*',
            'multi_end': r'\*/\s*$',
            'multi_single': r'^\s*/\*.*\*/\s*$',
        },
        # Python, shell scripts, Ruby, Perl, R, Julia, YAML
        'python_style': {
            'single_line': r'^\s*#.*$',
            'doc_string_start': r'^\s*"""',
            'doc_string_end': r'"""\s*$',
        },
        # Lua, SQL, Haskell
        'lua_style': {
            'single_line': r'^\s*--.*$',
            'multi_start': r'^\s*--\[\[',
            'multi_end': r'\]\]\s*$',
        },
        # HTML, XML
        'html_style': {
            'multi_start': r'^\s*<!--',
            'multi_end': r'-->\s*$',
            'multi_single': r'^\s*<!--.*-->\s*$',
        },
    }

    # Import/include patterns by language
    IMPORT_PATTERNS = {
        'python': [
            r'^\s*import\s+',
            r'^\s*from\s+.*\s+import\s+',
        ],
        'javascript': [
            r'^\s*import\s+.*\s+from\s+',
            r'^\s*import\s+["\']',
            r'^\s*import\s+type\s+',
            r'^\s*export\s+\*\s+from\s+',
            r'^\s*export\s+\{.*\}\s+from\s+',
            r'^\s*const\s+.*\s*=\s*require\(',
            r'^\s*var\s+.*\s*=\s*require\(',
            r'^\s*let\s+.*\s*=\s*require\(',
        ],
        'typescript': [
            r'^\s*import\s+',
            r'^\s*export\s+.*\s+from\s+',
            r'^\s*import\s+type\s+',
            r'^\s*import\s+\{.*\}\s+from\s+',
        ],
        'java': [
            r'^\s*import\s+',
            r'^\s*package\s+',
        ],
        'kotlin': [
            r'^\s*import\s+',
            r'^\s*package\s+',
        ],
        'scala': [
            r'^\s*import\s+',
            r'^\s*package\s+',
        ],
        'go': [
            r'^\s*import\s+\(',
            r'^\s*import\s+"',
            r'^\s*package\s+',
            r'^\s*"[^"]*"\s*$',  # Imports inside import () block
            # Imports with alias: name "package"
            r'^\s*[a-zA-Z_][a-zA-Z0-9_]*\s+"[^"]*"\s*$',
            r'^\s*_\s+"[^"]*"\s*$',  # _ "package" imports
        ],
        'rust': [
            r'^\s*use\s+',
            r'^\s*extern\s+crate\s+',
            r'^\s*mod\s+',
        ],
        'cpp': [
            r'^\s*#include\s+',
            r'^\s*#pragma\s+',
            r'^\s*#ifndef\s+.*_H.*',  # Header guards: #ifndef FOO_H
            r'^\s*#define\s+.*_H.*',  # Header guards: #define FOO_H
            # #endif at end of file (may have comment)
            r'^\s*#endif\s+(//.*)?\s*$',
        ],
        'csharp': [
            r'^\s*using\s+',
            r'^\s*namespace\s+',
        ],
        'php': [
            r'^\s*use\s+',
            r'^\s*require\s+',
            r'^\s*require_once\s+',
            r'^\s*include\s+',
            r'^\s*include_once\s+',
            r'^\s*namespace\s+',
        ],
        'swift': [
            r'^\s*import\s+',
        ],
        'ruby': [
            r'^\s*require\s+',
            r'^\s*require_relative\s+',
            r'^\s*load\s+',
        ],
        'perl': [
            r'^\s*use\s+',
            r'^\s*require\s+',
        ],
        'r': [
            r'^\s*library\(',
            r'^\s*require\(',
            r'^\s*source\(',
        ],
        'lua': [
            r'^\s*require\s+',
            r'^\s*local\s+.*\s*=\s*require\(',
        ],
        'dart': [
            r'^\s*import\s+',
            r'^\s*export\s+',
            r'^\s*part\s+',
        ],
        'haskell': [
            r'^\s*import\s+',
            r'^\s*module\s+',
        ],
        'elixir': [
            r'^\s*import\s+',
            r'^\s*alias\s+',
            r'^\s*require\s+',
            r'^\s*use\s+',
        ],
        'clojure': [
            r'^\s*\(\s*ns\s+',
            r'^\s*\(\s*require\s+',
            r'^\s*\(\s*import\s+',
        ],
    }

    # Keywords that indicate licenses
    LICENSE_KEYWORDS = [
        'copyright', 'license', 'licensed', 'all rights reserved',
        'permission', 'redistribution', 'warranty', 'liability',
        'apache', 'mit', 'gpl', 'bsd', 'mozilla', 'author:',
        'spdx-license', 'contributors', 'licensee'
    ]

COMPLETE_DOCSTRING_QUOTE_COUNT = 2
LICENSE_HEADER_MAX_LINES = 50


class HeaderFilter(ScanossBase):
    """
    Source code file analyzer that filters headers, comments and imports.

    This class processes code files and returns only the real
    implementation content, omitting licenses, documentation comments
    and imports.
    """

    def __init__(
        self,
        max_lines: Optional[int] = None,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False
    ):
        """
        Initialize HeaderFilter
        Parameters
        ----------
            max_lines: int
                Maximum line number to analyze. If implementation is found
                beyond this line, will cap at max_lines.
                (None = unlimited by default)
        """
        super().__init__(debug, trace, quiet)
        self.patterns = LanguagePatterns()
        self.max_lines = max_lines

    def filter(self, file: str, bin_file: bool, contents: bytes) -> int:
        """
        Main method that filters file content
        Parameters
        ----------
            :param file: File path (used to detect extension)
            :param bin_file: Indicates if the file is binary
            :param contents: File contents in bytes
        Return
        ------
            - line_offset: Number of lines skipped from the beginning
              (0 if no filtering)
        """
        self.print_debug(f'HeaderFilter processing file: {file}')

        # If binary file, return without processing
        if bin_file:
            self.print_debug(f'Skipping line filter for binary file: {file}')
            return 0

        # Detect language
        language = self.detect_language(file)

        # If language is not supported, return original content
        if not language:
            self.print_debug(f'Skipping line filter for unsupported language: {file}')
            return 0
        try:
            # Decode content to UTF-8
            text_content = contents.decode('utf-8')
        except UnicodeDecodeError:
            # If decoding fails, return original content
            self.print_debug(f'Skipping line filter due to UTF-8 decode error: {file}')
            return 0

        # Split into lines keeping line endings
        lines = text_content.splitlines(keepends=True)
        self.print_debug(f'Analyzing {len(lines)} lines for file: {file}')

        # Find first implementation line (optimized - stops at first match)
        implementation_start = self.find_first_implementation_line(lines, language)

        # If no implementation, return empty
        if implementation_start is None:
            self.print_debug(f'No implementation found in file: {file}')
            return 0

        # Calculate how many lines were filtered out (line_offset)
        line_offset = implementation_start - 1

        # Apply max_lines limit if configured
        if self.max_lines is not None and line_offset > self.max_lines:
            self.print_debug(
                f'Line offset {line_offset} exceeds max_lines {self.max_lines}, '
                f'capping at {self.max_lines} for: {file}'
            )
            line_offset = self.max_lines

        if line_offset > 0:
            self.print_debug(f'Filtered out {line_offset} lines from beginning of {file} (language: {language})')

        return line_offset

    def detect_language(self, file_path: str) -> Optional[str]:
        """Detect language based on file extension"""
        path = Path(file_path)
        extension = path.suffix.lower()

        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.mjs': 'javascript',
            '.cjs': 'javascript',
            '.ts': 'typescript',
            '.tsx': 'typescript',
            '.jsx': 'javascript',
            '.java': 'java',
            '.kt': 'kotlin',
            '.kts': 'kotlin',
            '.scala': 'scala',
            '.sc': 'scala',
            '.go': 'go',
            '.rs': 'rust',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.c': 'cpp',
            '.h': 'cpp',
            '.hpp': 'cpp',
            '.hxx': 'cpp',
            '.cs': 'csharp',
            '.php': 'php',
            '.swift': 'swift',
            '.rb': 'ruby',
            '.pl': 'perl',
            '.pm': 'perl',
            '.r': 'r',
            '.R': 'r',
            '.lua': 'lua',
            '.dart': 'dart',
            '.hs': 'haskell',
            '.ex': 'elixir',
            '.exs': 'elixir',
            '.clj': 'clojure',
            '.cljs': 'clojure',
            '.m': 'cpp',  # Objective-C
            '.mm': 'cpp',  # Objective-C++
            # Shell scripts share Python's # comment style, but lack dedicated
            # import patterns (source/. commands won't be filtered)
            '.sh': 'python',
            '.bash': 'python',
            '.zsh': 'python',
            '.fish': 'python',
        }

        detected_language = ext_map.get(extension)
        if detected_language:
            self.print_debug(f'Detected language "{detected_language}" for extension "{extension}"')
        else:
            self.print_debug(f'No language mapping found for extension "{extension}"')

        return detected_language

    def is_blank_line(self, line: str) -> bool:
        """Check if a line is blank"""
        return len(line.strip()) == 0

    def is_shebang(self, line: str) -> bool:
        """Check if it's a shebang line"""
        return line.strip().startswith('#!')

    def is_license_header(self, line: str) -> bool:
        """Check if the line appears to be part of a license header"""
        line_lower = line.lower()
        return any(keyword in line_lower for keyword in self.patterns.LICENSE_KEYWORDS)

    def get_comment_style(self, language: str) -> str:
        """Return comment style for a language"""
        if language in ['cpp', 'java', 'kotlin', 'scala', 'javascript', 'typescript',
                        'go', 'rust', 'csharp', 'php', 'swift', 'dart']:
            return 'c_style'
        if language in ['python', 'ruby', 'perl', 'r']:
            return 'python_style'
        if language in ['lua', 'haskell']:
            return 'lua_style'
        return 'c_style'  # Default

    def is_comment(self, line: str, language: str, in_multiline: bool) -> Tuple[bool, bool]:  # noqa: PLR0911
        """
        Check if a line is a comment

        :param line: Line to check
        :param language: Programming language
        :param in_multiline: Whether we're currently in a multiline comment
        :return: Tuple of (is_comment, still_in_multiline)
        """
        style = self.get_comment_style(language)
        patterns = self.patterns.COMMENT_PATTERNS[style]

        # If we're in a multiline comment
        if in_multiline:
            # Check if comment ends
            if 'multi_end' in patterns and re.search(patterns['multi_end'], line):
                return True, False
            if 'doc_string_end' in patterns and '"""' in line:
                return True, False
            return True, True

        # Single line comment
        if 'single_line' in patterns and re.match(patterns['single_line'], line):
            return True, False

        # Multiline comment complete in one line
        if 'multi_single' in patterns and re.match(patterns['multi_single'], line):
            return True, False

        # Start of multiline comment (C-style)
        if 'multi_start' in patterns and re.search(patterns['multi_start'], line):
            # If it also ends on the same line
            if 'multi_end' in patterns and re.search(patterns['multi_end'], line):
                return True, False
            return True, True

        # Start of docstring (Python)
        if 'doc_string_start' in patterns and '"""' in line:
            # Count how many quotes there are
            count = line.count('"""')
            if count == COMPLETE_DOCSTRING_QUOTE_COUNT:  # Complete docstring in one line
                return True, False
            if count == 1:  # Start of multiline docstring
                return True, True

        return False, in_multiline

    def is_import(self, line: str, language: str) -> bool:
        """Check if a line is an import/include"""
        if language not in self.patterns.IMPORT_PATTERNS:
            return False

        patterns = self.patterns.IMPORT_PATTERNS[language]
        return any(re.match(pattern, line) for pattern in patterns)

    def find_first_implementation_line(self, lines: list[str], language: str) -> Optional[int]:  # noqa: PLR0912
        """
        Find the line number where implementation begins (optimized version).
        Returns as soon as the first implementation line is found.

        :param lines: List of code lines
        :param language: Programming language
        :return: Line number (1-indexed) where implementation starts, or None if not found
        """
        in_multiline_comment = False
        in_license_section = False
        in_import_block = False  # To handle import blocks in Go
        consecutive_imports_count = 0

        for i, line in enumerate(lines):
            line_number = i + 1
            stripped = line.strip()

            # Shebang (only first line)
            if i == 0 and self.is_shebang(line):
                self.print_debug(f'Line {line_number}: Detected shebang')
                continue

            # Blank line
            if self.is_blank_line(line):
                # Blank lines don't break import sequences
                continue

            # Check if it's a comment
            is_comment, in_multiline_comment = self.is_comment(line, language, in_multiline_comment)

            if is_comment:
                # Check if it's part of license header
                if self.is_license_header(line):
                    if not in_license_section:
                        self.print_debug(f'Line {line_number}: Detected license header section')
                    in_license_section = True
                # If still in license section (first lines)
                elif in_license_section and line_number < LICENSE_HEADER_MAX_LINES:
                    pass  # Still in license section
                else:
                    if in_license_section:
                        self.print_debug(f'Line {line_number}: End of license header section')
                    in_license_section = False
                continue

            # If not a comment but we find a non-empty line, end license section
            if not is_comment:
                in_license_section = False

            # Handle import blocks in Go
            if language == 'go':
                if stripped.startswith('import ('):
                    self.print_debug(f'Line {line_number}: Detected Go import block start')
                    in_import_block = True
                    continue
                if in_import_block:
                    if stripped == ')':
                        self.print_debug(f'Line {line_number}: Detected Go import block end')
                        in_import_block = False
                        continue
                    if (stripped.startswith('"') or stripped.startswith('_') or
                            re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s+"', stripped)):
                        # It's part of the import block
                        continue

            # Check if it's an import
            if self.is_import(line, language):
                if consecutive_imports_count == 0:
                    self.print_debug(f'Line {line_number}: Detected import section')
                consecutive_imports_count += 1
                continue

            # If we get here, it's implementation code - return immediately!
            self.print_debug(f'Line {line_number}: First implementation line detected')
            return line_number

        return None


#
# End of HeaderFilter Class
#
