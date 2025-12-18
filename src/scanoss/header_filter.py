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
    """
    Regex patterns for different programming languages.

    This class provides a collection of regex patterns for identifying different
    programming constructs, handling imports, comments, and license statements
    across various programming languages. The main purpose of this class is to
    assist in parsing or analysing code written in different languages efficiently.

    :ivar COMMENT_PATTERNS: A dictionary containing regex patterns to identify
        single-line and multi-line comments in various programming languages.
    :ivar IMPORT_PATTERNS: A dictionary mapping programming languages to their
        respective regex patterns for identifying import statements or package
        includes it.
    :ivar LICENSE_KEYWORDS: A list of keywords commonly found in license texts
        or statements, often used to detect the presence of licensing information.
    """
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
# Map of file extensions to programming languages
EXT_MAP = {
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


def is_blank_line(stripped_line: str) -> bool:
    """
    Check if a line is blank.

    This method determines whether a given string `line` is blank by checking
    if it consists entirely of whitespace or is empty.

    :param stripped_line: The string to be evaluated.
    :return: True if the string is blank, otherwise False.
    """
    return len(stripped_line) == 0


def is_shebang(stripped_line: str) -> bool:
    """
    Check if the given line is a shebang line.

    This function determines if the provided string is a shebang line,
    which indicates the path to the interpreter that should execute the
    script.

    :param stripped_line: The string to check if it's a shebang line.
    :return: True if the given line starts with '#!', otherwise False.
    """
    return stripped_line.startswith('#!')


class HeaderFilter(ScanossBase):
    """
    Source code file analyser that filters headers, comments, and imports.

    This class processes code files and returns only the real
    implementation content, omitting licenses, documentation comments,
    and imports.
    """

    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        skip_limit: Optional[int] = None
    ):
        """
        Initialise HeaderFilter
        Parameters
        ----------
            skip_limit: int
                Maximum number of lines to skip when analysing a file.
                If set, then stop stripping data after this number of lines.
                (None/0 = unlimited by default)
        """
        super().__init__(debug, trace, quiet)
        self.patterns = LanguagePatterns()
        self.max_lines = skip_limit

    def filter(self, file: str, decoded_contents: str) -> int:
        """
        Main method that filters file content
        Parameters
        ----------
            :param file: File path (used to detect extension)
            :param decoded_contents: File contents in utf-8 encoding
        Return
        ------
            - line_offset: Number of lines skipped from the beginning
              (0 if no filtering)
        """
        if not decoded_contents or not file:
            self.print_msg(f'No file or contents provided, skipping line filter for: {file}')
            return 0
        self.print_debug(f'HeaderFilter processing file: {file}')
        # Detect language
        language = self.detect_language(file)
        # If language is not supported, return original content
        if not language:
            self.print_debug(f'Skipping line filter for unsupported language: {file}')
            return 0
        lines = decoded_contents.splitlines(keepends=True)
        num_lines = len(lines)
        if num_lines == 0:
            self.print_msg(f'No lines in file: {file}')
            return 0
        self.print_debug(f'Analysing {num_lines} lines for file: {file}')

        # Find the first implementation line (optimised - stops at first match)
        implementation_start = self.find_first_implementation_line(lines, language)
        # If no implementation, return empty
        if implementation_start is None:
            self.print_debug(f'No implementation found in file: {file}')
            return 0
        # Calculate how many lines were filtered out (line_offset)
        line_offset = implementation_start - 1
        # Apply max_lines limit if configured
        if self.max_lines is not None and 0 < self.max_lines < line_offset:
            self.print_trace(
                f'Line offset {line_offset} exceeds max_lines {self.max_lines}, '
                f'capping at {self.max_lines} for: {file}'
            )
            line_offset = self.max_lines

        if line_offset > 0:
            self.print_debug(f'Filtered out {line_offset} lines from beginning of {file} (language: {language})')
        return line_offset

    def detect_language(self, file_path: str) -> Optional[str]:
        """
        Detects the programming language based on the provided file extension.

        This function uses a predefined mapping between file extensions and programming
        languages to determine the language associated with the file. If the file extension
        is found in the mapping, the corresponding language is returned. Otherwise, it
        returns None.

        :param file_path: Path to the file whose programming language needs to be detected.
        :return: The programming language corresponding to the file extension if mapped,
                 otherwise None.
        """
        path = Path(file_path)
        extension = path.suffix.lower()
        if extension:
            detected_language = EXT_MAP.get(extension)
            if detected_language:
                self.print_debug(f'Detected language "{detected_language}" for extension "{extension}"')
            else:
                self.print_debug(f'No language mapping found for extension "{extension}"')
        else:
            self.print_debug(f'No file extension found, skipping language detection for: {file_path}')
            detected_language = None
        return detected_language

    def is_license_header(self, line: str) -> bool:
        """
        Check if the line appears to be part of a license header.

        This method evaluates a given line of text to determine whether it
        contains keywords that suggest it is part of a license header. It
        performs a case-insensitive check against a predefined set of license
        keywords.

        :param line: The line of text to check.
        :return: True if the line contains keywords indicating it is part of a
            license header; False otherwise.
        """
        line_lower = line.lower()
        return any(keyword in line_lower for keyword in self.patterns.LICENSE_KEYWORDS)

    def get_comment_style(self, language: str) -> str:
        """
        Return the comment style associated with a given programming language.

        This method determines the appropriate comment style to use based on the
        specified programming language. Supported languages include those with C-style
        comments, Python-style comments, and Lua-style comments. If the language does
        not match any of the explicitly defined groups, a default of `c_style` is
        returned.

        :param language: The name of the programming language for which the comment
            style needs to be determined.
        :return: The comment style for the provided programming language. Possible
            values are 'c_style', 'python_style', or 'lua_style'.
        """
        if language:
            if language in ['cpp', 'java', 'kotlin', 'scala', 'javascript', 'typescript',
                            'go', 'rust', 'csharp', 'php', 'swift', 'dart']:
                return 'c_style'
            if language in ['python', 'ruby', 'perl', 'r']:
                return 'python_style'
            if language in ['lua', 'haskell']:
                return 'lua_style'
        self.print_debug(f'No comment style defined for language "{language}", using default: "c_style"')
        return 'c_style'  # Default

    def is_comment(self, line: str, in_multiline: bool, patterns: dict) -> Tuple[bool, bool]:  # noqa: PLR0911
        """
        Check if a line is a comment

        :param patterns: comment patterns
        :param line: Line to check
        :param in_multiline: Whether we're currently in a multiline comment
        :return: Tuple of (is_comment, still_in_multiline)
        """
        if not patterns:
            self.print_msg('No comment patterns defined, skipping comment check')
            return False, in_multiline
        # If we're in a multiline comment
        if in_multiline:
            # Check if the comment ends
            if 'multi_end' in patterns and re.search(patterns['multi_end'], line):
                return True, False
            if 'doc_string_end' in patterns and re.search(patterns['doc_string_end'], line):
                return True, False
            return True, True
        # Single-line comment
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
            if count == 1:  # Start of a multiline docstring
                return True, True
        # Default response: not a comment
        return False, in_multiline

    def is_import(self, line: str, patterns: dict) -> bool:
        """
        Check if a line of code is an import or include statement for a given programming language.

        This function determines whether a specific line of code matches any
        import/include patterns defined for the provided programming language.
        It relies on predefined regular expression patterns.

        :param patterns: import patterns for the given language.
        :param line: A single line of code to check.
        :return: True if the line matches any import/include pattern for the given language,
            otherwise False.
        """
        if not patterns:
            self.print_debug('No import patterns defined, skipping import check')
        return any(re.match(pattern, line) for pattern in patterns)

    def find_first_implementation_line(self, lines: list[str], language: str) -> Optional[int]:  # noqa: PLR0912
        """
        Find the line number where the implementation begins (optimised version).
        Returns as soon as the first implementation line is found.

        :param lines: List of code lines
        :param language: Programming language
        :return: Line number (1-indexed) where implementation starts, or None if not found
        """
        if not lines or not language:
            self.print_debug('No lines or language provided, skipping implementation line detection')
            return None
        in_multiline_comment = False
        in_license_section = False
        in_import_block = False  # To handle import blocks in Go
        consecutive_imports_count = 0
        # Get comment & import patterns for the language
        comment_patterns = self.patterns.COMMENT_PATTERNS[self.get_comment_style(language)]
        import_patterns = self.patterns.IMPORT_PATTERNS[language]
        # Iterate through lines trying to find the first implementation line
        for i, line in enumerate(lines):
            line_number = i + 1
            stripped = line.strip()
            # Shebang (only first line) or blank line
            if (i == 0 and is_shebang(stripped)) or is_blank_line(stripped):
                continue
            # Check if it's a comment
            is_a_comment, in_multiline_comment = self.is_comment(line, in_multiline_comment, comment_patterns)
            if is_a_comment:
                # Check if it's part of the license header
                if self.is_license_header(line):
                    if not in_license_section:
                        self.print_trace(f'Line {line_number}: Detected license header section')
                    in_license_section = True
                # If still in the license section (first lines)
                elif in_license_section and line_number < LICENSE_HEADER_MAX_LINES:
                    pass  # Still in the license section. Keep looking.
                else:
                    if in_license_section:
                        self.print_trace(f'Line {line_number}: End of license header section')
                    in_license_section = False
                continue
            # If not a comment but we find a non-empty line, end license section
            if not is_a_comment:
                in_license_section = False
            # Handle import blocks in Go
            if language == 'go':
                if stripped.startswith('import ('):
                    self.print_trace(f'Line {line_number}: Detected Go import block start')
                    in_import_block = True
                    continue
                if in_import_block:
                    if stripped == ')':
                        self.print_trace(f'Line {line_number}: Detected Go import block end')
                        in_import_block = False
                        continue
                    if (stripped.startswith('"') or stripped.startswith('_') or
                            re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s+"', stripped)):
                        # It's part of the import block
                        continue
            # Check if it's an import
            if self.is_import(line, import_patterns):
                if consecutive_imports_count == 0:
                    self.print_trace(f'Line {line_number}: Detected import section')
                consecutive_imports_count += 1
                continue
            # If we get here, it's implementation code - return immediately!
            self.print_trace(f'Line {line_number}: First implementation line detected')
            return line_number
        # End for loop?
        return None
#
# End of HeaderFilter Class
#