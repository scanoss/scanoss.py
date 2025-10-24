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

def generate_table(headers, rows, centered_columns=None):
    """
    Generate a Markdown table.

    :param headers: List of headers for the table.
    :param rows: List of rows for the table.
    :param centered_columns: List of column indices to be centered.
    :return: A string representing the Markdown table.
    """
    col_sep = ' | '
    centered_column_set = set(centered_columns or [])
    if headers is None:
        return None

    # Decide which separator to use
    def create_separator(index):
        if centered_columns is None:
            return '-'
        return ':-:' if index in centered_column_set else '-'

    # Build the row separator
    row_separator = col_sep + col_sep.join(create_separator(index) for index, _ in enumerate(headers)) + col_sep
    # build table rows
    table_rows = [col_sep + col_sep.join(headers) + col_sep, row_separator]
    table_rows.extend(col_sep + col_sep.join(row) + col_sep for row in rows)
    return '\n'.join(table_rows)

def generate_jira_table(headers, rows, centered_columns=None):
    col_sep = '*|*'
    if headers is None:
        return None

    table_header = '|*' + col_sep.join(headers) + '*|\n'
    table = table_header
    for row in rows:
        if len(headers) == len(row):
            table += '|' + '|'.join(row) + '|\n'

    return table