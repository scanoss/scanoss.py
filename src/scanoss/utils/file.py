"""
SPDX-License-Identifier: MIT

  Copyright (c) 2024, SCANOSS

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
from dataclasses import dataclass
from typing import Optional

JSON_ERROR_PARSE = 1
JSON_ERROR_FILE_NOT_FOUND = 2
JSON_ERROR_FILE_EMPTY = 3
JSON_ERROR_FILE_SIZE = 4


@dataclass
class JsonValidation:
    is_valid: bool
    data: Optional[dict] = None
    error: Optional[str] = None
    error_code: Optional[int] = None


def validate_json_file(json_file_path: str) -> JsonValidation:
    """
    Validate if the specified file is indeed a valid JSON file

    Args:
        json_file_path (str): The JSON file to validate

    Returns:
        JsonValidation: A JsonValidation object containing a boolean indicating if the file is valid, the data, error, and error code
    """  # noqa: E501
    if not json_file_path:
        return JsonValidation(is_valid=False, error='No JSON file specified')
    if not os.path.isfile(json_file_path):
        return JsonValidation(
            is_valid=False,
            error=f'File not found: {json_file_path}',
            error_code=JSON_ERROR_FILE_NOT_FOUND,
        )
    try:
        if os.stat(json_file_path).st_size == 0:
            return JsonValidation(
                is_valid=False,
                error=f'File is empty: {json_file_path}',
                error_code=JSON_ERROR_FILE_EMPTY,
            )
    except OSError as e:
        return JsonValidation(
            is_valid=False,
            error=f'Problem checking file size: {json_file_path}: {e}',
            error_code=JSON_ERROR_FILE_SIZE,
        )
    try:
        with open(json_file_path) as f:
            data = json.load(f)
            return JsonValidation(is_valid=True, data=data)
    except json.JSONDecodeError as e:
        return JsonValidation(
            is_valid=False,
            error=f'Problem parsing JSON file: "{json_file_path}": {e}',
            error_code=JSON_ERROR_PARSE,
        )
