import json
import os
import sys
from typing import Tuple


def print_stderr(*args, **kwargs):
    """
    Print the given message to STDERR
    """
    print(*args, file=sys.stderr, **kwargs)


def is_valid_file(file_path: str) -> bool:
    """Check if the specified file exists and is a file

    Args:
        file_path (str): The file path

    Returns:
        bool: True if valid, False otherwise
    """
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        print_stderr(f'Specified file does not exist or is not a file: {file_path}')
        return False
    return True


def validate_json_file(json_file_path: str) -> Tuple[bool, str]:
    """Validate if the specified file is indeed a valid JSON file

    Args:
        json_file_path (str): The JSON file to validate

    Returns:
        Tuple[bool, str]: A tuple containing a boolean indicating if the file is valid and a message
    """
    if not json_file_path:
        return False, 'No JSON file provided to parse.'
    if not os.path.isfile(json_file_path):
        return False, f'JSON file does not exist or is not a file: {json_file_path}'
    try:
        with open(json_file_path) as f:
            json.load(f)
            return True, ''
    except Exception as e:
        return False, f'Problem parsing JSON file "{json_file_path}": {e}'
