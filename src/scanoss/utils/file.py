import json
import os
import sys


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


def validate_json_file(json_file_path: str) -> None:
    """Validate if the specified file is indeed a valid JSON file

    Args:
        json_file_path (str): The JSON file to validate

    Raises:
        ValueError: If the JSON file is not valid
    """
    if not json_file_path:
        raise ValueError('No JSON file provided to parse.')
    if not os.path.isfile(json_file_path):
        raise ValueError(f'JSON file does not exist or is not a file: {json_file_path}')
    try:
        with open(json_file_path) as f:
            json.load(f)
    except Exception as e:
        raise ValueError(f'Problem parsing JSON file "{json_file_path}": {e}') from e
