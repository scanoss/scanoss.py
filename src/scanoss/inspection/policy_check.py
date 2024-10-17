import json
import os.path
from abc import abstractmethod
from enum import Enum
from scanoss.inspection.utils.result_utils import get_components
from scanoss.results import Results
from scanoss.scanossbase import ScanossBase

class PolicyStatus(Enum):
    SUCCESS = 0
    FAIL = 1
    ERROR = 2

class PolicyCheck(ScanossBase):

    VALID_FORMATS = {'md', 'json'}

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format: str = None, status: str = None, output: str = None, name: str = None):
        super().__init__(debug, trace, quiet)
        self.filepath = filepath
        self.name = name
        self.output = output
        self.format =format
        self.status = status


    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def _get_formatter(self) -> str:
        pass

    def _init(self) :
        if self.status is not None:
            if not self._is_valid_path(self.status):
               return None
        if self.output is not None:
            if not self._is_valid_path(self.output):
                return None

        return True

    def _debug(self):
        self.print_debug(f"Policy: {self.name}")
        self.print_debug(f"Format: {self.format}")
        self.print_debug(f"Status: {self.status}")
        self.print_debug(f"Output: {self.output}")
        self.print_debug(f"Input: {self.filepath}")

    def _is_valid_format(self):
        """
          Validate if the format specified is supported.

          This method checks if the format stored in self.format is one of the
          valid formats defined in self.VALID_FORMATS.

          Returns:
              bool: True if the format is valid, False otherwise.
        """
        if self.format not in self.VALID_FORMATS:
            valid_formats_str = ", ".join(self.VALID_FORMATS)
            self.print_stderr(f"Invalid format '{self.format}'. Valid formats are: {valid_formats_str}")
            return False
        return True

    def _is_valid_path(self, file_path: str) -> bool:
        """
        Check if the directory path for a given file path exists.

        This method extracts the directory path from the given file path
        and checks if it exists.

        Args:
            file_path (str): The full path to the file.

        Returns:
            bool: True if the directory exists, False otherwise.
        """
        dir_path = os.path.dirname(file_path)
        # Check if the directory exists, if not, create it
        if not os.path.exists(dir_path):
            self.print_stderr(f"ERROR: Dir '{dir_path}' does not exist.")
            return False
        return True

    def read_input_file(self):
        """Load the result.json file

          Args:
              file (str): Path to the JSON file

          Returns:
              Dict[str, Any]: The parsed JSON data
          """
        if not os.path.exists(self.filepath):
            self.print_stderr(f"ERROR: The file '{self.filepath}' does not exist.")
            return None

        with open(self.filepath, "r") as jsonfile:
            try:
                return json.load(jsonfile)
            except Exception as e:
                self.print_stderr(f"ERROR: Problem parsing input JSON: {e}")
        return None

    def _get_components(self):
        if self.filepath is None:
            self.print_stderr(f'ERROR: Missing input file path')
            return None
        results = self.read_input_file()
        if results is None:
            return None
        components = get_components(results)
        return components

