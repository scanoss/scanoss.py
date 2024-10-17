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
    def run(self) :
        pass

    @abstractmethod
    def _get_formatter(self) -> str:
        pass

    def _debug(self):
        self.print_debug(f"Policy: {self.name}")
        self.print_debug(f"Format: {self.format}")
        self.print_debug(f"Status: {self.status}")
        self.print_debug(f"Output: {self.output}")
        self.print_debug(f"Input: {self.filepath}")

    def _is_valid_format(self):
        if self.format not in self.VALID_FORMATS:
            valid_formats_str = ", ".join(self.VALID_FORMATS)
            self.print_stderr(f"Invalid format '{self.format}'. Valid formats are: {valid_formats_str}")
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

    def _save_to_file(self, input: str, filename: str = None):
        if filename:
            self.print_to_file_or_stdout(input, filename)

