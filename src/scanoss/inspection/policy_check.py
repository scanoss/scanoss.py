from abc import abstractmethod
from typing import Dict, Any
from scanoss.inspection.utils.result_utils import get_components
from scanoss.results import Results
from scanoss.scanossbase import ScanossBase


class PolicyCheck(ScanossBase):

    result: Results

    def __init__(self, debug: bool = False, trace: bool = True, quiet: bool = False, filepath: str = None,
                 format: str = None, status: str = None, output: str = None, name: str = None):
        super().__init__(debug, trace, quiet)
        self.result = Results(debug, trace, quiet, filepath)
        self.filepath = filepath
        self.name = name
        self.output = output
        self.format =format
        self.status = status

    @abstractmethod
    def run(self) -> Dict[str, Any]:
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


    def _get_components(self):
        results = self.result.load_file(self.filepath)
        components = get_components(results)
        return components


    def _save_to_file(self, input: str, filename: str = None):
        if filename:
            self.print_to_file_or_stdout(input, filename)

