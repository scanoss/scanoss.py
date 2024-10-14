from abc import abstractmethod

from scanoss.results import Results
from scanoss.scanossbase import ScanossBase


class PolicyCheck(ScanossBase):

    result: Results


    def __init__(self, debug: bool = False, trace: bool = False, quiet: bool = False, filepath: str = None, format: str = None, status: str = None):
        super().__init__(debug, trace, quiet)
        self.file_path = filepath
        self.format = format
        self.status = status
        self.result = Results(debug, trace, quiet, filepath)

    @abstractmethod
    def run(self):
        pass