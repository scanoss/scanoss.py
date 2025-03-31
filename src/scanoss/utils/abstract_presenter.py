from abc import ABC, abstractmethod

from scanoss.scanossbase import ScanossBase


class AbstractPresenter(ABC):
    """
    Abstract presenter class for presenting output in a given format.
    Subclasses must implement the _format_json_output and _format_plain_output methods.
    """

    def __init__(
        self,
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
        output_file: str = None,
        output_format: str = None,
    ):
        """
        Initialize the presenter with the given output file and format.
        """
        self.AVAILABLE_OUTPUT_FORMATS = ['json', 'plain', 'cyclonedx', 'spdxlite', 'csv', 'raw']
        self.base = ScanossBase(debug=debug, trace=trace, quiet=quiet)
        self.output_file = output_file
        self.output_format = output_format

    def present(self, output_format: str = None, output_file: str = None):
        """
        Present the formatted output to a file if provided; otherwise, print to stdout.
        """
        file_path = output_file or self.output_file
        fmt = output_format or self.output_format

        if fmt and fmt not in self.AVAILABLE_OUTPUT_FORMATS:
            raise ValueError(
                f"ERROR: Invalid output format '{fmt}'. Valid values are: {', '.join(self.AVAILABLE_OUTPUT_FORMATS)}"
            )

        if fmt == 'json':
            content = self._format_json_output()
        elif fmt == 'plain':
            content = self._format_plain_output()
        elif fmt == 'cyclonedx':
            content = self._format_cyclonedx_output()
        elif fmt == 'spdxlite':
            content = self._format_spdxlite_output()
        elif fmt == 'csv':
            content = self._format_csv_output()
        elif fmt == 'raw':
            content = self._format_raw_output()
        else:
            content = self._format_plain_output()

        self._present_output(content, file_path)

    def _present_output(self, content: str, file_path: str = None):
        """
        If a file path is provided, write to that file; otherwise, print the content to stdout.
        """
        self.base.print_to_file_or_stdout(content, file_path)

    @abstractmethod
    def _format_cyclonedx_output(self) -> str:
        """
        Return a CycloneDX string representation of the data.
        """
        pass

    @abstractmethod
    def _format_spdxlite_output(self) -> str:
        """
        Return a SPDX-Lite string representation of the data.
        """
        pass

    @abstractmethod
    def _format_csv_output(self) -> str:
        """
        Return a CSV string representation of the data.
        """
        pass

    @abstractmethod
    def _format_json_output(self) -> str:
        """
        Return a JSON string representation of the data.
        """
        pass

    @abstractmethod
    def _format_plain_output(self) -> str:
        """
        Return a plain text string representation of the data.
        """
        pass

    @abstractmethod
    def _format_raw_output(self) -> str:
        """
        Return a raw string representation of the data.
        """
        pass
