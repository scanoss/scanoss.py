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
import subprocess
from dataclasses import dataclass
from typing import List, Optional, TypedDict

from scanoss.scanossbase import ScanossBase
from scanoss.utils.abstract_presenter import AbstractPresenter

DEFAULT_SYFT_TIMEOUT = 600
DEFAULT_SYFT_COMMAND = 'syft'


@dataclass
class ContainerScannerConfig:
    debug: bool = False
    trace: bool = False
    quiet: bool = False
    syft_command: str = DEFAULT_SYFT_COMMAND
    syft_timeout: int = DEFAULT_SYFT_TIMEOUT


def create_container_scanner_config_from_args(args) -> ContainerScannerConfig:
    return ContainerScannerConfig(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        syft_command=args.syft_command,
        syft_timeout=args.syft_timeout,
    )


class LicenseItem(TypedDict):
    value: str
    spdxExpression: str
    type: str

    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)


class SyftArtifactItem(TypedDict):
    name: str
    version: str
    type: str
    purl: str
    licenses: List[LicenseItem]

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            name=data['name'],
            version=data['version'],
            type=data['type'],
            purl=data['purl'],
            licenses=[LicenseItem.from_dict(lic) for lic in data['licenses']],
        )


class SyftScanResult(TypedDict):
    artifacts: List[SyftArtifactItem]

    @classmethod
    def from_dict(cls, data: dict):
        return cls(artifacts=[SyftArtifactItem.from_dict(a) for a in data['artifacts']])


class SyftScanError(Exception):
    """Base exception for Syft scan errors"""

    pass


class SyftExecutionError(SyftScanError):
    """Raised when Syft returns a non-zero exit code"""

    pass


class SyftJsonError(SyftScanError):
    """Raised when Syft output cannot be parsed as JSON"""

    pass


class SyftTimeoutError(SyftScanError):
    """Raised when a Syft scan times out"""

    pass


class PurlItem(TypedDict):
    purl: str
    requirement: Optional[str]


class ContainerScanResultFileItem(TypedDict):
    file: str
    purls: List[PurlItem]


class ContainerScanResult(TypedDict):
    files: List[ContainerScanResultFileItem]


class ContainerScanner:
    """SCANOSS container scanning class.

    This class provides functionality to scan containers using Syft and process
    the results into SCANOSS dependency format.
    """

    def __init__(
        self,
        config: ContainerScannerConfig,
        what_to_scan: str,
    ):
        """Initialize ContainerScanner class.

        Args:
            config: ContainerScannerConfig object containing configuration settings.
        """
        self.base = ScanossBase(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
        self.presenter = ContainerScannerPresenter(
            self,
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
        self.what_to_scan: str = what_to_scan
        self.syft_command: str = config.syft_command
        self.syft_timeout: int = config.syft_timeout
        self.scan_results: Optional[SyftScanResult] = None

    def scan(self) -> SyftScanResult:
        """
        Scan the provided container using Syft.

        Returns:
            SyftScanResult: The Syft scan results.

        Raises:
            SyftExecutionError: If Syft returns a non-zero exit code
            SyftJsonError: If the scan output cannot be parsed as JSON
            SyftTimeoutError: If the scan times out
            SyftScanError: For other scan-related errors
        """
        self.run_scan()
        return self.scan_results

    def run_scan(
        self,
    ) -> None:
        """Run a syft scan of the specified target.

        Raises:
            SyftExecutionError: If Syft returns a non-zero exit code
            SyftJsonError: If the scan output cannot be parsed as JSON
            SyftTimeoutError: If the scan times out
            SyftScanError: For other scan-related errors
        """
        try:
            self.base.print_trace(
                f'About to execute {self.syft_command} scan {self.what_to_scan} -q {self.what_to_scan} -o json'
            )
            result = subprocess.run(
                [self.syft_command, 'scan', self.what_to_scan, '-q', '-o', 'json'],
                cwd=os.getcwd(),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=self.syft_timeout,
                check=False,
            )
            self.base.print_trace(f'Subprocess return: {result}')

            if result.returncode:
                error_msg = (
                    f'Syft scan of {self.what_to_scan} failed with exit code {result.returncode}:\n{result.stdout}'
                )
                self.base.print_stderr(f'ERROR: {error_msg}')
                raise SyftExecutionError(error_msg)

            try:
                json_data = json.loads(result.stdout)
                self.scan_results = SyftScanResult.from_dict(json_data)
            except json.JSONDecodeError as e:
                error_msg = f'Failed to parse JSON output from syft: {e}\n{result.stdout}'
                self.base.print_stderr(f'ERROR: {error_msg}')
                raise SyftJsonError(error_msg) from e

        except subprocess.TimeoutExpired as e:
            error_msg = f'Timed out attempting to run syft scan on {self.what_to_scan}: {e}'
            self.base.print_stderr(f'ERROR: {error_msg}')
            raise SyftTimeoutError(error_msg) from e

        except Exception as e:
            if isinstance(e, SyftScanError):
                raise
            error_msg = f'Issue running syft scan on {self.what_to_scan}: {e}'
            self.base.print_stderr(f'ERROR: {error_msg}')
            raise SyftScanError(error_msg) from e

    def present(self, output_format: str = None, output_file: str = None):
        """Present the results in the selected format"""
        self.presenter.present(output_format=output_format, output_file=output_file)


class ContainerScannerPresenter(AbstractPresenter):
    """
    ContainerScannerPresenter presenter class
    Handles the presentation of the container scan results
    """

    def __init__(self, scanner: ContainerScanner, **kwargs):
        super().__init__(**kwargs)
        self.scanner = scanner

    def _format_json_output(self) -> str:
        """
        Format the scan output data into a JSON object

        Returns:
            str: The formatted JSON string
        """
        return json.dumps(self._normalize_syft_output(), indent=2)

    def _normalize_syft_output(self) -> ContainerScanResult:
        """
        Normalize the Syft output data into the same format we use in dependency scanning

        Returns:
            ContainerScanResult: The normalized output
        """
        normalized_output = ContainerScanResult()

        # This is a workaround because we don't have file paths as in dependency scanning, we use the container name
        file_name = self.scanner.what_to_scan
        artifacts = self.scanner.scan_results['artifacts']

        normalized_output['files'] = [
            {
                'file': file_name,
                'purls': [PurlItem(purl=artifact['purl']) for artifact in artifacts],
            }
        ]

        return normalized_output

    def _format_plain_output(self) -> str:
        """
        Format the scan output data into a plain text string
        """
        return (
            json.dumps(self._normalize_syft_output(), indent=2)
            if isinstance(self.scanner.scan_results, SyftScanResult)
            else str(self.scanner.scan_results)
        )
