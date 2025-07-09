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
from typing import Dict, List, Optional, TypedDict

from scanoss.constants import DEFAULT_RETRY, DEFAULT_TIMEOUT
from scanoss.csvoutput import CsvOutput
from scanoss.cyclonedx import CycloneDx
from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.spdxlite import SpdxLite
from scanoss.utils.abstract_presenter import AbstractPresenter

DEFAULT_SYFT_TIMEOUT = 600
DEFAULT_SYFT_COMMAND = 'syft'


@dataclass
class ContainerScannerConfig:
    debug: bool = False
    trace: bool = False
    quiet: bool = False
    retry: int = DEFAULT_RETRY
    timeout: int = DEFAULT_TIMEOUT
    output: Optional[str] = None
    format: Optional[str] = None
    apiurl: Optional[str] = None
    ignore_cert_errors: bool = False
    key: Optional[str] = None
    proxy: Optional[str] = None
    pac: Optional[str] = None
    grpc_proxy: Optional[str] = None
    ca_cert: Optional[str] = None
    syft_command: str = DEFAULT_SYFT_COMMAND
    syft_timeout: int = DEFAULT_SYFT_TIMEOUT
    only_interim_results: bool = False


def create_container_scanner_config_from_args(args) -> ContainerScannerConfig:
    return ContainerScannerConfig(
        debug=args.debug if 'debug' in args else False,
        trace=args.trace if 'trace' in args else False,
        quiet=args.quiet if 'quiet' in args else False,
        retry=args.retry if 'retry' in args else DEFAULT_RETRY,
        timeout=args.timeout if 'timeout' in args else DEFAULT_TIMEOUT,
        output=args.output if 'output' in args else None,
        format=args.format if 'format' in args else None,
        apiurl=args.api2url if 'api2url' in args else None,
        proxy=args.proxy if 'proxy' in args else None,
        pac=args.pac if 'pac' in args else None,
        grpc_proxy=args.grpc_proxy if 'grpc_proxy' in args else None,
        ca_cert=args.ca_cert if 'ca_cert' in args else None,
        ignore_cert_errors=args.ignore_cert_errors if 'ignore_cert_errors' in args else False,
        key=args.key if 'key' in args else None,
        syft_command=args.syft_command if 'syft_command' in args else DEFAULT_SYFT_COMMAND,
        syft_timeout=args.syft_timeout if 'syft_timeout' in args else DEFAULT_SYFT_TIMEOUT,
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


class PurlItem(TypedDict):
    purl: str
    requirement: Optional[str]


class ContainerScanResultFileItem(TypedDict):
    file: str
    purls: List[PurlItem]


class ContainerScanResult(TypedDict):
    files: List[ContainerScanResultFileItem]


class DependencyLicenseItem(TypedDict):
    value: str
    spdxExpression: str
    type: str


class DependencyItem(TypedDict):
    purl: str
    licenses: List[DependencyLicenseItem]


class DecoratedContainerScanResultFileItem(TypedDict):
    file: str
    id: str
    status: str
    dependencies: List[DependencyItem]


class DecoratedContainerScanResult(TypedDict):
    files: List[ContainerScanResultFileItem]
    status: Dict[str, str]


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


class SCANOSSDependencyScanError(Exception):
    """Base exception for SCANOSS dependency scan errors"""

    pass


class DecorateScanResultsError(SCANOSSDependencyScanError):
    """Raised when there is an issue decorating scan results with dependencies"""

    pass


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
            output_file=config.output,
            output_format=config.format,
        )
        self.grpc_api = ScanossGrpc(
            debug=config.debug,
            quiet=config.quiet,
            trace=config.trace,
            url=config.apiurl,
            api_key=config.key,
            ca_cert=config.ca_cert,
            proxy=config.proxy,
            pac=config.pac,
            grpc_proxy=config.grpc_proxy,
        )
        self.what_to_scan: str = what_to_scan
        self.syft_command: str = config.syft_command
        self.syft_timeout: int = config.syft_timeout
        self.only_interim_results: bool = config.only_interim_results
        self.syft_output: Optional[SyftScanResult] = None
        self.normalized_syft_output: Optional[ContainerScanResult] = None
        self.decorated_scan_results: Optional[DecoratedContainerScanResult] = None

    def decorate_scan_results_with_dependencies(self) -> None:
        """
        Decorate the scan results with dependencies.
        """
        try:
            decorated_scan_results = self.grpc_api.get_dependencies(self.normalized_syft_output)
            self.decorated_scan_results = decorated_scan_results
            return decorated_scan_results
        except Exception as e:
            error_msg = f'Issue decorating scan results with dependencies: {e}'
            self.base.print_stderr(f'ERROR: {error_msg}')
            raise DecorateScanResultsError(error_msg) from e

    def scan(
        self,
    ) -> ContainerScanResult:
        """Run a syft scan of the specified target.

        Returns:
            ContainerScanResult: The container scan results.

        Raises:
            SyftScanError: For other scan-related errors
        """
        try:
            self.syft_output = self._execute_syft_scan()
            self.normalized_syft_output = self._normalize_syft_output()
            return self.normalized_syft_output
        except Exception as e:
            if isinstance(e, SyftScanError):
                raise
            error_msg = f'Issue running syft scan on {self.what_to_scan}: {e}'
            self.base.print_stderr(f'ERROR: {error_msg}')
            raise SyftScanError(error_msg) from e

    def _execute_syft_scan(self) -> SyftScanResult:
        """
        Execute a Syft scan of the specified target.

        Returns:
            SyftScanResult: The result of the Syft scan.

        Raises:
            SyftScanError: If the Syft scan fails.
            SyftJsonError: If the Syft scan output cannot be parsed as JSON.
            SyftTimeoutError: If the Syft scan times out.
            SyftExecutionError: If the Syft scan execution fails.
        """
        try:
            self.base.print_trace(f'About to execute {self.syft_command} scan {self.what_to_scan} -q -o json')
            self.base.print_msg('Scanning container...')
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
                return SyftScanResult.from_dict(json_data)
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

    def _get_dependencies(self) -> None:
        """
        Run a dependency scan of the specified target.
        """
        try:
            if not self.normalized_syft_output:
                error_msg = 'Syft scan output is not available'
                self.base.print_stderr(error_msg)
                raise ValueError(error_msg)
            if not self.grpc_api.get_dependencies(self.normalized_syft_output):
                error_msg = 'Failed to get dependencies'
                self.base.print_stderr(error_msg)
                raise SCANOSSDependencyScanError(error_msg)
        except Exception as e:
            error_msg = f'Failed to run dependency scan: {e}'
            self.base.print_stderr(error_msg)
            raise SCANOSSDependencyScanError(error_msg)

    def _normalize_syft_output(self) -> ContainerScanResult:
        """
        Normalize the Syft output data into the same format we use in dependency scanning

        Returns:
            ContainerScanResult: The normalized output
        """
        normalized_output = ContainerScanResult()

        # This is a workaround because we don't have file paths as in dependency scanning, we use the container name
        file_name = self.what_to_scan
        artifacts = self.syft_output['artifacts']

        unique_purls = set()
        unique_purl_items = []

        for artifact in artifacts:
            purl = artifact['purl']
            if purl not in unique_purls:
                unique_purls.add(purl)
                unique_purl_items.append(PurlItem(purl=purl))

        normalized_output['files'] = [
            {
                'file': file_name,
                'purls': unique_purl_items,
            }
        ]

        return normalized_output

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
        self.AVAILABLE_OUTPUT_FORMATS = ['plain', 'cyclonedx', 'spdxlite', 'csv', 'raw']

    def _convert_raw_to_scan_output(self) -> dict:
        """
        Convert the raw output from dependency scanning API to our scan output format

        Returns:
            dict: The converted output
        """
        formatted_output = {}
        if (
            self.scanner.decorated_scan_results
            and 'files' in self.scanner.decorated_scan_results
            and self.scanner.decorated_scan_results['files']
            and isinstance(self.scanner.decorated_scan_results['files'], list)
        ):
            file_item = self.scanner.decorated_scan_results['files'][0]
            if file_item and isinstance(file_item, dict) and 'file' in file_item:
                formatted_output[file_item['file']] = [file_item]

        return formatted_output

    def _format_plain_output(self) -> str:
        """
        Format the scan output data into a plain text string
        """
        return json.dumps(self._convert_raw_to_scan_output(), indent=2)

    def _format_raw_output(self) -> str:
        """
        Format the scan output data into the raw output from dependency scanning API
        """
        if self.scanner.only_interim_results:
            return json.dumps(self.scanner.normalized_syft_output, indent=2)
        return json.dumps(self.scanner.decorated_scan_results, indent=2)

    def _format_cyclonedx_output(self) -> str:
        """
        Format the scan output data into a CycloneDX object
        """
        cdx = CycloneDx(self.base.debug, self.output_file)
        scan_results = {}
        for f in self.scanner.decorated_scan_results['files']:
            scan_results[f['file']] = [f]
        success, cdx_output = cdx.produce_from_json(scan_results)
        if not success:
            error_msg = 'Failed to produce CycloneDX output'
            self.base.print_stderr(error_msg)
            return None
        return json.dumps(cdx_output, indent=2)

    def _format_spdxlite_output(self) -> str:
        """
        Format the scan output data into a SPDXLite object
        """
        spdxlite = SpdxLite(self.base.debug, self.output_file)
        scan_results = {}
        for f in self.scanner.decorated_scan_results['files']:
            scan_results[f['file']] = [f]
        if not spdxlite.produce_from_json(scan_results, self.output_file):
            error_msg = 'Failed to produce SPDXLite output'
            self.base.print_stderr(error_msg)
            raise ValueError(error_msg)

    def _format_csv_output(self) -> str:
        """
        Format the scan output data into a CSV object
        """
        csv = CsvOutput(self.base.debug, self.output_file)
        scan_results = {}
        for f in self.scanner.decorated_scan_results['files']:
            scan_results[f['file']] = [f]
        if not csv.produce_from_json(scan_results, self.output_file):
            error_msg = 'Failed to produce CSV output'
            self.base.print_stderr(error_msg)
            raise ValueError(error_msg)

    def _format_json_output(self) -> str:
        """
        Format the scan output data into a JSON object
        """
        pass
