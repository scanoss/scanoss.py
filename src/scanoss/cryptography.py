import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from scanoss.cyclonedx import CycloneDx
from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.utils.abstract_presenter import AbstractPresenter
from scanoss.utils.file import validate_json_file


class ScanossCryptographyError(Exception):
    pass


MIN_SPLIT_PARTS = 2


@dataclass
class CryptographyConfig:
    purl: List[str]
    debug: bool = False
    header: Optional[str] = None
    input_file: Optional[str] = None
    output_file: Optional[str] = None
    quiet: bool = False
    trace: bool = False
    use_grpc: bool = False
    with_range: bool = False

    def _process_input_file(self) -> dict:
        """
        Process and validate the input file, returning the validated purl_request.
        
        Returns:
            dict: The validated purl_request dictionary
            
        Raises:
            ScanossCryptographyError: If the input file is invalid
        """
        result = validate_json_file(self.input_file)
        if not result.is_valid:
            raise ScanossCryptographyError(
                f'There was a problem with the purl input file. {result.error}'
            )
            
        cdx = CycloneDx(debug=self.debug)
        if cdx.is_cyclonedx_json(json.dumps(result.data)):
            purl_request = cdx.get_purls_request_from_cdx(result.data)
        else:
            purl_request = result.data
        
        if (
            not isinstance(purl_request, dict)
            or 'purls' not in purl_request
            or not isinstance(purl_request['purls'], list)
            or not all(isinstance(p, dict) and 'purl' in p for p in purl_request['purls'])
        ):
            raise ScanossCryptographyError('The supplied input file is not in the correct PurlRequest format.')
            
        return purl_request

    def __post_init__(self):
        """
        Validate that the configuration is valid.
        """
        if self.purl:
            if self.with_range:
                for purl in self.purl:
                    parts = purl.split('@')
                    if not (len(parts) >= MIN_SPLIT_PARTS and parts[1]):
                        raise ScanossCryptographyError(
                            f'Invalid PURL format: "{purl}".It must include a version (e.g., pkg:type/name@version)'
                        )
        if self.input_file:
            purl_request = self._process_input_file()
            purls = purl_request['purls']
            purls_with_requirement = []
            if self.with_range and any('requirement' not in p for p in purls):
                raise ScanossCryptographyError(
                    f'One or more PURLs in "{self.input_file}" are missing the "requirement" field.'
                )

            for purl in purls:
                if 'requirement' in purl:
                    purls_with_requirement.append(f'{purl["purl"]}@{purl["requirement"]}')
                else:
                    purls_with_requirement.append(purl['purl'])
            self.purl = purls_with_requirement


def create_cryptography_config_from_args(args) -> CryptographyConfig:
    return CryptographyConfig(
        debug=getattr(args, 'debug', False),
        header=getattr(args, 'header', None),
        input_file=getattr(args, 'input', None),
        output_file=getattr(args, 'output', None),
        purl=getattr(args, 'purl', []),
        quiet=getattr(args, 'quiet', False),
        trace=getattr(args, 'trace', False),
        use_grpc=getattr(args, 'grpc', False),
        with_range=getattr(args, 'with_range', False),
    )


class Cryptography:
    """
    Cryptography Class

    This class is used to decorate purls with cryptography information.
    """

    def __init__(
        self,
        config: CryptographyConfig,
        client: ScanossGrpc,
    ):
        """
        Initialize the Cryptography.

        Args:
            config (CryptographyConfig): Configuration parameters for the cryptography.
            client (ScanossGrpc): gRPC client for communicating with the scanning service.
        """
        self.base = ScanossBase(
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )
        self.presenter = CryptographyPresenter(
            self,
            debug=config.debug,
            trace=config.trace,
            quiet=config.quiet,
        )

        self.client = client
        self.config = config
        self.components_request = self._build_components_request()
        self.results = None

    def get_algorithms(self) -> Optional[Dict]:
        """
        Get the cryptographic algorithms for the provided purl or input file.

        Returns:
            Optional[Dict]: The folder hash response from the gRPC client, or None if an error occurs.
        """

        if not self.components_request or not self.components_request.get('components'):
            raise ScanossCryptographyError('No PURLs supplied. Provide --purl or --input.')
        components_str = ', '.join(p['purl'] for p in self.components_request['components'])
        self.base.print_stderr(f'Getting cryptographic algorithms for {components_str}')
        if self.config.with_range:
            response = self.client.get_crypto_algorithms_in_range_for_purl(
                self.components_request, self.config.use_grpc
            )
        else:
            response = self.client.get_crypto_algorithms_for_purl(self.components_request, self.config.use_grpc)
        if response:
            self.results = response

        return self.results

    def get_encryption_hints(self) -> Optional[Dict]:
        """
        Get the encryption hints for the provided purl or input file.

        Returns:
            Optional[Dict]: The encryption hints response from the gRPC client, or None if an error occurs.
        """

        if not self.components_request or not self.components_request.get('components'):
            raise ScanossCryptographyError('No PURLs supplied. Provide --purl or --input.')
        self.base.print_stderr(
            f'Getting encryption hints '
            f'{"in range" if self.config.with_range else ""} '
            f'for {", ".join([p["purl"] for p in self.components_request["components"]])}'
        )
        if self.config.with_range:
            response = self.client.get_encryption_hints_in_range_for_purl(self.components_request, self.config.use_grpc)
        else:
            response = self.client.get_encryption_hints_for_purl(self.components_request, self.config.use_grpc)
        if response:
            self.results = response

        return self.results

    def get_versions_in_range(self) -> Optional[Dict]:
        """
        Given a list of PURLS and version ranges, get a list of versions that do/do not contain cryptographic algorithms

        Returns:
            Optional[Dict]: The versions in range response from the gRPC client, or None if an error occurs.
        """

        if not self.components_request or not self.components_request.get('components'):
            raise ScanossCryptographyError('No PURLs supplied. Provide --purl or --input.')

        components_str = ', '.join(p['purl'] for p in self.components_request['components'])
        self.base.print_stderr(f'Getting versions in range for {components_str}')

        response = self.client.get_versions_in_range_for_purl(self.components_request, self.config.use_grpc)
        if response:
            self.results = response

        return self.results

    def _build_components_request(
        self,
    ) -> Optional[dict]:
        """
        Load the specified purls from a JSON file or a list of PURLs and return a dictionary

        Returns:
            Optional[dict]: The dictionary containing the PURLs
        """
        return {
            'components': [
                {
                    'purl': self._remove_version_from_purl(purl),
                    'requirement': self._extract_version_from_purl(purl),
                }
                for purl in self.config.purl
            ]
        }

    def _remove_version_from_purl(self, purl: str) -> str:
        """
        Remove version from purl

        Args:
            purl (str): The purl string to remove the version from

        Returns:
            str: The purl string without the version
        """
        if '@' not in purl:
            return purl
        return purl.split('@')[0]

    def _extract_version_from_purl(self, purl: str) -> str:
        """
        Extract version from purl

        Args:
            purl (str): The purl string to extract the version from

        Returns:
            str: The extracted version

        Raises:
            ScanossCryptographyError: If the purl is not in the correct format
        """
        try:
            return purl.split('@')[-1]
        except IndexError:
            raise ScanossCryptographyError(f'Invalid purl format: {purl}')

    def present(
        self,
        output_format: Optional[str] = None,
        output_file: Optional[str] = None,
    ):
        """Present the results in the selected format"""
        self.presenter.present(output_format=output_format, output_file=output_file)


class CryptographyPresenter(AbstractPresenter):
    """
    Cryptography presenter class
    Handles the presentation of the cryptography results
    """

    def __init__(self, cryptography: Cryptography, **kwargs):
        super().__init__(**kwargs)
        self.cryptography = cryptography

    def _format_json_output(self) -> str:
        """
        Format the scan output data into a JSON object

        Returns:
            str: The formatted JSON string
        """
        return json.dumps(self.cryptography.results, indent=2)

    def _format_plain_output(self) -> str:
        """
        Format the scan output data into a plain text string
        """
        return (
            json.dumps(self.cryptography.results, indent=2)
            if isinstance(self.cryptography.results, dict)
            else str(self.cryptography.results)
        )

    def _format_cyclonedx_output(self) -> str:
        raise NotImplementedError('CycloneDX output is not implemented')

    def _format_spdxlite_output(self) -> str:
        raise NotImplementedError('SPDXlite output is not implemented')

    def _format_csv_output(self) -> str:
        raise NotImplementedError('CSV output is not implemented')

    def _format_raw_output(self) -> str:
        raise NotImplementedError('Raw output is not implemented')
