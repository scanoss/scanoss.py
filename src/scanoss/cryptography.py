import json
from dataclasses import dataclass
from typing import Dict, List, Optional

from scanoss.scanossbase import ScanossBase
from scanoss.scanossgrpc import ScanossGrpc
from scanoss.utils.abstract_presenter import AbstractPresenter
from scanoss.utils.file import validate_json_file


class ScanossCryptographyError(Exception):
    pass


@dataclass
class CryptographyConfig:
    debug: bool = False
    trace: bool = False
    quiet: bool = False
    get_range: bool = False
    purl: List[str] = None
    input_file: str = None
    output_file: str = None
    header: str = None


def create_cryptography_config_from_args(args) -> CryptographyConfig:
    return CryptographyConfig(
        debug=getattr(args, 'debug', None),
        trace=getattr(args, 'trace', None),
        quiet=getattr(args, 'quiet', None),
        get_range=getattr(args, 'range', None),
        purl=getattr(args, 'purl', None),
        input_file=getattr(args, 'input', None),
        output_file=getattr(args, 'output', None),
        header=getattr(args, 'header', None),
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
        self.purls_request = self._build_purls_request()
        self.results = None

    def get_algorithms(self) -> Optional[Dict]:
        """
        Get the cryptographic algorithms for the provided purl or input file.

        Returns:
            Optional[Dict]: The folder hash response from the gRPC client, or None if an error occurs.
        """

        if not self.purls_request:
            raise ScanossCryptographyError('No PURLs supplied. Provide --purl or --input.')
        self.base.print_stderr(
            f'Getting cryptographic algorithms for {", ".join([p["purl"] for p in self.purls_request["purls"]])}'
        )
        if self.config.get_range:
            response = self.client.get_crypto_algorithms_in_range_for_purl(self.purls_request)
        else:
            response = self.client.get_crypto_algorithms_for_purl(self.purls_request)
        if response:
            self.results = response

        return self.results

    def _build_purls_request(
        self,
    ) -> Optional[dict]:
        """
        Load the specified purls from a JSON file or a list of PURLs and return a dictionary

        Args:
            json_file (Optional[str], optional): The JSON file containing the PURLs. Defaults to None.
            purls (Optional[List[str]], optional): The list of PURLs. Defaults to None.

        Returns:
            Optional[dict]: The dictionary containing the PURLs
        """
        if self.config.input_file:
            input_file_validation = validate_json_file(self.config.input_file)
            if not input_file_validation.is_valid:
                raise Exception(f'There was a problem with the purl input file. {input_file_validation.error}')

            # Validate the input file is in PurlRequest format
            if (
                not isinstance(input_file_validation.data, dict)
                or 'purls' not in input_file_validation.data
                or not isinstance(input_file_validation.data['purls'], list)
                or not all(isinstance(p, dict) and 'purl' in p for p in input_file_validation.data['purls'])
            ):
                raise Exception('The supplied input file is not in the correct PurlRequest format.')
            return input_file_validation.data
        if self.config.purl:
            return {'purls': [{'purl': p} for p in self.config.purl]}
        return None

    def present(self, output_format: str = None, output_file: str = None):
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
