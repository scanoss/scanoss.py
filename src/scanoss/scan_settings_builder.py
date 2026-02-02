"""
SPDX-License-Identifier: MIT

  Copyright (c) 2025, SCANOSS

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

from typing import TYPE_CHECKING, Optional

from .scanossbase import ScanossBase

if TYPE_CHECKING:
    from .scanoss_settings import ScanossSettings

MAX_RANKING_THRESHOLD = 10


class ScanSettingsBuilder(ScanossBase):
    """Builder class for merging CLI arguments with scanoss.json settings file values.

    This class implements an API for merging scan configuration
    from multiple sources with the following priority order:
     1. settings.file_snippet section in scanoss.json (highest priority)
     2. settings section in scanoss.json (middle priority)
     3. CLI arguments (lowest priority - used as fallback)

    Attributes:
        proxy: Merged proxy host URL
        url: Merged API base URL
        ignore_cert_errors: Whether to ignore SSL certificate errors
        min_snippet_hits: Minimum snippet hits required for matching
        min_snippet_lines: Minimum snippet lines required for matching
        honour_file_exts: Whether to honour file extensions during scanning
        ranking: Whether ranking is enabled
        ranking_threshold: Ranking threshold value
    """

    def __init__(
        self,
        scanoss_settings: 'ScanossSettings | None',
        debug: bool = False,
        trace: bool = False,
        quiet: bool = False,
    ):
        """Initialize the builder with optional scanoss settings.

        Args:
            scanoss_settings: ScanossSettings instance loaded from scanoss.json,
                              or None if no settings file is available.
            debug: Enable debug output
            trace: Enable trace output
            quiet: Enable quiet mode
        """
        super().__init__(debug=debug, trace=trace, quiet=quiet)
        self.scanoss_settings = scanoss_settings
        # Merged values
        self.proxy: Optional[str] = None
        self.url: Optional[str] = None
        self.ignore_cert_errors: bool = False
        self.min_snippet_hits: Optional[int] = None
        self.min_snippet_lines: Optional[int] = None
        self.honour_file_exts: Optional[any] = None
        self.ranking: Optional[any] = None
        self.ranking_threshold: Optional[int] = None

    def with_proxy(self, cli_value: str = None) -> 'ScanSettingsBuilder':
        """Set proxy host with priority: file_snippet.proxy.host > settings.proxy.host > CLI.

        Args:
            cli_value: Proxy host from CLI argument (e.g., 'http://proxy:8080')

        Returns:
            Self for method chaining
        """
        self.proxy = self._merge_with_priority(
            cli_value,
            self._get_proxy_host(self._get_file_snippet_proxy()),
            self._get_proxy_host(self._get_root_proxy())
        )
        return self

    def with_url(self, cli_value: str = None) -> 'ScanSettingsBuilder':
        """Set API base URL with priority: file_snippet.http_config.base_uri > settings.http_config.base_uri > CLI.

        Args:
            cli_value: API base URL from CLI argument (e.g., 'https://api.scanoss.com')

        Returns:
            Self for method chaining
        """
        self.url = self._merge_with_priority(
            cli_value,
            self._get_file_snippet_http_config_value('base_uri'),
            self._get_http_config_value('base_uri')
        )
        return self

    def with_ignore_cert_errors(self, cli_value: bool = False) -> 'ScanSettingsBuilder':
        """Set ignore_cert_errors with priority: CLI True > file_snippet > settings > False.

        Note: CLI value only takes effect if True (flag present). False means
        the flag was not provided, so settings file values are checked.

        Args:
            cli_value: Whether to ignore SSL certificate errors from CLI flag

        Returns:
            Self for method chaining
        """
        result = self._merge_with_priority(
            cli_value if cli_value else None,
            self._get_file_snippet_http_config_value('ignore_cert_errors'),
            self._get_http_config_value('ignore_cert_errors')
        )
        self.ignore_cert_errors = result if result is not None else False
        return self

    def with_min_snippet_hits(self, cli_value: int = None) -> 'ScanSettingsBuilder':
        """Set minimum snippet hits with priority: settings.file_snippet.min_snippet_hits > CLI.

        Minimum allowed value is 0. Values below 0 will be clamped and logged.

        Args:
            cli_value: Minimum snippet hits from CLI argument

        Returns:
            Self for method chaining
        """
        self.min_snippet_hits = self._merge_cli_with_settings(
            cli_value,
            self._get_file_snippet_setting('min_snippet_hits')
        )
        if self.min_snippet_hits is not None and self.min_snippet_hits < 0:
            self.print_msg(
                f'WARNING: min-snippet-hits value {self.min_snippet_hits} is below minimum allowed (0). '
                f'Setting to 0.'
            )
            self.min_snippet_hits = 0
        return self

    def with_min_snippet_lines(self, cli_value: int = None) -> 'ScanSettingsBuilder':
        """Set minimum snippet lines with priority: settings.file_snippet.min_snippet_lines > CLI.

        Minimum allowed value is 0. Values below 0 will be clamped and logged.

        Args:
            cli_value: Minimum snippet lines from CLI argument

        Returns:
            Self for method chaining
        """
        self.min_snippet_lines = self._merge_cli_with_settings(
            cli_value,
            self._get_file_snippet_setting('min_snippet_lines')
        )
        if self.min_snippet_lines is not None and self.min_snippet_lines < 0:
            self.print_msg(
                f'WARNING: min-snippet-lines value {self.min_snippet_lines} is below minimum allowed (0). '
                f'Setting to 0.'
            )
            self.min_snippet_lines = 0
        return self

    def with_honour_file_exts(self, cli_value: str = None) -> 'ScanSettingsBuilder':
        """Set honour_file_exts with priority: settings.file_snippet.honour_file_exts > CLI.

        Args:
            cli_value: String 'true', 'false', or 'unset' from CLI argument

        Returns:
            Self for method chaining
        """
        self.honour_file_exts = self._merge_cli_with_settings(
            cli_value,
            self._get_file_snippet_setting('honour_file_exts')
        )
        ## Convert to boolean
        if self.honour_file_exts is not None and self.honour_file_exts!= 'unset':
            self.honour_file_exts = self._str_to_bool(self.honour_file_exts)
        return self

    def with_ranking(self, cli_value: str = None) -> 'ScanSettingsBuilder':
        """Set ranking enabled with priority: settings.file_snippet.ranking_enabled > CLI.

        Args:
            cli_value: String 'true', 'false', or 'unset' from CLI argument

        Returns:
            Self for method chaining
        """
        self.ranking = self._merge_cli_with_settings(
            cli_value,
            self._get_file_snippet_setting('ranking_enabled')
        )
        if self.ranking is not None and self.ranking != 'unset':
            self.ranking = self._str_to_bool(self.ranking)
        return self

    def with_ranking_threshold(self, cli_value: int = None) -> 'ScanSettingsBuilder':
        """Set ranking threshold with priority: settings.file_snippet.ranking_threshold > CLI.

        Valid range is -1 to 10. Values outside this range will be clamped and logged.

        Args:
            cli_value: Ranking threshold from CLI argument

        Returns:
            Self for method chaining
        """
        self.ranking_threshold = self._merge_cli_with_settings(
            cli_value,
            self._get_file_snippet_setting('ranking_threshold')
        )
        if self.ranking_threshold is not None:
            if self.ranking_threshold > MAX_RANKING_THRESHOLD:
                self.print_msg(
                    f'WARNING: ranking-threshold value {self.ranking_threshold} exceeds maximum allowed '
                    f'({MAX_RANKING_THRESHOLD}). Setting to {MAX_RANKING_THRESHOLD}.'
                )
                self.ranking_threshold = MAX_RANKING_THRESHOLD
            elif self.ranking_threshold < -1:
                self.print_msg(
                    f'WARNING: ranking-threshold value {self.ranking_threshold} is below minimum allowed (-1). '
                    f'Setting to -1.'
                )
                self.ranking_threshold = -1
        return self

    # Private helper methods
    @staticmethod
    def _merge_with_priority(cli_value, file_snippet_value, root_value):
        """Merge with priority: file_snippet > root settings > CLI"""
        if file_snippet_value is not None:
            return file_snippet_value
        if root_value is not None:
            return root_value
        return cli_value

    @staticmethod
    def _merge_cli_with_settings(cli_value, settings_value):
        """Merge CLI value with settings, with settings taking priority over CLI.

        Returns settings_value if not None, otherwise falls back to cli_value.
        """
        if settings_value is not None:
            return settings_value
        return cli_value


    @staticmethod
    def _str_to_bool(value: str) -> Optional[bool]:
        """Convert string 'true'/'false' to boolean."""
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        return value.lower() == 'true'

    # Methods to extract values from scanoss_settings
    def _get_file_snippet_setting(self, key: str):
        """Get a setting from the file_snippet section."""
        if not self.scanoss_settings:
            return None
        return self.scanoss_settings.get_file_snippet_settings().get(key)

    def _get_file_snippet_proxy(self):
        """Get proxy config from file_snippet section."""
        return self.scanoss_settings.get_file_snippet_proxy() if self.scanoss_settings else None

    def _get_root_proxy(self):
        """Get proxy config from root settings section."""
        return self.scanoss_settings.get_proxy() if self.scanoss_settings else None

    @staticmethod
    def _get_proxy_host(proxy_config) -> Optional[str]:
        """Extract host from proxy configuration dict."""
        if proxy_config is None:
            return None
        host = proxy_config.get('host')
        return host if host else None

    def _get_http_config_value(self, key: str):
        """Extract a value from http_config dict."""
        if not self.scanoss_settings:
            return None
        config = self.scanoss_settings.get_http_config()
        return config.get(key) if config else None

    def _get_file_snippet_http_config_value(self, key: str):
        """Extract a value from file_snippet http_config dict."""
        if not self.scanoss_settings:
            return None
        config = self.scanoss_settings.get_file_snippet_http_config()
        return config.get(key) if config else None