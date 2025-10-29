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

from dataclasses import dataclass

from ...scanossbase import ScanossBase
from ...utils import scanoss_scan_results_utils
from ..utils.file_utils import load_json_file
from ..utils.markdown_utils import generate_table


@dataclass
class MatchSummaryItem:
    """
    Represents a single match entry in the SCANOSS results.

    This data class encapsulates all the relevant information about a component
    match found during scanning, including file location, license details, and
    match quality metrics.
    """
    file: str
    file_url: str
    license: str
    similarity: str
    purl: str
    purl_url: str
    version: str
    lines: str


@dataclass
class ComponentMatchSummary:
    """
    Container for categorized SCANOSS match results.

    Organizes matches into two categories: full file matches and snippet matches.
    This separation allows for different presentation and analysis of match types.
    """
    files: list[MatchSummaryItem]
    snippet: list[MatchSummaryItem]

class MatchSummary(ScanossBase):
    """
    Generates Markdown summaries from SCANOSS scan results.

    This class processes SCANOSS scan results and creates human-readable Markdown
    reports with collapsible sections for file and snippet matches. The reports
    include clickable links to files when a line range
    prefix is provided.
    """

    def __init__(  # noqa: PLR0913
            self,
            debug: bool = False,
            trace: bool = False,
            quiet: bool = False,
            line_range_prefix: str = None,
            scanoss_results_path: str = None,
            output: str = None,
    ):
        """
        Initialize the Matches Summary generator.

        :param debug: Enable debug output for troubleshooting
        :param trace: Enable trace-level logging for detailed execution tracking
        :param quiet: Suppress informational messages
        :param line_range_prefix: Base URL prefix for GitLab file links with line ranges
                                  (e.g., 'https://gitlab.com/org/project/-/blob/main')
        :param scanoss_results_path: Path to SCANOSS scan results file in JSON format
        :param output: Output file path for the generated Markdown report (default: stdout)
        """
        super().__init__(debug=debug, trace=trace, quiet=quiet)
        self.scanoss_results_path = scanoss_results_path
        self.line_range_prefix = line_range_prefix
        self.output = output
        self.print_debug("Initializing MatchSummary class")


    def _get_match_summary_item(self, file_name: str, result: dict) -> MatchSummaryItem:
        """
        Create a MatchSummaryItem from a single scan result.

        Processes a SCANOSS scan result and creates a MatchSummaryItem with appropriate
        file URLs, license information, and line ranges. Handles both snippet matches
        (with specific line ranges) and file matches (entire file).

        :param file_name: Name of the scanned file (relative path in the repository)
        :param result: SCANOSS scan result dictionary containing match details
        :return: Populated match summary item with all relevant information
        """
        self.print_trace(f"Creating match summary item for file: {file_name}, id: {result.get('id')}")

        if result.get('id') == "snippet":
            # Snippet match: create URL with line range anchor
            lines = scanoss_scan_results_utils.get_lines(result.get('lines'))
            end_line = lines[len(lines) - 1] if len(lines) > 1 else lines[0]
            file_url = f"{self.line_range_prefix}/{file_name}#L{lines[0]}-L{end_line}"

            self.print_trace(f"Snippet match: lines {lines[0]}-{end_line}, purl: {result.get('purl')[0]}")

            return MatchSummaryItem(
                file_url=file_url,
                file=file_name,
                license=result.get('licenses')[0].get('name'),
                similarity=result.get('matched'),
                purl=result.get('purl')[0],
                purl_url=result.get('url'),
                version=result.get('version'),
                lines=f"{lines[0]}-{lines[len(lines) - 1] if len(lines) > 1 else lines[0]}"
            )
        # File match: create URL without line range
        self.print_trace(f"File match: {file_name}, purl: {result.get('purl')[0]}, version: {result.get('version')}")

        return MatchSummaryItem(
            file=file_name,
            file_url=f"{self.line_range_prefix}/{file_name}",
            license=result.get('licenses')[0].get('name'),
            similarity=result.get('matched'),
            purl=result.get('purl')[0],
            purl_url=result.get('url'),
            version=result.get('version'),
            lines="all"
        )

    def _validate_result(self, file_name: str, result: dict) -> bool:
        """
        Validate that a scan result has all required fields.

        :param file_name: Name of the file being validated
        :param result: The scan result to validate
        :return: True if valid, False otherwise
        """
        validations = [
            ('id', 'No id found'),
            ('lines', 'No lines found'),
            ('purl', 'No purl found'),
            ('licenses', 'No licenses found'),
            ('version', 'No version found'),
            ('matched', 'No matched found'),
            ('url', 'No url found'),
        ]

        for field, error_msg in validations:
            if not result.get(field):
                self.print_debug(f'ERROR: {error_msg} for file {file_name}')
                return False

        # Additional validation for non-empty lists
        if len(result.get('purl')) == 0:
            self.print_debug(f'ERROR: No purl found for file {file_name}')
            return False
        if len(result.get('licenses')) == 0:
            self.print_debug(f'ERROR: Empty licenses list for file {file_name}')
            return False

        return True

    def _get_matches_summary(self) -> ComponentMatchSummary:
        """
        Parse SCANOSS scan results and create categorized match summaries.

        Loads the SCANOSS scan results file and processes each match, validating
        required fields and categorizing matches into file matches and snippet matches.
        Skips invalid or incomplete results with debug messages.
        """
        self.print_debug(f"Loading scan results from: {self.scanoss_results_path}")

        # Load scan results from JSON file
        scan_results = load_json_file(self.scanoss_results_path)
        gitlab_matches_summary = ComponentMatchSummary(files=[], snippet=[])

        self.print_debug(f"Processing {len(scan_results)} files from scan results")
        self.print_trace(f"Line range prefix set to: {self.line_range_prefix}")

        # Process each file and its results
        for file_name, results in scan_results.items():
            self.print_trace(f"Processing file: {file_name} with {len(results)} results")

            for result in results:
                # Skip non-matches
                if result.get('id') == "none":
                    self.print_debug(f'Skipping non-match for file {file_name}')
                    continue

                # Validate required fields
                if not self._validate_result(file_name, result):
                    continue

                # Create summary item and categorize by match type
                summary_item = self._get_match_summary_item(file_name, result)
                if result.get('id') == "snippet":
                    gitlab_matches_summary.snippet.append(summary_item)
                    self.print_trace(f"Added snippet match for {file_name}")
                else:
                    gitlab_matches_summary.files.append(summary_item)
                    self.print_trace(f"Added file match for {file_name}")

        self.print_debug(
            f"Match summary complete: {len(gitlab_matches_summary.files)} file matches, "
            f"{len(gitlab_matches_summary.snippet)} snippet matches"
        )

        return gitlab_matches_summary


    def _markdown(self, gitlab_matches_summary: ComponentMatchSummary) -> str:
        """
        Generate Markdown from match summaries.

        Creates a formatted Markdown document with collapsible sections for file
        and snippet matches.

        :param gitlab_matches_summary: Container with categorized file and snippet matches to format
        :return: Complete Markdown document with formatted match tables
        """
        self.print_debug("Generating Markdown from match summaries")

        if len(gitlab_matches_summary.files) == 0 and len(gitlab_matches_summary.snippet) == 0:
            self.print_debug("No matches to format - returning empty string")
            return ""

        self.print_trace(
            f"Formatting {len(gitlab_matches_summary.files)} file matches and "
            f"{len(gitlab_matches_summary.snippet)} snippet matches"
        )

        # Define table headers
        file_match_headers = ['File', 'License', 'Similarity', 'PURL', 'Version']
        snippet_match_headers = ['File', 'License', 'Similarity', 'PURL', 'Version', 'Lines']

        # Build file matches table
        self.print_trace("Building file matches table")
        file_match_rows = []
        for file_match in gitlab_matches_summary.files:
            row = [
                f"[{file_match.file}]({file_match.file_url})",
                file_match.license,
                file_match.similarity,
                f"[{file_match.purl}]({file_match.purl_url})",
                file_match.version,
            ]
            file_match_rows.append(row)
        file_match_table = generate_table(file_match_headers, file_match_rows)

        # Build snippet matches table
        self.print_trace("Building snippet matches table")
        snippet_match_rows = []
        for snippet_match in gitlab_matches_summary.snippet:
            row = [
                f"[{snippet_match.file}]({snippet_match.file_url})",
                snippet_match.license,
                snippet_match.similarity,
                f"[{snippet_match.purl}]({snippet_match.purl_url})",
                snippet_match.version,
                snippet_match.lines
            ]
            snippet_match_rows.append(row)
        snippet_match_table = generate_table(snippet_match_headers, snippet_match_rows)

        # Assemble complete Markdown document
        markdown = ""
        markdown += "### SCANOSS Match Summary\n\n"

        # File matches section (collapsible)
        markdown += "<details>\n"
        markdown += "<summary>File Match Summary</summary>\n\n"
        markdown += file_match_table
        markdown += "\n</details>\n"

        # Snippet matches section (collapsible)
        markdown += "<details>\n"
        markdown += "<summary>Snippet Match Summary</summary>\n\n"
        markdown += snippet_match_table
        markdown += "\n</details>\n"

        self.print_trace(f"Markdown generation complete (length: {len(markdown)} characters)")
        self.print_debug("Match summary Markdown generation complete")
        return markdown

    def run(self):
        """
        Execute the matches summary generation process.

        This is the main entry point for generating the matches summary report.
        It orchestrates the entire workflow:
        1. Loads and parses SCANOSS scan results
        2. Validates and categorizes matches
        3. Generates Markdown report
        4. Outputs to file or stdout
        """
        self.print_debug("Starting match summary generation process")
        self.print_trace(
            f"Configuration - Results path: {self.scanoss_results_path}, Output: {self.output}, "
            f"Line range prefix: {self.line_range_prefix}"
        )

        # Load and process scan results into categorized matches
        self.print_trace("Loading and processing scan results")
        matches = self._get_matches_summary()

        # Format matches as GitLab-compatible Markdown
        self.print_trace("Generating Markdown output")
        matches_md = self._markdown(matches)
        if matches_md == "":
            self.print_debug("No matches found - exiting")
            self.print_stdout("No matches found.")
            return

        # Output to file or stdout
        self.print_trace("Writing output")
        if self.output:
            self.print_debug(f"Writing match summary to file: {self.output}")
        else:
            self.print_debug("Writing match summary to 'stdout'")

        self.print_to_file_or_stdout(matches_md, self.output)
        self.print_debug("Match summary generation complete")



