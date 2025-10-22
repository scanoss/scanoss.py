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
    file_url: str
    license: str
    similarity: str
    purl: str
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
        super().__init__(debug, trace, quiet)
        self.scanoss_results_path = scanoss_results_path
        self.line_range_prefix = line_range_prefix
        self.output = output

    @staticmethod
    def _get_lines(lines: str) -> list:
        """
        Parse line range string into a list of line numbers.

        Converts SCANOSS line notation (e.g., '10-20,25-30') into a flat list
        of individual line numbers for processing.

        :param lines: Comma-separated line ranges in SCANOSS format (e.g., '10-20,25-30')
        :return: Flat list of all line numbers extracted from the ranges
        """
        lineArray = []
        lines = lines.split(',')
        for line in lines:
            line_parts = line.split('-')
            for part in line_parts:
                lineArray.append(int(part))
        return lineArray


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
        if result.get('id') == "snippet":
            # Snippet match: create URL with line range anchor
            lines = self._get_lines(result.get('lines'))
            end_line = lines[len(lines) - 1] if len(lines) > 1 else lines[0]
            file_url = f"{self.line_range_prefix}/{file_name}#L{lines[0]}-L{end_line}"
            return MatchSummaryItem(
                file_url=file_url,
                license=result.get('licenses')[0].get('name'),
                similarity=result.get('matched'),
                purl=result.get('purl')[0],
                version=result.get('version'),
                lines=f"{lines[0]}-{lines[len(lines) - 1] if len(lines) > 1 else lines[0]}"
            )
        # File match: create URL without line range
        return MatchSummaryItem(
            file_url=f"{self.line_range_prefix}/{file_name}",
            license=result.get('licenses')[0].get('name'),
            similarity=result.get('matched'),
            purl=result.get('purl')[0],
            version=result.get('version'),
            lines="all"
        )

    def _get_matches_summary(self) -> ComponentMatchSummary:
        """
        Parse SCANOSS scan results and create categorized match summaries.

        Loads the SCANOSS scan results file and processes each match, validating
        required fields and categorizing matches into file matches and snippet matches.
        Skips invalid or incomplete results with debug messages.
        """
        # Load scan results from JSON file
        scan_results = load_json_file(self.scanoss_results_path)
        gitlab_matches_summary = ComponentMatchSummary(files=[], snippet=[])

        # Process each file and its results
        for file_name, results in scan_results.items():
            for result in results:
                # Validate required fields - skip invalid results with debug messages
                if not result.get('id'):
                    self.print_debug(f'ERROR: No id found for file {file_name}')
                    continue
                if result.get('id') == "none":  # Skip non-matches
                    continue
                if not result.get('lines'):
                    self.print_debug(f'ERROR: No lines found for file {file_name}')
                    continue
                if not result.get('purl'):
                    self.print_debug(f'ERROR: No purl found for file {file_name}')
                    continue
                if not len(result.get('purl')) > 0:
                    self.print_debug(f'ERROR: No purl found for file {file_name}')
                    continue
                if not result.get('licenses'):
                    self.print_debug(f'ERROR: No licenses found for file {file_name}')
                    continue
                if not result.get('version'):
                    self.print_debug(f'ERROR: No version found for file {file_name}')
                    continue
                if not result.get('matched'):
                    self.print_debug(f'ERROR: No matched found for file {file_name}')
                    continue

                # Create summary item and categorize by match type
                summary_item = self._get_match_summary_item(file_name, result)
                if result.get('id') == "snippet":
                    gitlab_matches_summary.snippet.append(summary_item)
                else:
                    gitlab_matches_summary.files.append(summary_item)

        return gitlab_matches_summary


    def _markdown(self, gitlab_matches_summary: ComponentMatchSummary) -> str:
        """
        Generate Markdown from match summaries.

        Creates a formatted Markdown document with collapsible sections for file
        and snippet matches.

        :param gitlab_matches_summary: Container with categorized file and snippet matches to format
        :return: Complete Markdown document with formatted match tables
        """
        # Define table headers
        headers = ['File', 'License', 'Similarity', 'PURL', 'Version', 'Lines']

        # Build file matches table
        file_match_rows = []
        for file in gitlab_matches_summary.files:
            row = [
                file.file_url,
                file.license,
                file.similarity,
                file.purl,
                file.version,
                file.lines
            ]
            file_match_rows.append(row)
        file_match_table = generate_table(headers, file_match_rows)

        # Build snippet matches table
        snippet_match_rows = []
        for file in gitlab_matches_summary.snippet:
            row = [
                file.file_url,
                file.license,
                file.similarity,
                file.purl,
                file.version,
                file.lines
            ]
            snippet_match_rows.append(row)
        snippet_match_table = generate_table(headers, snippet_match_rows)

        # Assemble complete Markdown document
        markdown = ""
        markdown += "### SCANOSS Matches Summary\n\n"

        # File matches section (collapsible)
        markdown += "<details>\n"
        markdown += "<summary>File Matches Summary</summary>\n\n"
        markdown += file_match_table
        markdown += "\n</details>\n"

        # Snippet matches section (collapsible)
        markdown += "<details>\n"
        markdown += "<summary>Snippet Matches Summary</summary>\n\n"
        markdown += snippet_match_table
        markdown += "\n</details>\n"

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
        # Load and process scan results into categorized matches
        matches = self._get_matches_summary()

        # Format matches as GitLab-compatible Markdown
        matches_md = self._markdown(matches)

        # Output to file or stdout
        self.print_to_file_or_stdout(matches_md, self.output)



