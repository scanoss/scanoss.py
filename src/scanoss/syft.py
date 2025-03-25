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
import os.path
import subprocess
import pkg_resources

from .scanossbase import ScanossBase


class SyftScan(ScanossBase):
    """
    SCANOSS container scanning class
    """

    def __init__(self, debug: bool = False, quiet: bool = False, trace: bool = False, output_file: str = None,
                 scan_output: str = None, timeout: int = 600, syft_command: str = None):
        """
        Initialise SyftScan class
        """
        super().__init__(debug, trace, quiet)
        self.quiet = quiet
        self.debug = debug
        self.trace = trace
        self.timeout = timeout
        self.scan_output = scan_output
        self.syft_command = syft_command if syft_command else 'syft'
        self.output_file = output_file if output_file else 'syft-output.txt'
        self.template = pkg_resources.resource_filename(__name__, "data/syft-purl-text.tmpl")

    def __log_result(self, string, outfile=None):
        """
        Logs result to file or STDOUT
        """
        if not outfile and self.scan_output:
            outfile = self.scan_output
        if outfile:
            with open(outfile, "a") as rf:
                rf.write(string + '\n')
        else:
            print(string)

    def remove_interim_file(self, output_file: str = None):
        """
        Remove the temporary Syft interim file
        :param output_file: filename to remove (optional)
        """
        if not output_file and self.output_file:
            output_file = self.output_file
        if os.path.isfile(output_file):
            try:
                self.print_trace(f'Cleaning temporary syft files...')
                os.remove(output_file)
            except Exception as e:
                self.print_stderr(f'Warning: Failed to remove temporary file {output_file}: {e}')

    def produce_from_file(self, what_to_scan: str, text_file: str = None) -> json:
        """
        Parse input text dependencies file and produce SCANOSS dependency JSON output
        :param what_to_scan: what was scanned (container/folder/package)
        :param text_file:
        :return: SCANOSS dependency JSON
        """
        if not text_file and self.output_file:
            text_file = self.output_file
        if not text_file:
            self.print_stderr('ERROR: No Syft interim file provided to parse.')
            return None
        if not os.path.isfile(text_file):
            self.print_stderr(f'ERROR: Syft file does not exist or is not a file: {text_file}')
            return None
        with open(text_file, 'r') as f:
            return self.produce_from_str(what_to_scan, f.read())

    def produce_from_str(self, what_to_scan: str, purl_str: str) -> dict:
        """
        Parse input text dependencies string and produce SCANOSS dependency JSON output
        :param what_to_scan: what was scanned (container/folder/package)
        :param purl_str: input purl string
        :return: SCANOSS dependency JSON
        """
        if not purl_str:
            self.print_stderr('ERROR: No Syft string provided to parse.')
            return None
        purls = []
        for purl in purl_str.split('\n'):
            purl = purl.strip()
            if not purl.startswith('#'):
                purl = purl.replace('"', '').replace('%22', '')  # remove unwanted quotes on purls
                if len(purl) > 0:
                    purls.append({'purl': purl})
        files = []
        if len(purls) > 0:
            files.append({'file': what_to_scan, 'purls': purls})
        deps = {'files': files}
        self.print_debug(f'Syft Data: {deps}')
        return deps

    def get_dependencies(self, output_file: str = None, what_to_scan: str = None, result_output: str = None) -> bool:
        """
        Get the dependencies for the required container/package/directory and output the JSON results
        :param output_file:  temporary syft file to write interim results to
        :param what_to_scan: file or directory to scan
        :param result_output: output location for parsed JSON dependencies (default: stdout)
        :return: True on success, False otherwise
        """
        self.print_msg('Searching for dependencies...')
        if not self.run_scan(output_file, what_to_scan):
            return False
        self.print_msg('Producing summary...')
        deps = self.produce_from_file(what_to_scan, output_file)
        self.remove_interim_file(output_file)
        if not deps:
            return False
        self.__log_result(json.dumps(deps, indent=2, sort_keys=True), outfile=result_output)
        return True

    def run_scan(self, output_file: str = None, what_to_scan: str = None) -> bool:
        """
        Run a syft scan of the specified target and output the results to temporary file
        :param output_file: temporary syft output filename
        :param what_to_scan: what to scan (container/image, file, folder)
        :return: True on success, False otherwise
        """
        if not output_file and self.output_file:
            output_file = self.output_file
        try:
            open(output_file, 'w').close()
            self.print_trace(f'About to execute {self.syft_command} scan -q -o template="{output_file}" '
                             f'-t "{self.template}" "{what_to_scan}"')
            result = subprocess.run([self.syft_command, 'scan', '-q', '-t', f'{self.template}',
                                     '-o', f'template={output_file}', what_to_scan],
                                    cwd=os.getcwd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=self.timeout
                                    )
            self.print_trace(f'Subprocess return: {result}')
            if result.returncode:
                self.print_stderr(f'ERROR: Syft scan of {what_to_scan} failed with exit code'
                                  f' {result.returncode}:\n{result.stdout}')
                return False
        except subprocess.TimeoutExpired as e:
            self.print_stderr(f'ERROR: Timed out attempting to run syft scan on {what_to_scan}: {e}')
            return False
        except Exception as e:
            self.print_stderr(f'ERROR: Issue running syft scan on {what_to_scan}: {e}')
            return False
        return True

    def load_from_file(self, json_file: str = None) -> json:
        """
        Load the parsed JSON dependencies file and return the json object
        :param json_file: dependency json file
        :return: SCANOSS dependency JSON
        """
        if not json_file:
            self.print_stderr('ERROR: No parsed JSON file provided to load.')
            return None
        if not os.path.isfile(json_file):
            self.print_stderr(f'ERROR: parsed JSON file does not exist or is not a file: {json_file}')
            return None
        with open(json_file, 'r') as f:
            try:
                return json.loads(f.read())
            except Exception as e:
                self.print_stderr(f'ERROR: Problem loading input JSON: {e}')
        return None

#
# End of SyftScan Class
#
