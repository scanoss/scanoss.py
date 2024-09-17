"""
 SPDX-License-Identifier: MIT

   Copyright (c) 2021, SCANOSS

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

from .scanossbase import ScanossBase


class ScancodeDeps(ScanossBase):
    """
    SCANOSS dependency scanning class
    """
    def __init__(self, debug: bool = False, quiet: bool = False, trace: bool = False, output_file: str = None,
                 scan_output: str = None, timeout: int = 600, sc_command: str = None):
        """
        Initialise ScancodeDeps class
        """
        super().__init__(debug, trace, quiet)
        self.quiet = quiet
        self.debug = debug
        self.trace = trace
        self.timeout = timeout
        self.scan_output = scan_output
        self.sc_command = sc_command if sc_command else 'scancode'
        self.output_file = output_file if output_file else 'scancode-dependencies.json'

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
        Remove the temporary Scancode interim file
        :param output_file: filename to remove (optional)
        """
        if not output_file and self.output_file:
            output_file = self.output_file
        if os.path.isfile(output_file):
            try:
                self.print_trace(f'Cleaning temporary scancode files...')
                os.remove(output_file)
            except Exception as e:
                self.print_stderr(f'Warning: Failed to remove temporary file {output_file}: {e}')

    def produce_from_json(self, data: json) -> dict:
        """
        Parse the given input JSON string and return Dependency summary
        :param data: json - JSON object
        :return: Dependency dictionary
        """
        if not data:
            self.print_stderr('ERROR: No JSON data provided to parse.')
            return None
        self.print_debug(f'Processing Scancode results into Dependency data...')
        files = []
        for t in data:
            if t == 'files':    # Only interested in 'files' details
                files_details = data.get(t)
                if not files_details or files_details == '':
                    continue
                # print(f'File: {t}: {file_details}')
                for fd in files_details:
                    # print(f'FD: {fd}')
                    f_path = fd.get('path')
                    if not f_path or f_path == '':
                        continue
                    f_type = fd.get('type')
                    if not f_type or f_type == '' or f_type != 'file':  # Only process files
                        continue
                    f_packages = fd.get('package_data')  # scancode format 2.0
                    if not f_packages or f_packages == '':
                        f_packages = fd.get('packages')  # scancode formate 1.0
                        if not f_packages or f_packages == '':
                            continue
                    self.print_debug(f'Path: {f_path}, Packages: {len(f_packages)}')
                    purls = []
                    scopes = []
                    for pkgs in f_packages:
                        pk_deps = pkgs.get('dependencies')

                        if not pk_deps or pk_deps == '':
                            continue
                        for d in pk_deps:
                            dp = d.get('purl')
                            if not dp or dp == '':
                                continue

                            dp = dp.replace('"', '').replace('%22', '')  # remove unwanted quotes on purls
                            dp_data = {'purl': dp}
                            rq = d.get('extracted_requirement')  # scancode format 2.0
                            if not rq or rq == '':
                                rq = d.get('requirement')        # scancode format 1.0
                            # skip requirement if it ends with the purl (i.e. exact version) or if it's local (file)
                            if rq and rq != '' and not dp.endswith(rq) and not rq.startswith('file:'):
                                dp_data['requirement'] = rq

                            # Gets dependency scope
                            scope = d.get('scope')
                            if scope and scope != '':
                                dp_data['scope'] = scope

                            purls.append(dp_data)
                        # end for loop

                    if len(purls) > 0:
                        files.append({'file': f_path, 'purls': purls})
                    # End packages
                # End file details
        # End dependencies json
        deps = {'files': files}
        return deps

    def produce_from_file(self, json_file: str = None) -> json:
        """
        Parse input JSON dependencies file and produce SCANOSS dependency JSON output
        :param json_file:
        :return: SCANOSS dependency JSON
        """
        if not json_file and self.output_file:
            json_file = self.output_file
        if not json_file:
            self.print_stderr('ERROR: No JSON file provided to parse.')
            return None
        if not os.path.isfile(json_file):
            self.print_stderr(f'ERROR: JSON file does not exist or is not a file: {json_file}')
            return None
        with open(json_file, 'r') as f:
            return self.produce_from_str(f.read())

    def produce_from_str(self, json_str: str) -> dict:
        """
        Parse input JSON dependencies string and produce SCANOSS dependency JSON output
        :param json_str: input JSON string
        :return: SCANOSS dependency JSON
        """
        if not json_str:
            self.print_stderr('ERROR: No JSON string provided to parse.')
            return None
        try:
            data = json.loads(json_str)
        except Exception as e:
            self.print_stderr(f'ERROR: Problem parsing input JSON: {e}')
            return None
        return self.produce_from_json(data)

    def get_dependencies(self, output_file: str = None, what_to_scan: str = None, result_output: str = None) -> bool:
        """
        Get the dependencies for the required file/directory and output the JSON results
        :param output_file:  temporary scanocde file to write interim results to
        :param what_to_scan: file or directory to scan
        :param result_output: output location for parsed JSON dependencies (default: stdout)
        :return: True on success, False otherwise
        """
        self.print_msg('Searching for dependencies...')
        if not self.run_scan(output_file, what_to_scan):
            return False
        self.print_msg('Producing summary...')
        deps = self.produce_from_file(output_file)
        deps = self.__remove_dep_scope(deps)
        self.remove_interim_file(output_file)
        if not deps:
            return False
        self.__log_result(json.dumps(deps, indent=2, sort_keys=True), outfile=result_output)
        return True

    def run_scan(self, output_file: str = None, what_to_scan: str = None) -> bool:
        """
        Run a scan of the specified file/folder and output the results to temporary file
        :param output_file: temporary scancode output filename
        :param what_to_scan: file/directory to scan
        :return: True on success, False otherwise
        """
        if not output_file and self.output_file:
            output_file = self.output_file
        try:
            open(output_file, 'w').close()
            self.print_trace(f'About to execute {self.sc_command} -p --only-findings --quiet --json {output_file}'
                             f' {what_to_scan}')
            result = subprocess.run([self.sc_command, '-p', '--only-findings', '--quiet', '--strip-root', '--json',
                                     output_file, what_to_scan],
                                    cwd=os.getcwd(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, timeout=self.timeout
                                    )
            self.print_trace(f'Subprocess return: {result}')
            if result.returncode:
                self.print_stderr(f'ERROR: Scancode dependency scan of {what_to_scan} failed with exit code'
                                  f' {result.returncode}:\n{result.stdout}')
                return False
        except subprocess.TimeoutExpired as e:
            self.print_stderr(f'ERROR: Timed out attempting to run scancode dependency scan on {what_to_scan}: {e}')
            return False
        except Exception as e:
            self.print_stderr(f'ERROR: Issue running scancode dependency scan on {what_to_scan}: {e}')
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


    @staticmethod
    def __remove_dep_scope(deps: json)->json:
        """
        :param deps: dependencies with scopes
        :return dependencies without scopes
        """
        files = deps.get("files")
        for file in files:
            if 'purls' in file:
                purls = file.get("purls")
                for purl in purls:
                    purl.pop("scope",None)

        return {"files": files }

#
# End of ScancodeDeps Class
#
