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
import os
import sys
import datetime
import pkg_resources

from progress.bar import Bar
from progress.spinner import Spinner

from .scanossapi import ScanossApi
from .winnowing import Winnowing
from .cyclonedx import CycloneDx
from .spdxlite import SpdxLite
from .csvoutput import CsvOutput
from .threadedscanning import ThreadedScanning
from .scancodedeps import ScancodeDeps
from .threadeddependencies import ThreadedDependencies
from .scanossgrpc import ScanossGrpc
from .scantype import ScanType
from .scanossbase import ScanossBase

from . import __version__

FILTERED_DIRS = {  # Folders to skip
                 "nbproject", "nbbuild", "nbdist", "__pycache__", "venv", "_yardoc", "eggs", "wheels", "htmlcov",
                "__pypackages__"
                 }
FILTERED_DIR_EXT = { # Folder endings to skip
                    ".egg-info"
                   }
FILTERED_EXT = {  # File extensions to skip
                ".1", ".2", ".3", ".4", ".5", ".6", ".7", ".8", ".9", ".ac", ".adoc", ".am",
                ".asciidoc", ".bmp", ".build", ".cfg", ".chm", ".class", ".cmake", ".cnf",
                ".conf", ".config", ".contributors", ".copying", ".crt", ".csproj", ".css",
                ".csv", ".dat", ".data", ".doc", ".docx", ".dtd", ".dts", ".iws", ".c9", ".c9revisions",
                ".dtsi", ".dump", ".eot", ".eps", ".geojson", ".gdoc", ".gif",
                ".glif", ".gmo", ".gradle", ".guess", ".hex", ".htm", ".html", ".ico", ".iml",
                ".in", ".inc", ".info", ".ini", ".ipynb", ".jpeg", ".jpg", ".json", ".jsonld", ".lock",
                ".log", ".m4", ".map", ".markdown", ".md", ".md5", ".meta", ".mk", ".mxml",
                ".o", ".otf", ".out", ".pbtxt", ".pdf", ".pem", ".phtml", ".plist", ".png",
                ".po", ".ppt", ".prefs", ".properties", ".pyc", ".qdoc", ".result", ".rgb",
                ".rst", ".scss", ".sha", ".sha1", ".sha2", ".sha256", ".sln", ".spec", ".sql",
                ".sub", ".svg", ".svn-base", ".tab", ".template", ".test", ".tex", ".tiff",
                ".toml", ".ttf", ".txt", ".utf-8", ".vim", ".wav", ".whl", ".woff", ".xht",
                ".xhtml", ".xls", ".xlsx", ".xml", ".xpm", ".xsd", ".xul", ".yaml", ".yml", ".wfp",
                ".editorconfig", ".dotcover", ".pid", ".lcov", ".egg", ".manifest", ".cache", ".coverage", ".cover",
                ".gem", ".lst", ".pickle", ".pdb", ".gml", ".pot", ".plt",
                # File endings
                "-doc", "changelog", "config", "copying", "license", "authors", "news",
                "licenses", "notice",
                "readme", "swiftdoc", "texidoc", "todo", "version", "ignore", "manifest", "sqlite", "sqlite3"
                }
FILTERED_FILES = {  # Files to skip
                    "gradlew", "gradlew.bat", "mvnw", "mvnw.cmd", "gradle-wrapper.jar", "maven-wrapper.jar",
                    "thumbs.db", "babel.config.js",
                    "license.txt", "license.md", "copying.lib", "makefile"
                }
WFP_FILE_START = "file="
MAX_POST_SIZE = 64 * 1024  # 64k Max post size


class Scanner(ScanossBase):
    """
    SCANOSS scanning class
    Handle the scanning of files, snippets and dependencies
    """
    def __init__(self, wfp: str = None, scan_output: str = None, output_format: str = 'plain',
                 debug: bool = False, trace: bool = False, quiet: bool = False, api_key: str = None, url: str = None,
                 sbom_path: str = None, scan_type: str = None, flags: str = None, nb_threads: int = 5,
                 post_size: int = 64, timeout: int = 120, no_wfp_file: bool = False,
                 all_extensions: bool = False, all_folders: bool = False, hidden_files_folders: bool = False,
                 scan_options: int = 7, sc_timeout: int = 600, sc_command: str = None, grpc_url: str = None,
                 obfuscate: bool = False, ignore_cert_errors: bool = False, proxy: str = None, ca_cert: str = None
                 ):
        """
        Initialise scanning class, including Winnowing, ScanossApi and ThreadedScanning
        """
        super().__init__(debug, trace, quiet)
        self.wfp = wfp if wfp else "scanner_output.wfp"
        self.scan_output = scan_output
        self.output_format = output_format
        self.no_wfp_file = no_wfp_file
        self.isatty = sys.stderr.isatty()
        self.all_extensions = all_extensions
        self.all_folders = all_folders
        self.hidden_files_folders = hidden_files_folders
        self.scan_options = scan_options
        self._skip_snippets = True if not scan_options & ScanType.SCAN_SNIPPETS.value else False
        ver_details = self.__version_details()

        self.winnowing = Winnowing(debug=debug, quiet=quiet, skip_snippets=self._skip_snippets,
                                   all_extensions=all_extensions, obfuscate=obfuscate
                                   )
        self.scanoss_api = ScanossApi(debug=debug, trace=trace, quiet=quiet, api_key=api_key, url=url,
                                      sbom_path=sbom_path, scan_type=scan_type, flags=flags, timeout=timeout,
                                      ver_details=ver_details, ignore_cert_errors=ignore_cert_errors,
                                      proxy=proxy, ca_cert=ca_cert
                                      )
        sc_deps = ScancodeDeps(debug=debug, quiet=quiet, trace=trace, timeout=sc_timeout, sc_command=sc_command)
        grpc_api = ScanossGrpc(url=grpc_url, debug=debug, quiet=quiet, trace=trace, api_key=api_key,
                               ver_details=ver_details, ca_cert=ca_cert
                               )
        self.threaded_deps = ThreadedDependencies(sc_deps, grpc_api, debug=debug, quiet=quiet, trace=trace)
        self.nb_threads = nb_threads
        if nb_threads and nb_threads > 0:
            self.threaded_scan = ThreadedScanning(self.scanoss_api, debug=debug, trace=trace, quiet=quiet,
                                                  nb_threads=nb_threads
                                                  )
        else:
            self.threaded_scan = None
        self.max_post_size = post_size * 1024 if post_size > 0 else MAX_POST_SIZE  # Set the max post size (default 64k)
        if self._skip_snippets:
            self.max_post_size = 8 * 1024          # 8k Max post size if we're skipping snippets

    def __filter_files(self, files: list) -> list:
        """
        Filter which files should be considered for processing
        :param files: list of files to filter
        :return list of filtered files
        """
        file_list = []
        for f in files:
            ignore = False
            if f.startswith(".") and not self.hidden_files_folders:  # Ignore all . files unless requested
                ignore = True
            if not ignore and not self.all_extensions:  # Skip this check if we're allowing all extensions
                f_lower = f.lower()
                if f_lower in FILTERED_FILES:           # Check for exact files to ignore
                    ignore = True
                if not ignore:
                    for ending in FILTERED_EXT:         # Check for file endings to ignore
                        if f_lower.endswith(ending):
                            ignore = True
                            break
            if not ignore:
                file_list.append(f)
        return file_list

    def __filter_dirs(self, dirs: list) -> list:
        """
        Filter which folders should be considered for processing
        :param dirs: list of directories to filter
        :return: list of filtered directories
        """
        dir_list = []
        for d in dirs:
            ignore = False
            if d.startswith(".") and not self.hidden_files_folders: # Ignore all . folders unless requested
                ignore = True
            if not ignore and not self.all_folders: # Skip this check if we're allowing all folders
                d_lower = d.lower()
                if d_lower in FILTERED_DIRS:      # Ignore specific folders
                    ignore = True
                if not ignore:
                    for de in FILTERED_DIR_EXT:   # Ignore specific folder endings
                        if d_lower.endswith(de):
                            ignore = True
                            break
            if not ignore:
                dir_list.append(d)
        return dir_list

    @staticmethod
    def __strip_dir(scan_dir: str, length: int, path: str) -> str:
        """
        Strip the leading string from the specified path
        Parameters
        ----------
            scan_dir: str
                Root path
            length: int
                length of the root path string
            path: str
                Path to strip
        """
        if length > 0 and path.startswith(scan_dir):
            path = path[length:]
        return path

    @staticmethod
    def __count_files_in_wfp_file(wfp_file: str):
        """
        Count the number of files in the WFP that need to be processed
        Parameters
        ----------
            wfp_file: str
                WFP file to process
        """
        count = 0
        if wfp_file:
            with open(wfp_file) as f:
                for line in f:
                    if WFP_FILE_START in line:
                        count += 1
        return count

    @staticmethod
    def valid_json_file(json_file: str) -> bool:
        """
        Validate if the specified file is indeed valid JSON
        :param: str JSON file to load
        :return bool True if valid, False otherwise
        """
        if not json_file:
            self.print_stderr('ERROR: No JSON file provided to parse.')
            return False
        if not os.path.isfile(json_file):
            self.print_stderr(f'ERROR: JSON file does not exist or is not a file: {json_file}')
            return False
        try:
            with open(json_file) as f:
                data = json.load(f)
        except Exception as e:
            Scanner.print_stderr(f'Problem parsing JSON file "{json_file}": {e}')
            return False
        return True

    @staticmethod
    def __version_details() -> str:
        """
        Extract the date this version was produced
        :return: version creation date string
        """
        data = None
        try:
            f_name = pkg_resources.resource_filename(__name__, 'data/build_date.txt')
            with open(f_name, 'r') as f:
                data = f.read().rstrip()
        except Exception as e:
            Scanner.print_stderr(f'Warning: Problem loading build time details: {e}')
        if not data or len(data) == 0:
            now = datetime.datetime.now()
            data = f'date: {now.strftime("%Y%m%d%H%M%S")}, utime: {int(now.timestamp())}'
        return f'tool: scanoss-py, version: {__version__}, {data}'


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

    def is_file_or_snippet_scan(self):
        """
        Check if file or snippet scanning is enabled
        :return: True if enabled, False otherwise
        """
        if self.is_file_scan() or self.is_snippet_scan():
            return True
        return False

    def is_file_scan(self):
        """
        Check if file scanning is enabled
        :return: True if enabled, False otherwise
        """
        if self.scan_options & ScanType.SCAN_FILES.value:
            return True
        return False

    def is_snippet_scan(self):
        """
        Check if snippet scanning is enabled
        :return: True if enabled, False otherwise
        """
        if self.scan_options & ScanType.SCAN_SNIPPETS.value:
            return True
        return False

    def is_dependency_scan(self):
        """
        Check if dependency scanning is enabled
        :return: True if enabled, False otherwise
        """
        if self.scan_options & ScanType.SCAN_DEPENDENCIES.value:
            return True
        return False

    def scan_folder_with_options(self, scan_dir: str, file_map: dict = None) -> bool:
        """
        Scan the given folder for whatever scaning options that have been configured
        :param scan_dir: directory to scan
        :param file_map: mapping of obfuscated files back into originals
        :return: True if successful, False otherwise
        """
        success = True
        if not scan_dir:
            raise Exception(f"ERROR: Please specify a folder to scan")
        if not os.path.exists(scan_dir) or not os.path.isdir(scan_dir):
            raise Exception(f"ERROR: Specified folder does not exist or is not a folder: {scan_dir}")
        if not self.is_file_or_snippet_scan() and not self.is_dependency_scan():
            raise Exception(f"ERROR: No scan options defined to scan folder: {scan_dir}")

        if self.scan_output:
            self.print_msg(f'Writing results to {self.scan_output}...')
        if self.is_dependency_scan():
            if not self.threaded_deps.run(what_to_scan=scan_dir, wait=False):  # Kick off a background dependency scan
                success = False
        if self.is_file_or_snippet_scan():
            if not self.scan_folder(scan_dir):
                success = False
        if self.threaded_scan:
            if not self.__finish_scan_threaded(file_map):
                success = False
        return success

    def scan_folder(self, scan_dir: str) -> bool:
        """
        Scan the specified folder producing fingerprints, send to the SCANOSS API and return results

        :param scan_dir: str
                    Directory to scan
        :return True if successful, False otherwise
        """
        success = True
        if not scan_dir:
            raise Exception(f"ERROR: Please specify a folder to scan")
        if not os.path.exists(scan_dir) or not os.path.isdir(scan_dir):
            raise Exception(f"ERROR: Specified folder does not exist or is not a folder: {scan_dir}")

        scan_dir_len = len(scan_dir) if scan_dir.endswith(os.path.sep) else len(scan_dir)+1
        self.print_msg(f'Searching {scan_dir} for files to fingerprint...')
        spinner = None
        if not self.quiet and self.isatty:
            spinner = Spinner('Fingerprinting ')
        wfp_list = []
        scan_block = ''
        scan_size = 0
        queue_size = 0
        file_count = 0
        scan_started = False
        for root, dirs, files in os.walk(scan_dir):
            self.print_trace(f'U Root: {root}, Dirs: {dirs}, Files {files}')
            dirs[:] = self.__filter_dirs(dirs)                             # Strip out unwanted directories
            filtered_files = self.__filter_files(files)                    # Strip out unwanted files
            self.print_debug(f'F Root: {root}, Dirs: {dirs}, Files {filtered_files}')
            for file in filtered_files:                                       # Cycle through each filtered file
                path = os.path.join(root, file)
                f_size = 0
                try:
                    f_size = os.stat(path).st_size
                except Exception as e:
                    self.print_trace(f'Ignoring missing symlink file: {file} ({e})') # Can fail if there is a broken symlink
                if f_size > 0:                                                 # Ignore broken links and empty files
                    self.print_trace(f'Fingerprinting {path}...')
                    if spinner:
                        spinner.next()
                    wfp = self.winnowing.wfp_for_file(path, Scanner.__strip_dir(scan_dir, scan_dir_len, path))
                    wfp_list.append(wfp)
                    file_count += 1
                    if self.threaded_scan:
                        wfp_size = len(wfp.encode("utf-8"))
                        if (wfp_size + scan_size) >= self.max_post_size:
                            self.threaded_scan.queue_add(scan_block)
                            queue_size += 1
                            scan_block = ''
                        scan_block += wfp
                        scan_size = len(scan_block.encode("utf-8"))
                        if scan_size >= self.max_post_size:
                            self.threaded_scan.queue_add(scan_block)
                            queue_size += 1
                            scan_block = ''
                        if queue_size > self.nb_threads and not scan_started: # Start scanning if we have something to do
                            scan_started = True
                            if not self.threaded_scan.run(wait=False):
                                self.print_stderr(
                                    f'Warning: Some errors encounted while scanning. Results might be incomplete.')
                                success = False
        # End for loop
        if self.threaded_scan and scan_block:
            self.threaded_scan.queue_add(scan_block)  # Make sure all files have been submitted
        if spinner:
            spinner.finish()

        if wfp_list:
            if not self.no_wfp_file or not self.threaded_scan:  # Write a WFP file if no threading or not not requested
                self.print_debug(f'Writing fingerprints to {self.wfp}')
                with open(self.wfp, 'w') as f:
                    f.write(''.join(wfp_list))
            else:
                self.print_debug( f'Skipping writing WFP file {self.wfp}')
            wfp_list = None
            if self.threaded_scan:
                success = self.__run_scan_threaded(scan_started, file_count)
        else:
            Scanner.print_stderr(f'Warning: No files found to scan in folder: {scan_dir}')
        return success

    def __run_scan_threaded(self, scan_started: bool, file_count: int) -> bool:
        """
        Finish scanning the filtered files and but do not wait for it to complete
        :param scan_started: If the scan has already started or not
        :param file_count:  Number of total files to be scanned
        :return: True if successful, False otherwise
        """
        success = True
        self.threaded_scan.update_bar(create=True, file_count=file_count)
        if not scan_started:
            if not self.threaded_scan.run(wait=False):           # Run the scan but do not wait for it to complete
                self.print_stderr(f'Warning: Some errors encounted while scanning. Results might be incomplete.')
                success = False
        return success

    def __finish_scan_threaded(self, file_map: dict = None) -> bool:
        """
        Wait for the threaded scans to complete
        :param file_map: mapping of obfuscated files back into originals
        :return: True if successful, False otherwise
        """
        success = True
        responses = None
        dep_responses = None
        if self.is_file_or_snippet_scan():
            if not self.threaded_scan.complete():               # Wait for the scans to complete
                self.print_stderr(f'Warning: Scanning analysis ran into some trouble.')
                success = False
            self.threaded_scan.complete_bar()
            responses = self.threaded_scan.responses
        if self.is_dependency_scan():
            self.print_msg('Retrieving dependency data...')
            if not self.threaded_deps.complete():
                self.print_stderr(f'Warning: Dependency analysis ran into some trouble.')
                success = False
            dep_responses = self.threaded_deps.responses
            # self.print_stderr(f'Dep Data: {dep_responses}')
        # TODO change to dictionary
        raw_output = "{\n"
        # TODO look into merging the two dictionaries. See https://favtutor.com/blogs/merge-dictionaries-python
        if responses or dep_responses:
            first = True
            if responses:
                for scan_resp in responses:
                    if scan_resp is not None:
                        for key, value in scan_resp.items():
                            if file_map:  # We have a map for obfuscated files. Check if we can revert it
                                fm = file_map.get(key)
                                if fm:
                                    key = fm  # Replace the obfuscated filename
                            if first:
                                raw_output += "  \"%s\":%s" % (key, json.dumps(value, indent=2))
                                first = False
                            else:
                                raw_output += ",\n  \"%s\":%s" % (key, json.dumps(value, indent=2))
                # End for loop
            if dep_responses:
                dep_files = dep_responses.get("files")
                if dep_files and len(dep_files) > 0:
                    for dep_file in dep_files:
                        file = dep_file.pop("file", None)
                        if file is not None:
                            if first:
                                raw_output += "  \"%s\":[%s]" % (file, json.dumps(dep_file, indent=2))
                                first = False
                            else:
                                raw_output += ",\n  \"%s\":[%s]" % (file, json.dumps(dep_file, indent=2))
                    # End for loop
        else:
            success = False
        raw_output += "\n}"
        parsed_json = None
        try:
            parsed_json = json.loads(raw_output)
        except Exception as e:
            self.print_stderr(f'Warning: Problem decoding parsed json: {e}')

        if self.output_format == 'plain':
            if parsed_json:
                self.__log_result(json.dumps(parsed_json, indent=2, sort_keys=True))
            else:
                self.__log_result(raw_output)
        elif self.output_format == 'cyclonedx':
            cdx = CycloneDx(self.debug, self.scan_output)
            if parsed_json:
                success = cdx.produce_from_json(parsed_json)
            else:
                success = cdx.produce_from_str(raw_output)
        elif self.output_format == 'spdxlite':
            spdxlite = SpdxLite(self.debug, self.scan_output)
            if parsed_json:
                success = spdxlite.produce_from_json(parsed_json)
            else:
                success = spdxlite.produce_from_str(raw_output)
        elif self.output_format == 'csv':
                csvo = CsvOutput(self.debug, self.scan_output)
                if parsed_json:
                    success = csvo.produce_from_json(parsed_json)
                else:
                    success = csvo.produce_from_str(raw_output)
        else:
            self.print_stderr(f'ERROR: Unknown output format: {self.output_format}')
            success = False
        return success


    def scan_file_with_options(self, file: str, file_map: dict = None) -> bool:
        """
        Scan the given file for whatever scaning options that have been configured
        :param file: file to scan
        :param file_map: mapping of obfuscated files back into originals
        :return: True if successful, False otherwise
        """
        success = True
        if not file:
            raise Exception(f"ERROR: Please specify a file to scan")
        if not os.path.exists(file) or not os.path.isfile(file):
            raise Exception(f"ERROR: Specified file does not exist or is not a file: {file}")
        if not self.is_file_or_snippet_scan() and not self.is_dependency_scan():
            raise Exception(f"ERROR: No scan options defined to scan file: {file}")

        if self.scan_output:
            self.print_msg(f'Writing results to {self.scan_output}...')
        if self.is_dependency_scan():
            if not self.threaded_deps.run(what_to_scan=file, wait=False):  # Kick off a background dependency scan
                success = False
        if self.is_file_or_snippet_scan():
            if not self.scan_file(file):
                success = False
        if self.threaded_scan:
            if not self.__finish_scan_threaded(file_map):
                success = False
        return success


    def scan_file(self, file: str) -> bool:
        """
        Scan the specified file and produce a result
        Parameters
        ----------
            file: str
                File to fingerprint and scan/identify
        :return True if successful, False otherwise
        """
        success = True
        if not file:
            raise Exception(f"ERROR: Please specify a file to scan")
        if not os.path.exists(file) or not os.path.isfile(file):
            raise Exception(f"ERROR: Specified files does not exist or is not a file: {file}")
        self.print_debug(f'Fingerprinting {file}...')
        wfp = self.winnowing.wfp_for_file(file, file)
        if wfp:
            if self.threaded_scan:
                self.threaded_scan.queue_add(wfp)  # Submit the WFP for scanning
            self.print_debug(f'Scanning {file}...')
            if self.threaded_scan:
                success = self.__run_scan_threaded(False, 1)
        else:
            success = False
        return success

    def scan_wfp_file(self, file: str = None) -> bool:
        """
        Scan the contents of the specified WFP file (in the current process)
        Parameters
        ----------
            file: str
                WFP file to scan (optional)
        return: True if successful, False otherwise
        """
        success = True
        wfp_file = file if file else self.wfp   # If a WFP file is specified, use it, otherwise us the default
        if not os.path.exists(wfp_file) or not os.path.isfile(wfp_file):
            raise Exception(f"ERROR: Specified WFP file does not exist or is not a file: {wfp_file}")
        file_count = Scanner.__count_files_in_wfp_file(wfp_file)
        cur_files = 0
        cur_size = 0
        batch_files = 0
        wfp = ''
        max_component = {'name': '', 'hits': 0}
        components = {}
        self.print_debug(f'Found {file_count} files to process.')
        raw_output = "{\n"
        file_print = ''
        bar = None
        if not self.quiet and self.isatty:
            bar = Bar('Scanning', max=file_count)
            bar.next(0)
        with open(wfp_file) as f:
            for line in f:
                if line.startswith(WFP_FILE_START):
                    if file_print:
                        wfp += file_print         # Store the WFP for the current file
                        cur_size = len(wfp.encode("utf-8"))
                    file_print = line             # Start storing the next file
                    cur_files += 1
                    batch_files += 1
                else:
                    file_print += line             # Store the rest of the WFP for this file
                l_size = cur_size + len(file_print.encode('utf-8'))
                # Hit the max post size, so sending the current batch and continue processing
                if l_size >= self.max_post_size and wfp:
                    self.print_debug(f'Sending {batch_files} ({cur_files}) of'
                                     f' {file_count} ({len(wfp.encode("utf-8"))} bytes) files to the ScanOSS API.')
                    if self.debug and cur_size > self.max_post_size:
                        Scanner.print_stderr(f'Warning: Post size {cur_size} greater than limit {self.max_post_size}')
                    scan_resp = self.scanoss_api.scan(wfp, max_component['name'])  # Scan current WFP and store
                    if bar:
                        bar.next(batch_files)
                    if scan_resp is not None:
                        for key, value in scan_resp.items():
                            raw_output += "  \"%s\":%s," % (key, json.dumps(value, indent=2))
                            for v in value:
                                if hasattr(v, 'get'):
                                    if v.get('id') != 'none':
                                        vcv = '%s:%s:%s' % (v.get('vendor'), v.get('component'), v.get('version'))
                                        components[vcv] = components[vcv] + 1 if vcv in components else 1
                                        if max_component['hits'] < components[vcv]:
                                            max_component['name'] = v.get('component')
                                            max_component['hits'] = components[vcv]
                                else:
                                    Scanner.print_stderr(f'Warning: Unknown value: {v}')
                    else:
                        success = False
                    batch_files = 0
                    wfp = ''
        if file_print:
            wfp += file_print  # Store the WFP for the current file
        if wfp:
            self.print_debug(f'Sending {batch_files} ({cur_files}) of'
                             f' {file_count} ({len(wfp.encode("utf-8"))} bytes) files to the ScanOSS API.')
            scan_resp = self.scanoss_api.scan(wfp, max_component['name'])  # Scan current WFP and store
            if bar:
                bar.next(batch_files)
            first = True
            if scan_resp is not None:
                for key, value in scan_resp.items():
                    if first:
                        raw_output += "  \"%s\":%s" % (key, json.dumps(value, indent=2))
                        first = False
                    else:
                        raw_output += ",\n  \"%s\":%s" % (key, json.dumps(value, indent=2))
            else:
                success = False
        raw_output += "\n}"
        if bar:
            bar.finish()
        if self.output_format == 'plain':
            self.__log_result(raw_output)
        elif self.output_format == 'cyclonedx':
            cdx = CycloneDx(self.debug, self.scan_output)
            cdx.produce_from_str(raw_output)
        elif self.output_format == 'spdxlite':
            spdxlite = SpdxLite(self.debug, self.scan_output)
            success = spdxlite.produce_from_str(raw_output)
        elif self.output_format == 'csv':
            csvo = CsvOutput(self.debug, self.scan_output)
            csvo.produce_from_str(raw_output)
        else:
            self.print_stderr(f'ERROR: Unknown output format: {self.output_format}')
            success = False

        return success

    def scan_wfp_file_threaded(self, file: str = None, file_map: dict = None) -> bool:
        """
        Scan the contents of the specified WFP file (threaded)
        :param file: WFP file to scan (optional)
        :param file_map: mapping of obfuscated files back into originals (optional)
        return: True if successful, False otherwise
        """
        success = True
        wfp_file = file if file else self.wfp   # If a WFP file is specified, use it, otherwise us the default
        if not os.path.exists(wfp_file) or not os.path.isfile(wfp_file):
            raise Exception(f"ERROR: Specified WFP file does not exist or is not a file: {wfp_file}")
        cur_size = 0
        scan_size = 0
        queue_size = 0
        file_count = 0
        scan_started = False
        wfp = ''
        scan_block = ''
        with open(wfp_file) as f:   # Parse the WFP file
            for line in f:
                if line.startswith(WFP_FILE_START):
                    if scan_block:
                        wfp += scan_block         # Store the WFP for the current file
                        cur_size = len(wfp.encode("utf-8"))
                    scan_block = line             # Start storing the next file
                    file_count += 1
                else:
                    scan_block += line             # Store the rest of the WFP for this file
                l_size = cur_size + len(scan_block.encode('utf-8'))
                # Hit the max post size, so sending the current batch and continue processing
                if l_size >= self.max_post_size and wfp:
                    if self.debug and cur_size > self.max_post_size:
                        Scanner.print_stderr(f'Warning: Post size {cur_size} greater than limit {self.max_post_size}')
                    self.threaded_scan.queue_add(wfp)
                    queue_size += 1
                    wfp = ''
                    if queue_size > self.nb_threads and not scan_started:  # Start scanning if we have something to do
                        scan_started = True
                        if not self.threaded_scan.run(wait=False):
                            self.print_stderr(
                                        f'Warning: Some errors encounted while scanning. Results might be incomplete.')
                            success = False
            # End for loop
        if scan_block:
            wfp += scan_block  # Store the WFP for the current file
        if wfp:
            self.threaded_scan.queue_add(wfp)
            queue_size += 1

        if not self.__run_scan_threaded(scan_started, file_count):
            success = False
        elif not self.__finish_scan_threaded(file_map):
            success = False
        return success

    def scan_wfp(self, wfp: str) -> bool:
        """
        Send the specified (single) WFP to ScanOSS for identification
        Parameters
        ----------
            wfp: str
                Winnowing Fingerprint to scan/identify
        """
        success = True
        if not wfp:
            raise Exception(f"ERROR: Please specify a WFP to scan")
        raw_output = "{\n"
        scan_resp = self.scanoss_api.scan(wfp)
        if scan_resp is not None:
            for key, value in scan_resp.items():
                raw_output += "  \"%s\":%s" % (key, json.dumps(value, indent=2))
        else:
            success = False
        raw_output += "\n}"
        if self.output_format == 'plain':
            self.__log_result(raw_output)
        elif self.output_format == 'cyclonedx':
            cdx = CycloneDx(self.debug, self.scan_output)
            cdx.produce_from_str(raw_output)
        elif self.output_format == 'spdxlite':
            spdxlite = SpdxLite(self.debug, self.scan_output)
            success = spdxlite.produce_from_str(raw_output)
        elif self.output_format == 'csv':
            csvo = CsvOutput(self.debug, self.scan_output)
            csvo.produce_from_str(raw_output)
        else:
            self.print_stderr(f'ERROR: Unknown output format: {self.output_format}')
            success = False

        return success

    def wfp_file(self, scan_file: str, wfp_file: str = None):
        """
        Fingerprint the specified file
        """
        if not scan_file:
            raise Exception(f"ERROR: Please specify a file to fingerprint")
        if not os.path.exists(scan_file) or not os.path.isfile(scan_file):
            raise Exception(f"ERROR: Specified file does not exist or is not a file: {scan_file}")

        self.print_debug(f'Fingerprinting {scan_file}...')
        wfp = self.winnowing.wfp_for_file(scan_file, scan_file)
        if wfp:
            if wfp_file:
                self.print_stderr(f'Writing fingerprints to {wfp_file}')
                with open(wfp_file, 'w') as f:
                    f.write(wfp)
            else:
                print(wfp)
        else:
            Scanner.print_stderr(f'Warning: No fingerprints generated for: {scan_file}')

    def wfp_folder(self, scan_dir: str, wfp_file: str = None):
        """
        Fingerprint the specified folder producing fingerprints
        """
        if not scan_dir:
            raise Exception(f"ERROR: Please specify a folder to fingerprint")
        if not os.path.exists(scan_dir) or not os.path.isdir(scan_dir):
            raise Exception(f"ERROR: Specified folder does not exist or is not a folder: {scan_dir}")
        wfps = ''
        scan_dir_len = len(scan_dir) if scan_dir.endswith(os.path.sep) else len(scan_dir)+1
        self.print_msg(f'Searching {scan_dir} for files to fingerprint...')
        for root, dirs, files in os.walk(scan_dir):
            dirs[:] = self.__filter_dirs(dirs)                             # Strip out unwanted directories
            filtered_files = self.__filter_files(files)                    # Strip out unwanted files
            self.print_trace(f'Root: {root}, Dirs: {dirs}, Files {filtered_files}')
            for file in filtered_files:
                path = os.path.join(root, file)
                f_size = 0
                try:
                    f_size = os.stat(path).st_size
                except Exception as e:
                    self.print_trace(f'Ignoring missing symlink file: {file} ({e})') # Can fail if there is a broken symlink
                if f_size > 0:            # Ignore empty files
                    self.print_debug(f'Fingerprinting {path}...')
                    wfps += self.winnowing.wfp_for_file(path, Scanner.__strip_dir(scan_dir, scan_dir_len, path))
        if wfps:
            if wfp_file:
                self.print_stderr(f'Writing fingerprints to {wfp_file}')
                with open(wfp_file, 'w') as f:
                    f.write(wfps)
            else:
                print(wfps)
        else:
            Scanner.print_stderr(f'Warning: No files found to fingerprint in folder: {scan_dir}')

#
# End of ScanOSS Class
#
