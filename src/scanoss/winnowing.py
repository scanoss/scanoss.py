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

   Winnowing Algorithm implementation for SCANOSS.

   This module implements an adaptation of the original winnowing algorithm by S. Schleimer, D. S. Wilkerson and
   A. Aiken as described in their seminal article which can be found here:
   https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf
"""
import hashlib
import pathlib

from crc32c import crc32c
from binaryornot.check import is_binary

from .scanossbase import ScanossBase

# Winnowing configuration. DO NOT CHANGE.
GRAM = 30
WINDOW = 64
# ASCII characters
ASCII_0 = 48
ASCII_9 = 57
ASCII_A = 65
ASCII_Z = 90
ASCII_a = 97
ASCII_z = 122
ASCII_LF = 10
ASCII_BACKSLASH = 92
MAX_CRC32 = 4294967296
MAX_LONG_LINE_CHARS = 1000
MAX_POST_SIZE = 64 * 1024  # 64k Max post size
MIN_FILE_SIZE = 256

SKIP_SNIPPET_EXT = {  # File extensions to ignore snippets for
    ".exe", ".zip", ".tar", ".tgz", ".gz", ".7z", ".rar", ".jar", ".war", ".ear", ".class", ".pyc",
    ".o", ".a", ".so", ".obj", ".dll", ".lib", ".out", ".app", ".bin",
    ".lst", ".dat", ".json", ".htm", ".html", ".xml", ".md", ".txt",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".pages", ".key", ".numbers",
    ".pdf", ".min.js", ".mf", ".sum"
}


class Winnowing(ScanossBase):
    """
    Winnowing Algorithm implementation for SCANOSS.

    This module implements an adaptation of the original winnowing algorithm by
    S. Schleimer, D. S. Wilkerson and A. Aiken as described in their seminal article which can be found here:
    https://theory.stanford.edu/~aiken/publications/papers/sigmod03.pdf

    The winnowing algorithm is configured using two parameters, the gram size and the window size.
    For SCANOSS the values need to be:
     - GRAM: 30
     - WINDOW: 64

    The result of performing the Winnowing algorithm is a string called WFP (Winnowing FingerPrint).
    A WFP contains optionally the name of the source component and the results of the Winnowing algorithm for each file.
    EXAMPLE output: test-component.wfp
    component=f9fc398cec3f9dd52aa76ce5b13e5f75,test-component.zip
    file=cae3ae667a54d731ca934e2867b32aaa,948,test/test-file1.c
    4=579be9fb
    5=9d9eefda,58533be6,6bb11697
    6=80188a22,f9bb9220
    10=750988e0,b6785a0d
    12=600c7ec9
    13=595544cc
    18=e3cb3b0f
    19=e8f7133d
    file=cae3ae667a54d731ca934e2867b32aaa,1843,test/test-file2.c
    2=58fb3eed
    3=f5f7f458
    4=aba6add1
    8=53762a72,0d274008,6be2454a
    10=239c7dfa
    12=0b2188c9
    15=bd9c4b10,d5c8f9fb
    16=eb7309dd,63aebec5
    19=316e10eb
    [...]

    Where component is the MD5 hash and path of the component container (could be a path to a compressed file or URL).
    file is the MD5 hash, file length and file path being fingerprinted, followed by
    a list of WFP fingerprints with their corresponding line numbers.
    """

    def __init__(self, size_limit: bool = True, debug: bool = False, trace: bool = False, quiet: bool = False,
                 skip_snippets: bool = False, post_size: int = 64, all_extensions: bool = False, obfuscate: bool = False
                 ):
        """
        Instantiate Winnowing class
        Parameters
        ----------
            size_limit: bool
                Limit the size of a fingerprint to 64k (post size) - Default True
        """
        super().__init__(debug, trace, quiet)
        self.size_limit = size_limit
        self.skip_snippets = skip_snippets
        self.max_post_size = post_size * 1024 if post_size > 0 else MAX_POST_SIZE
        self.all_extensions = all_extensions
        self.obfuscate = obfuscate
        self.ob_count = 1
        self.file_map = {} if obfuscate else None

    @staticmethod
    def __normalize(byte):
        """
        Normalise a given byte as an ASCII character
        Parameters
        ----------
        byte : int
          The byte to normalize
        """
        if byte < ASCII_0:
            return 0
        if byte > ASCII_z:
            return 0
        if byte <= ASCII_9:
            return byte
        if byte >= ASCII_a:
            return byte
        if (byte >= 65) and (byte <= 90):
            return byte + 32
        return 0

    def __skip_snippets(self, file: str, src: str) -> bool:
        """
        Determine files that are not of interest based on their content or file extension
        Parameters
        ----------
            src: str
                string to compare
        Return
        ------
            True: if file should be skipped
            False: otherwise
        """
        if self.all_extensions:
            return False
        if file:
            lower_file = file.lower()
            for ending in SKIP_SNIPPET_EXT:
                if lower_file.endswith(ending):
                    self.print_trace(f'Skipping snippets due to file ending: {file} - {ending}')
                    return True;
        src_len = len(src)
        if src_len == 0 or src_len <= MIN_FILE_SIZE:  # Ignore empty or files that are too small
            self.print_trace(f'Skipping snippets as the file is too small: {file} - {src_len}')
            return True
        prefix = src[0:(MIN_FILE_SIZE - 1)].lower().strip()
        if len(prefix) > 0 and (prefix[0] == "{" or prefix[0] == "["):  # Ignore json
            self.print_trace(f'Skipping snippets as the file appears to be JSON: {file}')
            return True
        if prefix.startswith("<?xml") or prefix.startswith("<html") or prefix.startswith("<ac3d") or prefix.startswith(
                "<!doc"):
            self.print_trace(f'Skipping snippets as the file appears to be xml/html/binary: {file}')
            return True  # Ignore xml & html & ac3d
        index = src.index('\n') if '\n' in src else (src_len - 1)  # TODO still necessary if we have a binary check?
        if len(src[0:index]) > MAX_LONG_LINE_CHARS:  # Ignore long lines
            self.print_trace(f'Skipping snippets due to file line being too long: {file} - {MAX_LONG_LINE_CHARS}')
            return True
        return False

    def wfp_for_file(self, path: str, file: str) -> str:
        """
        Returns the WFP for a file by executing the winnowing algorithm over its contents.
        Parameters
        ----------
            path : str
                The full path of the file.
            file: str
                File name/path to record in WFP
        """
        binary_file = self.is_binary(path)
        with open(path, 'rb') as f:
            contents = f.read()
            return self.wfp_for_contents(file, binary_file, contents)

    def is_binary(self, path: str):
        """
        Check if the specified file is a potential "binary" file

        :param path: Path to the file to check
        :return: True if binary, False otherwise
        """
        if path:
            binary_path = is_binary(path)
            if binary_path:
                self.print_trace(f'Detected binary file: {path}')
            return binary_path
        return False

    def wfp_for_contents(self, file: str, bin_file: bool, contents: bytes) -> str:
        """
        Generate a Winnowing fingerprint (WFP) for the given file contents
        Parameters
        ----------
            :param file: file to fingerprint
            :param bin_file: binary file or not
            :param contents: file contents
        Return
        ------
            WFP string
        """
        file_md5 = hashlib.md5(contents).hexdigest()
        # Print file line
        content_length = len(contents)
        wfp_filename = file
        if self.obfuscate:  # hide the real size of the file and its name, but keep the suffix
            wfp_filename = f'{self.ob_count}{pathlib.Path(file).suffix}'
            self.ob_count = self.ob_count + 1
            self.file_map[wfp_filename] = file  # Save the file name map for later (reverse lookup)

        wfp = 'file={0},{1},{2}\n'.format(file_md5, content_length, wfp_filename)
        # We don't process snippets for binaries, or other uninteresting files, or if we're requested to skip
        if bin_file or self.skip_snippets or self.__skip_snippets(file, contents.decode('utf-8', 'ignore')):
            return wfp
        # Initialize variables
        gram = ""
        window = []
        line = 1
        last_hash = MAX_CRC32
        last_line = 0
        output = ""
        # Otherwise, recurse src_content and calculate Winnowing hashes
        for byte in contents:
            if byte == ASCII_LF:
                line += 1
                normalized = 0
            else:
                normalized = self.__normalize(byte)
            # Is it a useful byte?
            if normalized:
                gram += chr(normalized)  # Add byte to gram
                # Do we have a full gram?
                if len(gram) >= GRAM:
                    gram_crc32 = crc32c(gram.encode('ascii'))
                    window.append(gram_crc32)
                    # Do we have a full window?
                    if len(window) >= WINDOW:
                        # Select minimum hash for the current window
                        min_hash = min(window)
                        # Is the minimum hash a new one?
                        if min_hash != last_hash:
                            # Hashing the hash will result in a better balanced resulting data set
                            # as it will counter the winnowing effect which selects the "minimum"
                            # hash in each window
                            crc = crc32c(min_hash.to_bytes(4, byteorder='little'))
                            crc_hex = '{:08x}'.format(crc)
                            if last_line != line:
                                if output:
                                    if self.size_limit and \
                                            (len(wfp.encode("utf-8")) + len(
                                                output.encode("utf-8"))) > self.max_post_size:
                                        self.print_debug(f'Truncating WFP (64k limit) for: {file}')
                                        output = ''
                                        break  # Stop collecting snippets as it's over 64k
                                    wfp += output + '\n'
                                output = "%d=%s" % (line, crc_hex)
                            else:
                                output += ',' + crc_hex

                            last_line = line
                            last_hash = min_hash
                        # Shift window
                        window.pop(0)
                    # Shift gram
                    gram = gram[1:]
        if output and (
                not self.size_limit or (len(wfp.encode("utf-8")) + len(output.encode("utf-8"))) < self.max_post_size):
            wfp += output + '\n'

        return wfp

#
# End of Winnowing Class
#
