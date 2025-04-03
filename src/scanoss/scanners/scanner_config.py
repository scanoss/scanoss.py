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
from typing import Optional

from pypac.parser import PACFile

from scanoss.constants import (
    DEFAULT_NB_THREADS,
    DEFAULT_POST_SIZE,
    DEFAULT_SC_TIMEOUT,
    DEFAULT_TIMEOUT,
)


@dataclass
class ScannerConfig:
    debug: bool = False
    trace: bool = False
    quiet: bool = False
    api_key: Optional[str] = None
    url: Optional[str] = None
    grpc_url: Optional[str] = None
    post_size: int = DEFAULT_POST_SIZE
    timeout: int = DEFAULT_TIMEOUT
    sc_timeout: int = DEFAULT_SC_TIMEOUT
    nb_threads: int = DEFAULT_NB_THREADS
    proxy: Optional[str] = None
    grpc_proxy: Optional[str] = None

    ca_cert: Optional[str] = None
    pac: Optional[PACFile] = None


def create_scanner_config_from_args(args) -> ScannerConfig:
    return ScannerConfig(
        debug=args.debug,
        trace=args.trace,
        quiet=args.quiet,
        api_key=getattr(args, 'key', None),
        url=getattr(args, 'api_url', None),
        grpc_url=getattr(args, 'grpc_url', None),
        post_size=getattr(args, 'post_size', DEFAULT_POST_SIZE),
        timeout=getattr(args, 'timeout', DEFAULT_TIMEOUT),
        sc_timeout=getattr(args, 'sc_timeout', DEFAULT_SC_TIMEOUT),
        nb_threads=getattr(args, 'nb_threads', DEFAULT_NB_THREADS),
        proxy=getattr(args, 'proxy', None),
        grpc_proxy=getattr(args, 'grpc_proxy', None),
        ca_cert=getattr(args, 'ca_cert', None),
        pac=getattr(args, 'pac', None),
    )
