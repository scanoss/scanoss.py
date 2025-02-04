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
        api_key=getattr(args, 'api_key', None),
        url=getattr(args, 'url', None),
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
