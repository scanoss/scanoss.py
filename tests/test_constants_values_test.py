"""
Unit tests for constants in src/scanoss/constants.py.
Framework: pytest

Covers:
- Exact values (as per PR diff)
- Strict types (avoid bool passing for int)
- Invariants and sanity bounds
- URL structure and distinctness
- Runtime compatibility for PYTHON_MAJOR_VERSION
"""

from pathlib import Path
import importlib.util
import sys
from urllib.parse import urlparse
import pytest


def _load_constants_module():
    """
    Load the constants module directly from file to avoid relying on package installation.
    Tries src/ layout first, then flat package layout.
    """
    repo_root = Path(__file__).resolve().parents[1]
    candidates = [
        repo_root / "src" / "scanoss" / "constants.py",
        repo_root / "scanoss" / "constants.py",
    ]
    for path in candidates:
        if path.exists():
            spec = importlib.util.spec_from_file_location("constants_under_test", str(path))
            assert spec and spec.loader, f"Failed to create spec for {path}"
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
            return mod
    raise AssertionError(f"Could not find constants module at any of: {candidates}")


constants = _load_constants_module()


@pytest.mark.parametrize(
    "name, expected",
    [
        ("DEFAULT_POST_SIZE", 32),
        ("DEFAULT_TIMEOUT", 180),
        ("DEFAULT_RETRY", 5),
        ("MIN_TIMEOUT", 5),
        ("PYTHON_MAJOR_VERSION", 3),
        ("DEFAULT_SC_TIMEOUT", 600),
        ("DEFAULT_NB_THREADS", 5),
        ("DEFAULT_URL", "https://api.osskb.org"),
        ("DEFAULT_URL2", "https://api.scanoss.com"),
        ("DEFAULT_API_TIMEOUT", 600),
        ("DEFAULT_HFH_RANK_THRESHOLD", 5),
        ("DEFAULT_HFH_DEPTH", 1),
        ("DEFAULT_HFH_MIN_CUTOFF_THRESHOLD", 0.25),
    ],
)
def test_exact_constant_values(name, expected):
    assert hasattr(constants, name), f"Missing constant: {name}"
    assert getattr(constants, name) == expected, f"{name} value mismatch"


@pytest.mark.parametrize(
    "name, typ",
    [
        ("DEFAULT_POST_SIZE", int),
        ("DEFAULT_TIMEOUT", int),
        ("DEFAULT_RETRY", int),
        ("MIN_TIMEOUT", int),
        ("PYTHON_MAJOR_VERSION", int),
        ("DEFAULT_SC_TIMEOUT", int),
        ("DEFAULT_NB_THREADS", int),
        ("DEFAULT_API_TIMEOUT", int),
        ("DEFAULT_HFH_RANK_THRESHOLD", int),
        ("DEFAULT_HFH_DEPTH", int),
        ("DEFAULT_HFH_MIN_CUTOFF_THRESHOLD", float),
        ("DEFAULT_URL", str),
        ("DEFAULT_URL2", str),
    ],
)
def test_constant_types_are_strict(name, typ):
    assert hasattr(constants, name), f"Missing constant: {name}"
    value = getattr(constants, name)
    # Strict type check so bool does not pass for int
    assert type(value) is typ, f"{name} should be {typ.__name__}, got {type(value).__name__}"


def test_python_major_version_matches_runtime():
    assert constants.PYTHON_MAJOR_VERSION == sys.version_info.major


def test_timeouts_relationships_and_bounds():
    assert constants.DEFAULT_TIMEOUT >= constants.MIN_TIMEOUT
    assert constants.DEFAULT_SC_TIMEOUT >= constants.DEFAULT_TIMEOUT
    assert constants.DEFAULT_API_TIMEOUT >= constants.DEFAULT_TIMEOUT
    for v in (constants.MIN_TIMEOUT, constants.DEFAULT_TIMEOUT, constants.DEFAULT_API_TIMEOUT, constants.DEFAULT_SC_TIMEOUT):
        assert isinstance(v, int) and v > 0


def test_threads_retry_postsize_constraints():
    assert constants.DEFAULT_RETRY >= 0
    assert constants.DEFAULT_NB_THREADS >= 1
    assert constants.DEFAULT_POST_SIZE > 0


def test_hfh_thresholds_constraints():
    assert constants.DEFAULT_HFH_RANK_THRESHOLD >= 0 and type(constants.DEFAULT_HFH_RANK_THRESHOLD) is int
    assert constants.DEFAULT_HFH_DEPTH >= 0 and type(constants.DEFAULT_HFH_DEPTH) is int
    cutoff = constants.DEFAULT_HFH_MIN_CUTOFF_THRESHOLD
    assert type(cutoff) is float and 0.0 <= cutoff <= 1.0


def _assert_https_url(value: str):
    parsed = urlparse(value)
    assert parsed.scheme == "https", f"URL must be https: {value}"
    assert parsed.netloc, f"URL must have a host: {value}"


def test_urls_are_valid_https_and_distinct():
    _assert_https_url(constants.DEFAULT_URL)
    _assert_https_url(constants.DEFAULT_URL2)
    assert constants.DEFAULT_URL \!= constants.DEFAULT_URL2, "DEFAULT_URL and DEFAULT_URL2 should be distinct"