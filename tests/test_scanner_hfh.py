
# =========================
# Additional unit tests for ScannerHFH and ScannerHFHPresenter
# Test framework: pytest
# =========================
import sys
import json
from types import SimpleNamespace
import pytest

# ---- Test utilities and fakes ----
class _DummyThread:
    def __init__(self, target=None, *_, **__):
        self._target = target
    def start(self):
        # Do not spin a real thread in tests
        pass
    def join(self, *args, **kwargs):
        pass

class _DummySpinner:
    def __init__(self, text=''):
        self.text = text
        self.steps = 0
    def next(self):
        self.steps += 1
    def finish(self):
        pass

class _FakeFolderHasher:
    def __init__(self, scan_dir, config, scanoss_settings=None, depth=1):
        self.scan_dir = scan_dir
        self.depth = depth
        self.config = config
        self.scanoss_settings = scanoss_settings
    def hash_directory(self, path):
        # Ensure the requested path matches configured directory
        assert path == self.scan_dir
        return "ROOT_HASH"

class _SpyClient:
    def __init__(self, response=None, deps=None, vulns=None, raise_in_deps=False):
        self.response = response
        self.deps = deps
        self.vulns = vulns
        self.raise_in_deps = raise_in_deps
        self.last_request = None
        self.last_dependencies_req = None
        self.last_vuln_req = None
    def folder_hash_scan(self, req):
        self.last_request = req
        return self.response
    def get_dependencies(self, req):
        if self.raise_in_deps:
            raise RuntimeError("boom")
        self.last_dependencies_req = req
        return self.deps
    def get_vulnerabilities_json(self, req):
        self.last_vuln_req = req
        return self.vulns

class _FakeBase:
    def __init__(self, *args, **kwargs):
        self.errors = []
    def print_stderr(self, msg):
        self.errors.append(str(msg))

# Autouse fixture to patch threading, spinner, and heavy dependencies used during ScannerHFH.__init__/scan
@pytest.fixture(autouse=True)
def _patch_env(monkeypatch):
    # Access current module (this file)
    this_mod = sys.modules[__name__]
    # Replace Spinner used by ScannerHFH.scan
    monkeypatch.setattr(this_mod, "Spinner", _DummySpinner, raising=False)
    # Replace stdlib threading.Thread only for this module's reference
    import threading as _threading
    monkeypatch.setattr(this_mod.threading, "Thread", _DummyThread, raising=True)
    # Stub out heavy collaborators used during __init__
    monkeypatch.setattr(this_mod, "FolderHasher", _FakeFolderHasher, raising=False)
    # No-op stubs for classes not exercised directly in tests
    class _Noop:
        def __init__(self, *a, **k): pass
    monkeypatch.setattr(this_mod, "FileFilters", _Noop, raising=False)
    monkeypatch.setattr(this_mod, "ScanossBase", _FakeBase, raising=False)

# ---- ScannerHFH.scan tests ----

def _make_simple_config():
    # Minimal config object with required attributes
    return SimpleNamespace(debug=False, trace=False, quiet=True)

def test_scan_happy_path_builds_request_and_returns_response():
    client = _SpyClient(response={"ok": True, "results": [{"id": 1}]})
    cfg = _make_simple_config()
    # Instantiate real ScannerHFH (collaborators are patched)
    scanner = ScannerHFH(
        scan_dir="/tmp/project",
        config=cfg,
        client=client,
        rank_threshold=7,
        depth=2,
        min_cutoff_threshold=0.5,
    )
    out = scanner.scan()
    assert out == {"ok": True, "results": [{"id": 1}]}
    # Verify request structure and values
    assert client.last_request == {
        "root": "ROOT_HASH",
        "rank_threshold": 7,
        "min_cutoff_threshold": 0.5,
    }
    # Ensure scan_results stored
    assert scanner.scan_results == out

def test_scan_handles_none_response_and_leaves_scan_results_none():
    client = _SpyClient(response=None)
    cfg = _make_simple_config()
    scanner = ScannerHFH(scan_dir="/path", config=cfg, client=client)
    out = scanner.scan()
    assert out is None
    assert scanner.scan_results is None

def test_present_delegates_to_presenter_with_arguments():
    # Call the unbound method with a lightweight fake 'self'
    calls = {}
    class _PresenterStub:
        def present(self, **kwargs):
            calls.update(kwargs)
    fake_self = SimpleNamespace(presenter=_PresenterStub())
    ScannerHFH.present(fake_self, output_format="json", output_file="out.json")
    assert calls == {"output_format": "json", "output_file": "out.json"}

# ---- ScannerHFHPresenter formatting tests ----

def _make_presenter_with_scan_results(scan_results, client=None):
    # Bypass AbstractPresenter.__init__ by constructing without calling __init__
    presenter = object.__new__(ScannerHFHPresenter)
    presenter.scanner = SimpleNamespace(scan_results=scan_results, client=client)
    presenter.base = _FakeBase()
    return presenter

def test_format_json_output_pretty_prints_dict():
    prs = _make_presenter_with_scan_results({"a": 1, "b": [2, 3]})
    out = prs._format_json_output()
    assert isinstance(out, str)
    parsed = json.loads(out)
    assert parsed == {"a": 1, "b": [2, 3]}

@pytest.mark.parametrize(
    "value,expects_json",
    [
        ({"x": 1}, True),
        (["x", "y"], False),
        ("scalar", False),
    ],
)
def test_format_plain_output_handles_dict_and_non_dict(value, expects_json):
    prs = _make_presenter_with_scan_results(value)
    out = prs._format_plain_output()
    if expects_json:
        assert out.strip().startswith("{")
        assert '"x": 1' in out
    else:
        assert out == str(value)

def test_cyclonedx_output_returns_empty_when_no_results_and_logs_error():
    prs = _make_presenter_with_scan_results({"foo": "bar"})
    out = prs._format_cyclonedx_output()
    assert out == ""
    assert any("No scan results found" in e for e in prs.base.errors)

def test_cyclonedx_output_returns_empty_when_no_best_match_component():
    prs = _make_presenter_with_scan_results(
        {"results": [{"components": [{"order": 2}, {"order": 3}]}]}
    )
    out = prs._format_cyclonedx_output()
    assert out == ""
    assert any("No best match component" in e for e in prs.base.errors)

def test_cyclonedx_output_returns_empty_when_no_versions():
    prs = _make_presenter_with_scan_results(
        {"results": [{"components": [{"order": 1, "name": "name", "purl": "p", "versions": []}]}]}
    )
    out = prs._format_cyclonedx_output()
    assert out == ""
    assert any("No versions found" in e for e in prs.base.errors)

def test_cyclonedx_output_returns_none_when_produce_fails(monkeypatch):
    # Prepare valid minimal scan_results
    scan_results = {
        "results": [
            {
                "components": [
                    {
                        "order": 1,
                        "name": "name",
                        "purl": "pkg:pypi/name@1.2.3",
                        "versions": [{"version": "1.2.3"}],
                    }
                ]
            }
        ]
    }
    client = _SpyClient(
        deps={"files": [{"file": "name:1.2.3"}]},
        vulns=None,
    )
    prs = _make_presenter_with_scan_results(scan_results, client=client)

    # Stub CycloneDx to simulate failure
    produced_inputs = {}
    class _FailCdx:
        def __init__(self, debug=False): pass
        def produce_from_json(self, sr):
            produced_inputs.update(sr)
            return False, None

    monkeypatch.setattr(sys.modules[__name__], "CycloneDx", _FailCdx, raising=False)

    out = prs._format_cyclonedx_output()
    assert out is None
    assert any("Failed to produce CycloneDX output" in e for e in prs.base.errors)
    # Ensure input shape to CycloneDx was as expected
    assert produced_inputs == {"name:1.2.3": [{"file": "name:1.2.3"}]}

def test_cyclonedx_output_handles_exception_and_logs_error(monkeypatch):
    scan_results = {
        "results": [
            {
                "components": [
                    {
                        "order": 1,
                        "name": "name",
                        "purl": "pkg:pypi/name@1.2.3",
                        "versions": [{"version": "1.2.3"}],
                    }
                ]
            }
        ]
    }
    client = _SpyClient(
        deps=None,
        vulns=None,
        raise_in_deps=True,  # Force exception path
    )
    prs = _make_presenter_with_scan_results(scan_results, client=client)

    # Provide a benign CycloneDx to ensure exception originates from deps call
    class _OkCdx:
        def __init__(self, debug=False): pass
        def produce_from_json(self, sr):
            return True, {"bom": "base"}
        def append_vulnerabilities(self, cdx_output, vulnerabilities, purl):
            return cdx_output

    monkeypatch.setattr(sys.modules[__name__], "CycloneDx", _OkCdx, raising=False)

    out = prs._format_cyclonedx_output()
    assert out is None
    assert any("Failed to get license information" in e for e in prs.base.errors)

def test_cyclonedx_output_success_with_vulnerabilities_appended(monkeypatch):
    scan_results = {
        "results": [
            {
                "components": [
                    {
                        "order": 1,
                        "name": "name",
                        "purl": "pkg:pypi/name@1.2.3",
                        "versions": [{"version": "1.2.3"}],
                    }
                ]
            }
        ]
    }
    client = _SpyClient(
        deps={"files": [{"file": "name:1.2.3"}]},
        vulns={"vulnerabilities": [{"id": "CVE-123"}]},
    )
    prs = _make_presenter_with_scan_results(scan_results, client=client)

    # Track calls/inputs to CycloneDx
    captured = {"produced": None, "appended": None}
    class _Cdx:
        def __init__(self, debug=False): pass
        def produce_from_json(self, sr):
            captured["produced"] = sr
            return True, {"bom": "base"}
        def append_vulnerabilities(self, cdx_output, vulnerabilities, purl):
            captured["appended"] = {"cdx_output": cdx_output, "vulnerabilities": vulnerabilities, "purl": purl}
            # Simulate augmented BOM
            out = dict(cdx_output)
            out["vulnerabilities"] = vulnerabilities
            out["purl"] = purl
            return out

    monkeypatch.setattr(sys.modules[__name__], "CycloneDx", _Cdx, raising=False)

    out = prs._format_cyclonedx_output()
    assert isinstance(out, str)
    data = json.loads(out)
    # Validate that vulnerabilities were appended and purl is passed through
    assert data["bom"] == "base"
    assert data["vulnerabilities"] == {"vulnerabilities": [{"id": "CVE-123"}]}
    assert data["purl"] == "pkg:pypi/name@1.2.3"
    # Ensure CycloneDx received normalized input
    assert captured["produced"] == {"name:1.2.3": [{"file": "name:1.2.3"}]}
    assert captured["appended"]["purl"] == "pkg:pypi/name@1.2.3"
