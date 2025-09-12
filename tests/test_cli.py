# NOTE: This file was created by test generator. Framework: pytest.
import builtins
import io
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, mock_open
import sys
import pytest

# Detect import path heuristically: prefer local module named 'cli' under src/ or project root.
# Fall back to relative imports if test tree already defines helpers.
try:
    from cli import (
        inspect_copyleft,
        inspect_undeclared,
        inspect_license_summary,
        inspect_component_summary,
        inspect_dep_track_project_violations,
        _dt_args_validator,
        get_pac_file,
        results,
        process_req_headers,
        initialise_empty_file,
    )
except Exception:
    # Try common package roots
    try:
        from src.cli import (
            inspect_copyleft,
            inspect_undeclared,
            inspect_license_summary,
            inspect_component_summary,
            inspect_dep_track_project_violations,
            _dt_args_validator,
            get_pac_file,
            results,
            process_req_headers,
            initialise_empty_file,
        )
    except Exception:
        # Last resort: dynamically locate via importlib
        import importlib
        import types
        _cli = None
        for mod_name in ("project.cli", "app.cli", "package.cli"):
            try:
                _cli = importlib.import_module(mod_name)
                break
            except Exception:
                continue
        if _cli is None:
            raise
        inspect_copyleft = _cli.inspect_copyleft
        inspect_undeclared = _cli.inspect_undeclared
        inspect_license_summary = _cli.inspect_license_summary
        inspect_component_summary = _cli.inspect_component_summary
        inspect_dep_track_project_violations = _cli.inspect_dep_track_project_violations
        _dt_args_validator = _cli._dt_args_validator
        get_pac_file = _cli.get_pac_file
        results = _cli.results
        process_req_headers = _cli.process_req_headers
        initialise_empty_file = _cli.initialise_empty_file

# Helper: minimal parser stub capturing parse_args calls
class ParserStub:
    def __init__(self):
        self.calls = []
    def parse_args(self, argv):
        self.calls.append(tuple(argv))
        # mimic argparse.parse_args behavior of exiting on -h by raising SystemExit
        if "-h" in argv:
            raise SystemExit(0)

@pytest.fixture
def parser():
    return ParserStub()

@pytest.fixture
def args_base(tmp_path):
    # Provide defaults common across commands
    return SimpleNamespace(
        subparser="scan",
        subparsercmd="inspect",
        subparser_subcmd="copyleft",
        input=str(tmp_path / "input.json"),
        output=None,
        status=None,
        format="json",
        include=None,
        exclude=None,
        explicit=None,
        sbom_format="legacy",
        debug=False,
        trace=False,
        quiet=True,
        url="https://dt.local",
        apikey="apikey",
        project_id=None,
        project_name=None,
        project_version=None,
        upload_token=None,
        timeout=5,
        filepath=None,
        has_pending=False,
        match_type=None,
    )

def test_process_req_headers_empty_returns_empty_dict():
    assert process_req_headers([]) == {}
    assert process_req_headers(None) == {}

def test_process_req_headers_parses_and_trims_and_keeps_last_duplicate():
    headers = [
        " Authorization :  Bearer token ",
        "Content-Type: application/json",
        "X-Ignore-This",  # invalid
        "X-Multi: a: b: c",  # value contains colons; split once only
        "Authorization: final",  # duplicate key should overwrite previous
    ]
    got = process_req_headers(headers)
    assert got == {
        "Authorization": "final",
        "Content-Type": "application/json",
        "X-Multi": "a: b: c",
    }

def test_initialise_empty_file_creates_or_truncates(tmp_path):
    p = tmp_path / "out.txt"
    # create with contents
    p.write_text("hello")
    # truncate
    initialise_empty_file(str(p))
    assert p.exists()
    assert p.read_text() == ""
    # create new
    p2 = tmp_path / "new.txt"
    initialise_empty_file(str(p2))
    assert p2.exists()
    assert p2.read_text() == ""

def test_initialise_empty_file_handles_io_error(monkeypatch, tmp_path):
    def _raise(*a, **k):
        raise OSError("kaboom")
    monkeypatch.setattr(builtins, "open", _raise)
    with patch("cli.print_stderr") as err, pytest.raises(SystemExit) as ex:
        initialise_empty_file(str(tmp_path / "x.txt"))
    err.assert_called()
    assert ex.value.code == 1

def test_get_pac_file_none_returns_none():
    assert get_pac_file(None) is None
    assert get_pac_file("") is None

def test_get_pac_file_auto(monkeypatch):
    sentinel = object()
    get_pac = MagicMock(return_value=sentinel)
    with patch("cli.pypac.get_pac", get_pac):
        assert get_pac_file("auto") is sentinel
        get_pac.assert_called_once_with()

def test_get_pac_file_http(monkeypatch):
    sentinel = object()
    with patch("cli.pypac.get_pac", return_value=sentinel) as m:
        out = get_pac_file("https://example/pac.js")
        m.assert_called_once_with(url="https://example/pac.js")
        assert out is sentinel

def test_get_pac_file_file_missing(monkeypatch):
    with patch("cli.os.path.exists", return_value=False), \
         patch("cli.print_stderr") as err:
        with pytest.raises(SystemExit) as ex:
            get_pac_file("file:///nope.js")
    err.assert_called()
    assert ex.value.code == 1

def test_get_pac_file_file_reads_and_passes_js(monkeypatch):
    mopen = mock_open(read_data="function FindProxyForURL(url, host){}")
    with patch("cli.os.path.exists", return_value=True), \
         patch("cli.builtins.open", mopen), \
         patch("cli.pypac.get_pac", return_value="PACOBJ") as gp:
        out = get_pac_file("file:///tmp/proxy.pac")
        mopen.assert_called_once()
        gp.assert_called_once()
        # ensure called with js kwarg
        args, kwargs = gp.call_args
        assert kwargs.get("js", "").startswith("function")
        assert out == "PACOBJ"

def test_get_pac_file_unknown_option_exits():
    with patch("cli.print_stderr") as err:
        with pytest.raises(SystemExit) as ex:
            get_pac_file("gopher://not-supported")
    err.assert_called()
    assert ex.value.code == 1

def _make_args_for_copyleft(tmp_path, args_base):
    infile = tmp_path / "scan.json"
    infile.write_text("{}")
    a = SimpleNamespace(**vars(args_base))
    a.input = str(infile)
    a.output = str(tmp_path / "out.txt")
    a.status = str(tmp_path / "status.txt")
    a.include = ["GPL-2.0-only"]
    a.exclude = ["MIT"]
    a.explicit = ["GPL-3.0-only"]
    return a

def test_inspect_copyleft_input_missing_exits(parser, args_base):
    a = SimpleNamespace(**vars(args_base))
    a.input = None
    with patch("cli.print_stderr") as err, pytest.raises(SystemExit) as ex:
        inspect_copyleft(parser, a)
    # Help requested on same subcommands
    assert any("-h" in call for call in (c for c in parser.calls))
    err.assert_called()
    assert ex.value.code == 1

def test_inspect_copyleft_happy_path_exits_with_status(tmp_path, parser, args_base):
    a = _make_args_for_copyleft(tmp_path, args_base)
    with patch("cli.initialise_empty_file") as initf, \
         patch("cli.Copyleft") as CopyleftCls:
        inst = CopyleftCls.return_value
        inst.run.return_value = (3, {"summary": 1})
        with pytest.raises(SystemExit) as ex:
            inspect_copyleft(parser, a)
    # output/status files initialised
    initf.assert_any_call(a.output)
    initf.assert_any_call(a.status)
    # Constructed with expected args
    kwargs = CopyleftCls.call_args.kwargs
    assert kwargs["filepath"] == a.input
    assert kwargs["format_type"] == a.format
    assert kwargs["include"] == a.include
    assert kwargs["exclude"] == a.exclude
    assert kwargs["explicit"] == a.explicit
    assert ex.value.code == 3

def test_inspect_copyleft_exception_prints_and_exits(tmp_path, parser, args_base):
    a = _make_args_for_copyleft(tmp_path, args_base)
    with patch("cli.initialise_empty_file"), \
         patch("cli.Copyleft", side_effect=RuntimeError("boom")), \
         patch("cli.print_stderr") as err:
        with pytest.raises(SystemExit) as ex:
            inspect_copyleft(parser, a)
    err.assert_called()
    assert ex.value.code == 1

def test_inspect_undeclared_input_missing_exits(parser, args_base):
    a = SimpleNamespace(**vars(args_base))
    a.input = None
    with patch("cli.print_stderr") as err, pytest.raises(SystemExit) as ex:
        inspect_undeclared(parser, a)
    assert any("-h" in call for call in (c for c in parser.calls))
    err.assert_called()
    assert ex.value.code == 1

def test_inspect_undeclared_happy_path(tmp_path, parser, args_base):
    infile = tmp_path / "scan.json"
    infile.write_text("{}")
    a = SimpleNamespace(**vars(args_base))
    a.input = str(infile)
    a.output = str(tmp_path / "out.txt")
    a.status = str(tmp_path / "status.txt")
    a.sbom_format = "settings"
    with patch("cli.initialise_empty_file") as initf, \
         patch("cli.UndeclaredComponent") as U:
        U.return_value.run.return_value = (0, {})
        with pytest.raises(SystemExit) as ex:
            inspect_undeclared(parser, a)
    initf.assert_any_call(a.output)
    initf.assert_any_call(a.status)
    kwargs = U.call_args.kwargs
    assert kwargs["filepath"] == a.input
    assert kwargs["sbom_format"] == "settings"
    assert ex.value.code == 0

def test_inspect_license_summary_input_missing_exits(parser, args_base):
    a = SimpleNamespace(**vars(args_base))
    a.input = None
    with patch("cli.print_stderr") as err, pytest.raises(SystemExit) as ex:
        inspect_license_summary(parser, a)
    assert any("-h" in call for call in (c for c in parser.calls))
    err.assert_called()
    assert ex.value.code == 1

def test_inspect_license_summary_runs_and_no_exit(tmp_path, parser, args_base):
    infile = tmp_path / "scan.json"; infile.write_text("{}")
    out = tmp_path / "licenses.md"
    a = SimpleNamespace(**vars(args_base), input=str(infile), output=str(out))
    with patch("cli.initialise_empty_file") as initf, \
         patch("cli.LicenseSummary") as L:
        L.return_value.run.return_value = None
        inspect_license_summary(parser, a)
    initf.assert_called_once_with(str(out))
    kwargs = L.call_args.kwargs
    assert kwargs["filepath"] == str(infile)
    assert kwargs["output"] == str(out)

def test_inspect_component_summary_input_missing_exits(parser, args_base):
    a = SimpleNamespace(**vars(args_base))
    a.input = None
    with patch("cli.print_stderr") as err, pytest.raises(SystemExit) as ex:
        inspect_component_summary(parser, a)
    assert any("-h" in call for call in (c for c in parser.calls))
    err.assert_called()
    assert ex.value.code == 1

def test_inspect_component_summary_runs_and_no_exit(tmp_path, parser, args_base):
    infile = tmp_path / "scan.json"; infile.write_text("{}")
    out = tmp_path / "components.md"
    a = SimpleNamespace(**vars(args_base), input=str(infile), output=str(out))
    with patch("cli.initialise_empty_file") as initf, \
         patch("cli.ComponentSummary") as C:
        C.return_value.run.return_value = None
        inspect_component_summary(parser, a)
    initf.assert_called_once_with(str(out))
    kwargs = C.call_args.kwargs
    assert kwargs["filepath"] == str(infile)
    assert kwargs["output"] == str(out)

def test__dt_args_validator_requires_id_or_name_version(parser):
    # none provided -> prints help and exits(1)
    a = SimpleNamespace(subparser="dt", project_id=None, project_name=None, project_version=None)
    with patch("cli.print_stderr") as err, pytest.raises(SystemExit) as ex:
        _dt_args_validator(parser, a)
    assert ex.value.code == 1
    err.assert_called()
    # name without version -> exits(1)
    a2 = SimpleNamespace(subparser="dt", project_id=None, project_name="proj", project_version=None)
    with patch("cli.print_stderr") as err2, pytest.raises(SystemExit) as ex2:
        _dt_args_validator(parser, a2)
    assert ex2.value.code == 1
    err2.assert_called()
    # id only -> OK
    a3 = SimpleNamespace(subparser="dt", project_id="uuid", project_name=None, project_version=None)
    _dt_args_validator(parser, a3)
    # name+version -> OK
    a4 = SimpleNamespace(subparser="dt", project_id=None, project_name="proj", project_version="1.2.3")
    _dt_args_validator(parser, a4)

def _make_dt_args(args_base, tmp_path):
    a = SimpleNamespace(**vars(args_base))
    a.subparser = "dt"
    a.url = "https://dt.example"
    a.apikey = "key"
    a.status = str(tmp_path / "status.md")
    a.output = str(tmp_path / "out.md")
    a.format = "md"
    a.project_id = "uuid-123"
    a.project_name = None
    a.project_version = None
    return a

def test_inspect_dep_track_project_violations_happy_path(parser, args_base, tmp_path):
    a = _make_dt_args(args_base, tmp_path)
    with patch("cli.initialise_empty_file") as initf, \
         patch("cli.DependencyTrackProjectViolationPolicyCheck") as D:
        D.return_value.run.return_value = 2
        with pytest.raises(SystemExit) as ex:
            inspect_dep_track_project_violations(parser, a)
    initf.assert_called_with(a.output)
    kwargs = D.call_args.kwargs
    assert kwargs["url"] == a.url
    assert kwargs["api_key"] == a.apikey
    assert kwargs["project_id"] == a.project_id
    assert kwargs["format_type"] == a.format
    assert kwargs["status"] == a.status
    assert ex.value.code == 2

def test_results_requires_filepath(parser, args_base):
    a = SimpleNamespace(**vars(args_base))
    a.filepath = None
    with patch("cli.print_stderr") as err, pytest.raises(SystemExit) as ex:
        results(parser, a)
    assert any("-h" in call for call in (c for c in parser.calls))
    err.assert_called()
    assert ex.value.code == 1

def test_results_missing_file_exits(args_base, tmp_path):
    a = SimpleNamespace(**vars(args_base))
    a.filepath = str(tmp_path / "nope.json")
    with patch("cli.print_stderr") as err, pytest.raises(SystemExit) as ex:
        results(ParserStub(), a)
    err.assert_called()
    assert ex.value.code == 1

def test_results_pending_branch_exits_when_has_results(tmp_path, args_base):
    p = tmp_path / "res.json"; p.write_text("{}")
    a = SimpleNamespace(**vars(args_base))
    a.filepath = str(p)
    a.has_pending = True
    with patch("cli.Results") as R:
        inst = R.return_value
        inst.get_pending_identifications.return_value.present.return_value = None
        inst.has_results.return_value = True
        with pytest.raises(SystemExit) as ex:
            results(ParserStub(), a)
    assert ex.value.code == 1
    R.assert_called()

def test_results_apply_filters_branch_no_exit(tmp_path, args_base):
    p = tmp_path / "res.json"; p.write_text("{}")
    a = SimpleNamespace(**vars(args_base))
    a.filepath = str(p)
    a.has_pending = False
    with patch("cli.Results") as R:
        inst = R.return_value
        inst.apply_filters.return_value.present.return_value = None
        results(ParserStub(), a)
    R.assert_called()