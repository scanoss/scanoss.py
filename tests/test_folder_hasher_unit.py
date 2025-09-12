import json
import os
from pathlib import Path
from types import SimpleNamespace
import importlib.util
from unittest import mock

import pytest

# Utility: dynamically load the implementation module sitting at tests/test_folder_hasher.py
IMPL_PATH = Path(__file__).parent / "test_folder_hasher.py"
spec = importlib.util.spec_from_file_location("folder_hasher_impl", str(IMPL_PATH))
impl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(impl)  # type: ignore

# Fixtures
@pytest.fixture
def temp_dir(tmp_path: Path) -> Path:
    return tmp_path

@pytest.fixture
def dummy_bar():
    class DummyBar:
        def __init__(self, *args, **kwargs): pass
        def next(self): pass
        def finish(self): pass
    return DummyBar

@pytest.fixture
def patched_hash_funcs(monkeypatch):
    # Stable hashing/maths to make assertions deterministic
    monkeypatch.setattr(impl.CRC64, "get_hash_buff", lambda b: b"\x01\x02\x03\x04\x05\x06\x07\x08")
    monkeypatch.setattr(impl, "vectorize_bytes", lambda lst: b"VEC")   # input ignored
    monkeypatch.setattr(impl, "fingerprint", lambda vec: 0xBEEF)
    # Return fixed ints for both simhash calls
    monkeypatch.setattr(impl, "simhash", lambda wf: 0xABCD)
    # WordFeatureSet can remain as imported; it won't be executed semantically in our stubs
    return True

@pytest.fixture
def patched_bar(monkeypatch, dummy_bar):
    monkeypatch.setattr(impl, "Bar", dummy_bar)
    return True

@pytest.fixture
def patched_file_filters(monkeypatch):
    # Ensure FileFilters.get_filtered_files_from_files returns what FolderHasher sees from rglob
    # We'll override on the instance in tests as needed; here just provide a passthrough default.
    original_cls = impl.FileFilters
    class DummyFF(original_cls):
        def get_filtered_files_from_files(self, all_files, root_str):
            return all_files
    monkeypatch.setattr(impl, "FileFilters", DummyFF)
    return True

@pytest.fixture
def new_hasher(temp_dir, patched_bar, patched_hash_funcs, patched_file_filters):
    cfg = impl.FolderHasherConfig(debug=False, trace=False, quiet=True)
    # Use depth=1 to simplify child traversal in most tests
    return impl.FolderHasher(str(temp_dir), cfg, scanoss_settings=None, depth=1)

# Tests

def test_create_folder_hasher_config_from_args_defaults():
    args = SimpleNamespace(debug=True, trace=False, quiet=True, output="out.json", format="json",
                           settings=None, skip_settings_file=True)
    cfg = impl.create_folder_hasher_config_from_args(args)
    assert isinstance(cfg, impl.FolderHasherConfig)
    assert cfg.debug is True
    assert cfg.trace is False
    assert cfg.quiet is True
    assert cfg.output_file == "out.json"
    assert cfg.output_format == "json"
    assert cfg.settings_file is None
    assert cfg.skip_settings_file is True

def test_hash_directory_happy_path_builds_hash_tree(temp_dir, new_hasher, monkeypatch):
    # Create a structure with >= 8 files and sufficiently long concatenated names
    subA = temp_dir / "pkgA"
    subB = temp_dir / "pkgB" / "sub"
    subA.mkdir(parents=True, exist_ok=True)
    subB.mkdir(parents=True, exist_ok=True)

    names = [
        "alpha.txt", "beta.txt", "gamma.md", "delta.py",
        "epsilon.js", "zeta.ts", "eta.css", "theta.html",
    ]
    # Distribute files across directories
    targets = [subA, subA, subA, subB, subB, temp_dir, temp_dir, temp_dir]
    for n, d in zip(names, targets):
        (d / n).write_text(f"content-of-{n}")

    # Patch FileFilters to return relative paths to ensure code covers join logic
    def passthrough_filtered_files(self, all_files, root_str):
        # Return relative Paths to root to exercise absolute/relative handling
        root = Path(root_str)
        rels = []
        for f in all_files:
            if f.is_file():
                rels.append(f.relative_to(root))
        return rels
    monkeypatch.setattr(new_hasher.file_filters, "get_filtered_files_from_files", passthrough_filtered_files.__get__(new_hasher.file_filters, type(new_hasher.file_filters)))

    tree = new_hasher.hash_directory(str(temp_dir))
    # Validate structure
    assert isinstance(tree, dict)
    assert tree["path_id"] in (".", "")  # pathlib renders equal path to '.' usually
    # Hash strings are hex of the stubbed values
    assert tree["sim_hash_names"] == f"{0xABCD:02x}"
    assert tree["sim_hash_content"] == f"{0xBEEF:02x}"
    assert tree["sim_hash_dir_names"] == f"{0xABCD:02x}"
    # Extension counts
    ext = tree["lang_extensions"]
    assert ext["txt"] == 2
    assert ext["md"] == 1
    assert ext["py"] == 1
    assert ext["js"] == 1
    assert ext["ts"] == 1
    assert ext["css"] == 1
    assert ext["html"] == 1
    # With depth=1, no children should be traversed
    assert tree["children"] == []

def test__hash_calc_below_minimum_file_count_returns_none(new_hasher):
    node = impl.DirectoryNode(path="X")
    # Fewer than MINIMUM_FILE_COUNT = 8
    for i in range(3):
        df = impl.DirectoryFile(path=f"dir/file{i}.txt", key=b"\x00"*8, key_str="00"*8)
        node.files.append(df)
    res = new_hasher._hash_calc(node)
    assert res == {'name_hash': None, 'content_hash': None, 'dir_hash': None, 'lang_extensions': None}

def test__hash_calc_concatenated_names_too_short_returns_none(new_hasher):
    node = impl.DirectoryNode(path="Y")
    # 8 files but single-char names to keep concatenated length < 32
    for ch in list("abcdefgh"):
        df = impl.DirectoryFile(path=f"sub/{ch}", key=b"\x00"*8, key_str="00"*8)
        node.files.append(df)
    res = new_hasher._hash_calc(node)
    assert res == {'name_hash': None, 'content_hash': None, 'dir_hash': None, 'lang_extensions': None}

def test__hash_calc_from_node_relative_path_fallback(monkeypatch, temp_dir):
    hasher = impl.FolderHasher(scan_dir=str(temp_dir/"rootA"),
                               config=impl.FolderHasherConfig(quiet=True),
                               scanoss_settings=None, depth=1)
    ext_values = {'name_hash': 0x11, 'content_hash': 0x22, 'dir_hash': 0x33, 'lang_extensions': {'py': 2}}
    monkeypatch.setattr(hasher, "_hash_calc", lambda node: ext_values)
    # node not under scan_dir -> triggers ValueError -> fallback to name
    node = impl.DirectoryNode(path=str(temp_dir / "elsewhere" / "nodeX"))
    out = hasher._hash_calc_from_node(node, current_depth=1)
    assert out["path_id"] == "nodeX"
    assert out["sim_hash_names"] == f"{ext_values['name_hash']:02x}"
    assert out["sim_hash_content"] == f"{ext_values['content_hash']:02x}"
    assert out["sim_hash_dir_names"] == f"{ext_values['dir_hash']:02x}"
    assert out["lang_extensions"] == ext_values["lang_extensions"]
    assert out["children"] == []

def test__build_root_node_populates_tree_and_skips_on_read_error(temp_dir, patched_bar, patched_file_filters, monkeypatch):
    cfg = impl.FolderHasherConfig(quiet=True)
    hasher = impl.FolderHasher(str(temp_dir), cfg, scanoss_settings=None, depth=1)

    # Create nested structure
    d1 = temp_dir / "d1"
    d2 = temp_dir / "d1" / "d2"
    d2.mkdir(parents=True, exist_ok=True)
    good = d2 / "good.txt"
    bad = d2 / "bad.txt"
    good.write_text("good")
    bad.write_text("bad")

    # FileFilters: only include our two files
    def only_two(self, all_files, root_str):
        return [good.relative_to(root_str), bad.relative_to(root_str)]
    monkeypatch.setattr(hasher.file_filters, "get_filtered_files_from_files", only_two.__get__(hasher.file_filters, type(hasher.file_filters)))

    # read_bytes: raise for "bad.txt"
    orig_read_bytes = Path.read_bytes
    def rb(self: Path):
        if self.name == "bad.txt":
            raise IOError("boom")
        return orig_read_bytes(self)
    monkeypatch.setattr(Path, "read_bytes", rb)

    # Stable CRC64
    monkeypatch.setattr(impl.CRC64, "get_hash_buff", lambda b: b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11")

    root_node = hasher._build_root_node(str(temp_dir))

    # Verify root_node contains good file in files list
    files_paths = [f.path for f in root_node.files]
    assert "d1/d2/good.txt" in files_paths
    # Ensure directory children created
    assert any(Path(k).name == "d1" for k in root_node.children.keys())
    # Ensure the child node for d1 contains the file reference
    d1_node = root_node.children[str(Path(root_node.path) / "d1")]
    assert any(f.path.endswith("good.txt") for f in d1_node.files)
    # The bad file is skipped (not present in files lists under nodes)
    assert not any(f.path.endswith("bad.txt") for f in root_node.files)

def test_presenter_formatters_json_and_plain():
    # Build a fake hasher with a known tree
    cfg = impl.FolderHasherConfig()
    h = impl.FolderHasher(scan_dir=".", config=cgf) if False else None  # placeholder to keep type hints happy
    class DummyHasher:
        def __init__(self, tree): self.tree = tree
    tree = {"path_id": ".", "sim_hash_names": "abcd"}
    presenter = impl.FolderHasherPresenter(folder_hasher=DummyHasher(tree))
    js = presenter._format_json_output()
    assert json.loads(js) == tree
    # Plain returns JSON if dict, str otherwise
    assert json.loads(presenter._format_plain_output()) == tree
    presenter2 = impl.FolderHasherPresenter(folder_hasher=DummyHasher(["not-a-dict"]))
    assert presenter2._format_plain_output() == str(["not-a-dict"])
