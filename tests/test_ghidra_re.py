import os
import subprocess
from pathlib import Path

import pytest

from conftest import ROOT, TINY_C, build

WRAP = ROOT / "skills" / "re-routine" / "tools" / "ghidra_re.sh"
FAKE = ROOT / "tests" / "fake_ghidra"
REAL = Path(os.environ.get("GHIDRA_HOME", str(Path.home() / "tools" / "ghidra")))
HAS_REAL = (REAL / "support" / "analyzeHeadless").exists()


def run(args, cwd, **env):
    e = dict(os.environ)
    e.update({k: str(v) for k, v in env.items()})
    return subprocess.run(["bash", str(WRAP), *args], cwd=cwd, env=e, capture_output=True, text=True)


@pytest.fixture
def fake_env(tmp_path, tiny):
    log = tmp_path / "calls.log"
    return {"GHIDRA_HOME": FAKE, "FAKE_LOG": log, "RE_TARGET": tiny, "RE_GHIDRA_DIR": tmp_path / "g"}, log


def test_missing_ghidra_exits_2(tmp_path, tiny):
    r = run(["analyze"], tmp_path, GHIDRA_HOME=tmp_path / "none", RE_TARGET=tiny, RE_GHIDRA_DIR=tmp_path / "g")
    assert r.returncode == 2 and "analyzeHeadless 없음" in r.stderr


def test_missing_target_exits_2(tmp_path, fake_env):
    env, _ = fake_env
    r = run(["analyze"], tmp_path, **{**env, "RE_TARGET": tmp_path / "nope"})
    assert r.returncode == 2 and "대상 없음" in r.stderr


def test_list_before_analyze_exits_2(tmp_path, fake_env):
    env, _ = fake_env
    r = run(["list"], tmp_path, **env)
    assert r.returncode == 2 and "analyze" in r.stderr


def test_cache_reuse_and_invalidate(tmp_path, fake_env):
    env, log = fake_env
    assert run(["analyze"], tmp_path, **env).returncode == 0
    r2 = run(["analyze"], tmp_path, **env)
    assert r2.returncode == 0 and "cached" in r2.stdout
    assert len(log.read_text().splitlines()) == 1
    other = build(tmp_path, "other", TINY_C.replace("s3cr3t", "0ther"))
    assert run(["analyze"], tmp_path, **{**env, "RE_TARGET": other}).returncode == 0
    assert len(log.read_text().splitlines()) == 2


def test_list_sorted_and_filtered(tmp_path, fake_env):
    env, _ = fake_env
    run(["analyze"], tmp_path, **{**env, "FAKE_NFUNCS": 5})
    out = run(["list"], tmp_path, **env).stdout.splitlines()
    assert out[0].startswith("addr\tname") and out[1].split("\t")[1] == "f5"
    out2 = run(["list", "f3"], tmp_path, **env).stdout.splitlines()
    assert len(out2) == 2 and out2[1].split("\t")[1] == "f3"


def test_list_is_capped(tmp_path, fake_env):
    env, _ = fake_env
    run(["analyze"], tmp_path, **{**env, "FAKE_NFUNCS": 50})
    out = run(["list"], tmp_path, **{**env, "RE_MAX_LINES": 10}).stdout.splitlines()
    assert len(out) == 11 and "51줄 중 10줄 표시" in out[-1]


def test_xrefs(tmp_path, fake_env):
    env, _ = fake_env
    run(["analyze"], tmp_path, **env)
    out = run(["xrefs", "Correct"], tmp_path, **env).stdout
    assert "0x1010" in out and "Wrong" not in out


def test_decomp_is_capped(tmp_path, fake_env):
    env, log = fake_env
    run(["analyze"], tmp_path, **env)
    r = run(["decomp", "0x1010"], tmp_path, **{**env, "RE_MAX_LINES": 5, "FAKE_DECOMP_LINES": 40})
    lines = r.stdout.splitlines()
    assert r.returncode == 0 and len(lines) == 6 and "40줄 중 5줄 표시" in lines[-1]
    last = log.read_text().splitlines()[-1]
    assert "-readOnly" in last and "-noanalysis" in last and "0x1010" in last


def test_timeout_exits_2(tmp_path, fake_env):
    env, _ = fake_env
    r = run(["analyze"], tmp_path, **{**env, "FAKE_SLEEP": 30, "RE_TIMEOUT": 2})
    assert r.returncode == 2 and "시간 초과" in r.stderr


def test_usage_exits_2(tmp_path):
    r = run([], tmp_path)
    assert r.returncode == 2 and "analyze" in r.stdout


# ---- 실제 Ghidra (설치돼 있을 때만) ----
needs_real = pytest.mark.skipif(not HAS_REAL, reason="Ghidra 미설치")


def nm_addr(binary: Path, sym: str) -> int:
    for l in subprocess.run(["nm", str(binary)], capture_output=True, text=True).stdout.splitlines():
        p = l.split()
        if len(p) == 3 and p[2] == sym:
            return int(p[0], 16)
    raise AssertionError(sym)


@needs_real
def test_real_ghidra_pie_addresses_match_nm(tmp_path, tiny_pie):
    env = {"GHIDRA_HOME": REAL, "RE_TARGET": tiny_pie, "RE_GHIDRA_DIR": tmp_path / "g"}
    assert run(["analyze"], tmp_path, **env).returncode == 0
    want = nm_addr(tiny_pie, "check")
    rows = [l.split("\t") for l in (tmp_path / "g" / "functions.tsv").read_text().splitlines()[1:]]
    assert any(int(r[0], 16) == want and r[1] == "check" for r in rows)
    d = run(["decomp", hex(want)], tmp_path, **env)
    assert d.returncode == 0 and f"@ {hex(want)}" in d.stdout and "strcmp" in d.stdout


@needs_real
def test_real_ghidra_xrefs_finds_check_caller(tmp_path, tiny):
    env = {"GHIDRA_HOME": REAL, "RE_TARGET": tiny, "RE_GHIDRA_DIR": tmp_path / "g"}
    run(["analyze"], tmp_path, **env)
    out = run(["xrefs", "Correct"], tmp_path, **env).stdout
    assert hex(nm_addr(tiny, "main")) in out


@needs_real
def test_real_ghidra_does_not_touch_home(tmp_path, tiny):
    home = Path.home()
    watch = [home / ".ghidra", home / ".config" / "ghidra", home / ".cache" / "ghidra"]
    before = {p: (p.exists(), p.stat().st_mtime if p.exists() else 0) for p in watch}
    env = {"GHIDRA_HOME": REAL, "RE_TARGET": tiny, "RE_GHIDRA_DIR": tmp_path / "g"}
    assert run(["analyze"], tmp_path, **env).returncode == 0
    after = {p: (p.exists(), p.stat().st_mtime if p.exists() else 0) for p in watch}
    assert before == after


# ---- 최종 리뷰 반영 ----
def test_decomp_script_error_exits_2(tmp_path, fake_env):
    env, _ = fake_env
    run(["analyze"], tmp_path, **env)
    r = run(["decomp", "0x1010"], tmp_path, **{**env, "FAKE_SCRIPT_ERROR": 1})
    assert r.returncode == 2 and "스크립트 오류" in r.stderr


def test_decomp_empty_or_missing_output_exits_2(tmp_path, fake_env):
    env, _ = fake_env
    run(["analyze"], tmp_path, **env)
    r = run(["decomp", "0x1010"], tmp_path, **{**env, "FAKE_DECOMP_LINES": 0})
    assert r.returncode == 2 and "출력 없음" in r.stderr
    r = run(["decomp", "0x1010"], tmp_path, **{**env, "FAKE_NO_OUT": 1})
    assert r.returncode == 2 and "출력 없음" in r.stderr


def test_default_target_is_single_file_in_target_dir(tmp_path, tiny):
    (tmp_path / "target").mkdir()
    import shutil
    shutil.copy(tiny, tmp_path / "target" / "bin.exe")
    env = {"GHIDRA_HOME": FAKE, "FAKE_LOG": tmp_path / "l", "RE_GHIDRA_DIR": tmp_path / "g"}
    r = run(["analyze"], tmp_path, **env)
    assert r.returncode == 0, r.stderr
    assert "-import" in (tmp_path / "l").read_text() and "bin.exe" in (tmp_path / "l").read_text()


def test_ambiguous_target_mentions_re_target(tmp_path, tiny):
    (tmp_path / "target").mkdir()
    import shutil
    shutil.copy(tiny, tmp_path / "target" / "a")
    shutil.copy(tiny, tmp_path / "target" / "b")
    env = {"GHIDRA_HOME": FAKE, "FAKE_LOG": tmp_path / "l", "RE_GHIDRA_DIR": tmp_path / "g"}
    r = run(["analyze"], tmp_path, **env)
    assert r.returncode == 2 and "RE_TARGET" in r.stderr


@needs_real
def test_real_ghidra_decomp_accepts_objdump_style_addresses(tmp_path, tiny_pie):
    env = {"GHIDRA_HOME": REAL, "RE_TARGET": tiny_pie, "RE_GHIDRA_DIR": tmp_path / "g"}
    run(["analyze"], tmp_path, **env)
    want = nm_addr(tiny_pie, "check")
    for form in (format(want, "x"), format(want, "016x"), hex(want)):
        d = run(["decomp", form], tmp_path, **env)
        assert d.returncode == 0 and f"function check @ {hex(want)}" in d.stdout, (form, d.stdout, d.stderr)


@needs_real
def test_real_ghidra_no_writes_outside_work_dir(tmp_path, tiny):
    import time
    home = Path.home()
    user = os.environ.get("USER", "")
    watch = [home / ".ghidra", home / ".config" / "ghidra", home / ".cache" / "ghidra", Path(f"/tmp/hsperfdata_{user}")]
    t0 = time.time() - 1
    env = {"GHIDRA_HOME": REAL, "RE_TARGET": tiny, "RE_GHIDRA_DIR": tmp_path / "g"}
    assert run(["analyze"], tmp_path, **env).returncode == 0
    assert run(["decomp", "0x0"], tmp_path, **env).returncode in (0, 2)
    touched = [str(p) for w in watch if w.exists() for p in [w, *w.rglob("*")] if p.stat().st_mtime > t0]
    assert touched == []


def test_decomp_many_addresses_filename_ok(tmp_path, fake_env):
    env, _ = fake_env
    run(["analyze"], tmp_path, **env)
    addrs = [hex(0x140001000 + i * 16) for i in range(30)]
    r = run(["decomp", *addrs], tmp_path, **env)
    assert r.returncode == 0, r.stderr
