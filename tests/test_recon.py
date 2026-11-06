import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import (HIDDEN_C, INDIRECT_C, NETWORK_C, PLAIN_C, ROOT, build, many_c, nm_addr,
                      stripped_copy, table_c)

sys.path.insert(0, str(ROOT / "skills" / "re-routine" / "tools"))
import recon  # noqa: E402

RECON = ROOT / "skills" / "re-routine" / "tools" / "recon.py"
FAKE = ROOT / "tests" / "fake_ghidra"


def run_recon(target, out, *args, **env):
    e = dict(os.environ, GHIDRA_HOME=str(FAKE), FAKE_LOG=str(Path(out).parent / "calls.log"),
             RE_GHIDRA_DIR=str(Path(out).parent / "_ghidra"))
    e.update({k: str(v) for k, v in env.items()})
    return subprocess.run([sys.executable, "-I", str(RECON), str(target), "--out", str(out), *args],
                          capture_output=True, text=True, env=e)


def load(out):
    return json.loads((Path(out) / "recon.json").read_text())


# ---------- 명령어 파싱 (단위) ----------
def test_parse_insn_kinds():
    k = lambda t: recon.parse_insn(t)
    assert k("call   401020 <puts@plt>") == ("call", 0x401020)
    assert k("call   0x140001eb8") == ("call", 0x140001eb8)
    assert k("call   *0x10f1(%rip)        # 0x140002190") == ("call_slot", 0x140002190)
    assert k("jmp    *0x2fe2(%rip)        # 4018 <puts@GLIBC_2.2.5>") == ("jmp_slot", 0x4018)
    assert k("call   *%rax") == ("indirect", None)
    assert k("notrack jmp *%rax") == ("indirect", None)
    assert k("jmp    1200 <f+0x10>") == ("jmp", 0x1200)
    assert k("jne    1200 <f+0x10>") == (None, None)
    assert k("lea    0x2ee5(%rip),%rcx        # 0x140003000") == ("ref", 0x140003000)
    assert k("mov    0x2e8f(%rip),%eax        # 4010 <x>") == ("ref", 0x4010)
    assert k("mov    $0x404020,%edi") == ("imm", 0x404020)
    assert k("ret") == (None, None)
    assert k("callq  401020 <puts@plt>") == ("call", 0x401020)
    assert k("jmpq   *0x2fe2(%rip)        # 4018 <x>") == ("jmp_slot", 0x4018)


def test_parse_pe_imports():
    txt = ("\tDLL Name: api-ms-win-crt-string-l1-1-0.dll\n\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"
           "\t000021a8  <none>  0086  strcmp\n\n\tDLL Name: KERNEL32.dll\n\tvma:     Ordinal  Hint  Member-Name  Bound-To\n"
           "\t00002000  <none>  0123  GetStdHandle\n")
    assert recon.parse_pe_imports(txt, 0x140000000) == {0x1400021a8: "strcmp", 0x140002000: "GetStdHandle"}


def test_decide_rules():
    base = {"packed": False, "goal": "input-check", "anchors": 1, "region_bytes": 500, "region_indirect": 0,
            "region_tables": 0, "func_count": 30, "text_bytes": 4000, "stripped": True, "fallback": False}
    d = lambda **kw: recon.decide({**base, **kw}, recon.TH)[0]
    assert d() == "none"
    assert d(region_bytes=5000) == "partial"
    assert d(region_indirect=1) == "partial"
    assert d(packed=True) == "stop"
    assert d(goal="inventory") == "full"
    assert d(goal="overview", anchors=0) == "none"
    assert d(goal="overview", anchors=0, text_bytes=100000) == "full"
    assert d(anchors=0, fallback=True) == "none"
    assert d(anchors=0, fallback=True, func_count=500) == "full"


# ---------- 주소 참조 그래프 (합성 바이너리) ----------
def test_bounds_from_eh_frame_match_symbols(synth, tmp_path):
    b, truth = synth("plain", PLAIN_C)
    out = tmp_path / "o"
    assert run_recon(b, out, "--goal", "input-check", "--no-ghidra").returncode == 0
    r = load(out)
    assert r["bounds"] == "eh_frame"
    starts = {int(f["addr"], 16) for f in r["functions"]}
    assert truth["check"] in starts and truth["main"] in starts


def test_plain_check_found_via_string_and_import(synth, tmp_path):
    b, truth = synth("plain", PLAIN_C)
    out = tmp_path / "o"
    run_recon(b, out, "--goal", "input-check", "--no-ghidra")
    r = load(out)
    region = {int(f["addr"], 16): f for f in r["region"]}
    assert truth["check"] in region and region[truth["check"]]["distance"] <= 1
    assert truth["main"] in {int(a, 16) for a in r["anchors"]}
    kinds = {e.split("\t")[4] for e in (out / "xrefs.tsv").read_text().splitlines()[1:]}
    assert {"call", "ref"} <= kinds


def test_hidden_strings_found_via_imports(synth, tmp_path):
    b, truth = synth("hidden", HIDDEN_C)
    out = tmp_path / "o"
    run_recon(b, out, "--goal", "input-check", "--no-ghidra")
    r = load(out)
    assert truth["check"] in {int(f["addr"], 16) for f in r["region"]}
    assert any("memcmp" in s for s in r["seeds"])


def test_indirect_uses_fallback(synth, tmp_path):
    b, truth = synth("indirect", INDIRECT_C)
    out = tmp_path / "o"
    run_recon(b, out, "--goal", "input-check", "--no-ghidra")
    r = load(out)
    assert r["fallback"] is True
    assert truth["check"] in {int(f["addr"], 16) for f in r["region"]}


def test_network_goal(synth, tmp_path):
    b, truth = synth("net", NETWORK_C, syms=("main", "beacon"))
    out = tmp_path / "o"
    run_recon(b, out, "--goal", "network", "--no-ghidra")
    r = load(out)
    region = {int(f["addr"], 16): f for f in r["region"]}
    assert truth["beacon"] in region and region[truth["beacon"]]["distance"] == 0


def test_anchor_address_option(synth, tmp_path):
    b, truth = synth("plain", PLAIN_C)
    out = tmp_path / "o"
    run_recon(b, out, "--goal", "overview", "--anchor", hex(truth["check"]), "--no-ghidra")
    r = load(out)
    assert hex(truth["check"]) in r["anchors"]


def test_table_triggers_partial(tmp_path):
    p = stripped_copy(build(tmp_path, "tbl", table_c(20)))
    out = tmp_path / "o"
    run_recon(p, out, "--goal", "input-check", "--no-ghidra")
    r = load(out)
    assert r["decision"]["decision"] == "partial", r["decision"]


def test_inventory_is_full(tmp_path):
    p = stripped_copy(build(tmp_path, "many", many_c(300)))
    out = tmp_path / "o"
    run_recon(p, out, "--goal", "inventory", "--no-ghidra")
    assert load(out)["decision"]["decision"] == "full"


# ---------- 산출물 ----------
def test_outputs_and_structure_md(synth, tmp_path):
    b, truth = synth("plain", PLAIN_C)
    out = tmp_path / "o"
    r = run_recon(b, out, "--goal", "input-check", "--no-ghidra")
    assert r.returncode == 0, r.stderr
    for f in ["structure.md", "recon.json", "functions.tsv", "xrefs.tsv", "region.tsv"]:
        assert (out / f).exists(), f
    md = (out / "structure.md").read_text()
    for h in ["## 1. 기본 정보", "## 2. 하는 일", "## 3. 함수 지도", "## 4. 목적 관련 위치",
              "## 5. Ghidra 결정", "## 6. 산출물", "## 7. 다음 단계"]:
        assert h in md, h
    assert len(md.splitlines()) <= 300
    assert (out / "disasm" / f"{truth['check']:x}.s").exists()


def test_xref_query(synth, tmp_path):
    b, truth = synth("plain", PLAIN_C)
    out = tmp_path / "o"
    run_recon(b, out, "--goal", "input-check", "--no-ghidra")
    q = subprocess.run([sys.executable, "-I", str(RECON), "xref", "--to", hex(truth["check"]), "--out", str(out)],
                       capture_output=True, text=True)
    assert q.returncode == 0 and hex(truth["main"]) in q.stdout
    q2 = subprocess.run([sys.executable, "-I", str(RECON), "xref", "--from", hex(truth["check"]), "--out", str(out)],
                        capture_output=True, text=True)
    assert "strcmp" in q2.stdout


def test_partial_runs_ghidra_wrapper(tmp_path):
    p = stripped_copy(build(tmp_path, "tbl", table_c(20)))
    out = tmp_path / "o"
    r = run_recon(p, out, "--goal", "input-check")
    assert r.returncode == 0, r.stderr
    calls = (tmp_path / "calls.log").read_text().splitlines()
    assert any("-import" in c for c in calls) and any("DecompileAt.java" in c for c in calls)
    assert load(out)["ghidra"]["ran"] is True


def test_missing_target_exits_2(tmp_path):
    r = run_recon(tmp_path / "nope", tmp_path / "o", "--goal", "overview")
    assert r.returncode == 2 and "없음" in r.stderr


def test_bad_goal_rejected(synth, tmp_path):
    b, _ = synth("plain", PLAIN_C)
    r = run_recon(b, tmp_path / "o", "--goal", "nonsense")
    assert r.returncode == 2


def test_merge_call_targets_adds_leaf_functions():
    # .pdata는 스택을 쓰지 않는 leaf 함수를 싣지 않는다 → 직접 call 대상이면 함수로 보충
    rng = {0x1100: 0x1180, 0x1200: 0x1250}
    got = recon.merge_call_targets(rng, {0x1000, 0x1100, 0x1190, 0x1210}, 0x1300)
    assert got[0x1000] == 0x1100          # 다음 함수 시작까지
    assert got[0x1190] == 0x1200
    assert 0x1210 not in got              # 이미 있는 함수 내부
    assert got[0x1100] == 0x1180


def test_unsupported_format_is_reported_not_misjudged(tmp_path):
    # wasm 등 objdump가 해석하지 못하는 형식은 빈 지도로 'none'을 내지 말고 unsupported로 알린다
    w = tmp_path / "x.dex"
    w.write_bytes(b"dex\n035\x00" + b"\x00" * 64)
    out = tmp_path / "o"
    r = run_recon(w, out, "--goal", "input-check")
    assert r.returncode == 0, r.stderr
    d = load(out)
    assert d["decision"]["decision"] == "unsupported"
    assert "dex" in d["decision"]["reason"].lower()
    md = (out / "structure.md").read_text()
    assert "unsupported" in md and "jadx" in md


# ---------- wasm ----------
def wasm_addr(path, name):
    for l in subprocess.run(["wasm-objdump", "-d", str(path)], capture_output=True, text=True).stdout.splitlines():
        m = __import__("re").match(r"^([0-9a-f]+) func\[\d+\] <(.+)>:$", l)
        if m and m.group(2) == name:
            return int(m.group(1), 16)
    raise AssertionError(name)


def test_wasm_region_contains_check(wasm_mod, tmp_path):
    out = tmp_path / "o"
    r = run_recon(wasm_mod, out, "--goal", "input-check")
    assert r.returncode == 0, r.stderr
    d = load(out)
    assert d["format"] == "wasm" and d["bounds"] == "wasm-code"
    region = {int(x["addr"], 16): x for x in d["region"]}
    assert wasm_addr(wasm_mod, "check") in region
    assert wasm_addr(wasm_mod, "main") in {int(a, 16) for a in d["anchors"]}
    assert any("Correct" in s for s in d["seeds"]) and any("memcmp" in s for s in d["seeds"])


def test_wasm_table_and_indirect_trigger_partial_with_decompile(wasm_mod, tmp_path):
    out = tmp_path / "o"
    run_recon(wasm_mod, out, "--goal", "input-check")
    d = load(out)
    assert d["decision"]["decision"] == "partial", d["decision"]
    assert d["ghidra"]["tool"] == "wasm-decompile" and d["ghidra"]["ran"] is True
    assert (out / "decomp" / f"{wasm_addr(wasm_mod, 'check'):x}.dcmp").exists()
    assert (out / "disasm" / f"{wasm_addr(wasm_mod, 'check'):x}.s").exists()


def test_wasm_xref_and_structure(wasm_mod, tmp_path):
    out = tmp_path / "o"
    run_recon(wasm_mod, out, "--goal", "input-check")
    q = subprocess.run([sys.executable, "-I", str(RECON), "xref", "--to", hex(wasm_addr(wasm_mod, "check")), "--out", str(out)],
                       capture_output=True, text=True)
    assert hex(wasm_addr(wasm_mod, "main")) in q.stdout
    md = (out / "structure.md").read_text()
    assert "wasm-interp --wasi" in md and "## 7. 다음 단계" in md


def test_wasm_library_functions_not_anchors(wasm_mod, tmp_path):
    # 이름이 있으면 표준 라이브러리(core::, std:: …) 함수는 앵커로 삼지 않고, 그 너머로 탐색을 넓히지 않는다
    out = tmp_path / "o"
    run_recon(wasm_mod, out, "--goal", "input-check")
    d = load(out)
    anchors = {int(a, 16) for a in d["anchors"]}
    assert wasm_addr(wasm_mod, "core::panicking::panic") not in anchors
    assert wasm_addr(wasm_mod, "main") in anchors
    region = {int(x["addr"], 16): x for x in d["region"]}
    assert wasm_addr(wasm_mod, "check") in region
    assert wasm_addr(wasm_mod, "core::panicking::panic") not in region   # _print(라이브러리) 너머는 넓히지 않음


def test_wasm_region_rows_have_names_and_mem_data_files(wasm_mod, tmp_path):
    out = tmp_path / "o"
    run_recon(wasm_mod, out, "--goal", "input-check")
    d = load(out)
    names = {x["name"] for x in d["region"]}
    assert "check" in names and "main" in names
    assert all(not x["lib"] for x in d["region"] if x["name"] in ("check", "main"))
    assert any(p.name.startswith("mem_") for p in (out / "data").iterdir())
    assert "| 이름 |" in (out / "structure.md").read_text()


# ---------- 검사 사슬 (앵커 함수 내부의 입력→변환→비교 순서) ----------
def test_check_chain_splits_stages(tmp_path):
    from conftest import TWOSTAGE_C
    p = stripped_copy(build(tmp_path, "two", TWOSTAGE_C))
    out = tmp_path / "o"
    r = run_recon(p, out, "--goal", "input-check", "--no-ghidra")
    assert r.returncode == 0, r.stderr
    d = load(out)
    chains = d["check_chains"]
    assert chains, "검사 사슬 없음"
    c = chains[0]
    stages = [s for s in c["stages"] if s["inputs"]]
    assert len(stages) >= 2
    assert "strcmp" in " ".join(stages[0]["compares"])
    assert any("memcmp" in x for s in stages[1:] for x in s["compares"])
    assert any("system" in x for s in c["stages"] for x in s["sinks"])
    assert any("exit" in x for s in c["stages"] for x in s["exits"])
    md = (out / "structure.md").read_text()
    assert "## 4-1. 검사 사슬" in md and "단계 1" in md and "단계 2" in md
    assert (out / "chain" / f"{int(c['addr'], 16):x}.txt").exists()


def test_check_chain_wasm_names(wasm_mod, tmp_path):
    out = tmp_path / "o"
    run_recon(wasm_mod, out, "--goal", "input-check")
    d = load(out)
    txt = " ".join(" ".join(s["compares"]) for c in d["check_chains"] for s in c["stages"])
    assert "check" in txt or "memcmp" in txt


def test_check_chain_long_lib_names_and_stdin_getter(wasm_mod, tmp_path):
    out = tmp_path / "o"
    run_recon(wasm_mod, out, "--goal", "input-check")
    d = load(out)
    main = [c for c in d["check_chains"] if c["name"] == "main"][0]
    with_inputs = [s for s in main["stages"] if s["inputs"]]
    assert len(with_inputs) == 1                       # stdin() 핸들 얻기는 입력이 아님
    assert any("PartialEq" in x for s in main["stages"] for x in s["compares"])   # 긴 이름도 전체로 분류


# ---------- 독립 패키지용: 경로 독립성 ----------
def test_default_ghidra_dir_is_under_out_when_no_prewarm(tmp_path):
    p = stripped_copy(build(tmp_path, "tbl", table_c(20)))
    out = tmp_path / "o"
    e = dict(os.environ, GHIDRA_HOME=str(FAKE), FAKE_LOG=str(tmp_path / "calls.log"))
    e.pop("RE_GHIDRA_DIR", None)
    r = subprocess.run([sys.executable, "-I", str(RECON), str(p), "--goal", "input-check", "--out", str(out)],
                       capture_output=True, text=True, env=e, cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert (out / "_ghidra" / "functions.tsv").exists()
    assert not (tmp_path / "_ghidra").exists()
    assert load(out)["ghidra"]["dir"] == str(out / "_ghidra")


def test_structure_next_steps_have_exact_commands(tmp_path):
    p = stripped_copy(build(tmp_path, "tbl", table_c(20)))
    out = tmp_path / "o"
    run_recon(p, out, "--goal", "input-check")
    md = (out / "structure.md").read_text()
    assert f"{RECON} xref --to 0x" in md and f"--out {out}" in md
    assert "ghidra_re.sh decomp" in md and f"RE_TARGET={p}" in md
