import json
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import ROOT, build, many_c, stripped_copy, table_c, TINY_C

sys.path.insert(0, str(ROOT / "skills" / "re-routine" / "tools"))
import triage  # noqa: E402

BASE = {"format": "elf64-x86-64", "ptr_size": 8, "text_bytes": 4000, "text_lo": 0x1000,
        "text_hi": 0x2000, "stripped": False, "func_est": 10, "max_code_ptr_run": 1, "strings": []}


def f(**kw):
    d = dict(BASE); d.update(kw); return d


def test_decide_small_is_objdump():
    rec, why = triage.decide(f())
    assert rec == "objdump" and why


def test_decide_functions_task_is_ghidra():
    assert triage.decide(f(), task="functions")[0] == "ghidra"


def test_decide_many_functions():
    rec, why = triage.decide(f(func_est=200))
    assert rec == "ghidra" and any("func_est" in w for w in why)


def test_decide_big_stripped_only_when_stripped():
    assert triage.decide(f(text_bytes=70000, stripped=True))[0] == "ghidra"
    assert triage.decide(f(text_bytes=70000, stripped=False))[0] == "objdump"


def test_decide_pointer_table():
    rec, why = triage.decide(f(max_code_ptr_run=16))
    assert rec == "ghidra" and any("ptr" in w for w in why)


def test_thresholds_override():
    assert triage.decide(f(func_est=50), th={**triage.TH, "func_est": 40})[0] == "ghidra"


def test_collect_tiny(tiny):
    facts = triage.collect(str(tiny))
    assert facts["stripped"] is False
    assert facts["func_est"] < 50
    assert facts["max_code_ptr_run"] < 16
    assert any("Correct" in s for s in facts["strings"])
    assert triage.decide(facts)[0] == "objdump"


def test_collect_tiny_stripped(tiny):
    facts = triage.collect(str(stripped_copy(tiny)))
    assert facts["stripped"] is True
    assert triage.decide(facts)[0] == "objdump"


def test_collect_many(tmp_path):
    p = build(tmp_path, "many", many_c(300))
    facts = triage.collect(str(p))
    assert facts["func_est"] >= 300
    assert triage.decide(facts)[0] == "ghidra"


@pytest.mark.parametrize("flags", [("-fPIE", "-pie"), ("-fno-pie", "-no-pie")])
def test_collect_pointer_table(tmp_path, flags):
    p = build(tmp_path, "tbl", table_c(20), *flags)
    facts = triage.collect(str(p))
    assert facts["func_est"] < 200
    assert facts["max_code_ptr_run"] >= 20
    rec, why = triage.decide(facts)
    assert rec == "ghidra" and any("ptr" in w for w in why)


def test_cli_json(tiny):
    out = subprocess.run([sys.executable, "-I", str(ROOT / "skills/re-routine/tools/triage.py"), str(tiny), "--json"],
                         capture_output=True, text=True, check=True).stdout
    d = json.loads(out)
    assert d["recommend"] == "objdump" and "facts" in d and d["reasons"]


def test_cli_text_has_recommend_line(tiny):
    out = subprocess.run([sys.executable, "-I", str(ROOT / "skills/re-routine/tools/triage.py"), str(tiny), "--task", "functions"],
                         capture_output=True, text=True, check=True).stdout
    assert "RECOMMEND=ghidra" in out and "REASON:" in out


def test_cli_missing_file_exits_2(tmp_path):
    r = subprocess.run([sys.executable, "-I", str(ROOT / "skills/re-routine/tools/triage.py"), str(tmp_path / "nope")],
                       capture_output=True, text=True)
    assert r.returncode == 2 and "없음" in r.stderr


def test_collect_many_stripped_still_counts_calls(tmp_path):
    # 스트립된 ELF에서 objdump는 call 대상을 <puts@plt+0x...>처럼 표기한다 — PLT로 오인하면 안 됨
    p = stripped_copy(build(tmp_path, "many", many_c(300)))
    assert triage.collect(str(p))["func_est"] >= 300


def test_call_regex_pe_and_plt_forms():
    lines = ("   140001015:\tcall   0x140001eb8\n"
             "    32a2:\tcall   3100 <__cxa_finalize@plt>\n"
             "    4000:\tcall   7a96d <rand@plt+0x7779d>\n")
    got = triage.parse_call_targets(lines, 0, 1 << 40)
    assert got == {0x140001eb8, 0x7a96d}
