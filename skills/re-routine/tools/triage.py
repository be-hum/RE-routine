#!/usr/bin/env python3
"""0단계 triage: objdump/readelf로 사실을 모으고 분석 경로(objdump|ghidra)를 결정한다.

사용: python3 -I <스킬>/tools/triage.py TARGET [--task flag|functions|general] [--json]
"""
import argparse
import json
import re
import subprocess
import sys

TH = {"func_est": 200, "text_bytes": 65536, "ptr_run": 16}
STR_RE = re.compile(r"(?i)correct|wrong|flag|passw|key|input|success|fail|usage|invalid|error|nope|congrat")
CALL_RE = re.compile(r"\scall[q]?\s+(?:0x)?([0-9a-f]+)\b(?:\s+<([^>]*)>)?")
PLT_RE = re.compile(r"^[^+]*@plt$")  # 정확히 PLT 항목일 때만 (스트립된 바이너리의 <x@plt+0x..> 표기는 일반 함수)


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout


def file_format(path: str) -> str:
    m = re.search(r"file format (\S+)", sh("objdump", "-f", path))
    return m.group(1) if m else "unknown"


def sections(path: str) -> list:
    out = []
    for line in sh("objdump", "-h", "-w", path).splitlines():
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].isdigit():
            continue
        out.append({"name": parts[1], "size": int(parts[2], 16), "vma": int(parts[3], 16),
                    "off": int(parts[5], 16), "flags": parts[7]})
    return out


def func_symbols(path: str) -> int:
    return sum(1 for l in sh("objdump", "-t", path).splitlines() if " F " in l and ".text" in l)


def parse_call_targets(text: str, lo: int, hi: int) -> set:
    t = set()
    for m in CALL_RE.finditer(text):
        a = int(m.group(1), 16)
        if not PLT_RE.match(m.group(2) or "") and lo <= a < hi:
            t.add(a)
    return t


def call_targets(path: str, lo: int, hi: int) -> set:
    return parse_call_targets(sh("objdump", "-d", "-w", "--no-show-raw-insn", path), lo, hi)


def longest_run(offsets: list, step: int) -> int:
    best = cur = 0
    prev = None
    for o in sorted(set(offsets)):
        cur = cur + 1 if prev is not None and o - prev == step else 1
        best = max(best, cur)
        prev = o
    return best


def raw_ptr_run(path: str, secs: list, ptr: int, lo: int, hi: int) -> int:
    data = open(path, "rb").read()
    best = 0
    for s in secs:
        if "DATA" not in s["flags"] or "CONTENTS" not in s["flags"]:
            continue
        blob = data[s["off"]:s["off"] + s["size"]]
        offs = [s["vma"] + i for i in range(0, len(blob) - ptr + 1, ptr)
                if lo <= int.from_bytes(blob[i:i + ptr], "little") < hi]
        best = max(best, longest_run(offs, ptr))
    return best


def reloc_ptr_run(path: str, ptr: int, lo: int, hi: int) -> int:
    offs = []
    for line in sh("readelf", "-rW", path).splitlines():
        f = line.split()
        if len(f) >= 4 and f[2].endswith("_RELATIVE"):
            try:
                off, add = int(f[0], 16), int(f[-1], 16)
            except ValueError:
                continue
            if lo <= add < hi:
                offs.append(off)
    return longest_run(offs, ptr)


def interesting_strings(path: str) -> list:
    out = [s for s in sh("strings", "-a", "-n", "4", path).splitlines() if STR_RE.search(s)]
    return out[:30]


def collect(path: str) -> dict:
    fmt = file_format(path)
    ptr = 8 if "64" in fmt else 4
    secs = sections(path)
    code = [s for s in secs if "CODE" in s["flags"]]
    lo = min((s["vma"] for s in code), default=0)
    hi = max((s["vma"] + s["size"] for s in code), default=0)
    nsym = func_symbols(path)
    run = raw_ptr_run(path, secs, ptr, lo, hi)
    if fmt.startswith("elf"):
        run = max(run, reloc_ptr_run(path, ptr, lo, hi))
    return {"format": fmt, "ptr_size": ptr, "text_bytes": sum(s["size"] for s in code),
            "text_lo": lo, "text_hi": hi, "stripped": nsym == 0,
            "func_est": max(nsym, len(call_targets(path, lo, hi))),
            "max_code_ptr_run": run, "strings": interesting_strings(path)}


def decide(facts: dict, task: str = "general", th: dict = TH) -> tuple:
    why = []
    if task == "functions":
        why.append("R1 task=functions: 전체 함수 목록이 과제")
    if facts["func_est"] >= th["func_est"]:
        why.append(f"R2 func_est={facts['func_est']} >= {th['func_est']}")
    if facts["stripped"] and facts["text_bytes"] >= th["text_bytes"]:
        why.append(f"R3 stripped, text_bytes={facts['text_bytes']} >= {th['text_bytes']}")
    if facts["max_code_ptr_run"] >= th["ptr_run"]:
        why.append(f"R4 max_code_ptr_run={facts['max_code_ptr_run']} >= {th['ptr_run']} (dispatch 테이블/VM 신호)")
    if why:
        return "ghidra", why
    return "objdump", ["규칙 R1–R4 해당 없음: 작은 바이너리, dispatch 테이블 신호 없음"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("target")
    ap.add_argument("--task", choices=["flag", "functions", "general"], default="general")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--th-func-est", type=int, default=TH["func_est"])
    ap.add_argument("--th-text-bytes", type=int, default=TH["text_bytes"])
    ap.add_argument("--th-ptr-run", type=int, default=TH["ptr_run"])
    a = ap.parse_args()
    try:
        open(a.target, "rb").close()
    except OSError as e:
        print(f"triage: 대상 없음 또는 읽을 수 없음: {a.target} ({e})", file=sys.stderr)
        return 2
    th = {"func_est": a.th_func_est, "text_bytes": a.th_text_bytes, "ptr_run": a.th_ptr_run}
    facts = collect(a.target)
    rec, why = decide(facts, a.task, th)
    if a.json:
        print(json.dumps({"facts": facts, "recommend": rec, "reasons": why, "thresholds": th},
                         ensure_ascii=False, indent=1))
        return 0
    print(f"format={facts['format']} text_bytes={facts['text_bytes']} stripped={'yes' if facts['stripped'] else 'no'} "
          f"func_est={facts['func_est']} max_code_ptr_run={facts['max_code_ptr_run']}")
    print("strings: " + " | ".join(facts["strings"][:10]))
    print(f"RECOMMEND={rec}")
    for w in why:
        print(f"REASON: {w}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
