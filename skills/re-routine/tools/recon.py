#!/usr/bin/env python3
"""구조 파악 + 주소 참조 그래프 + Ghidra 범위 결정 루틴 (recon v2).

사용:
  python3 -I <스킬>/tools/recon.py TARGET --goal <범주> [--anchor 정규식|0x주소]... [--out work/recon] [--no-ghidra]
  python3 -I <스킬>/tools/recon.py xref (--to ADDR | --from ADDR) [--out work/recon]

범주: input-check | network | file | crypto | inventory | overview
"""
import argparse
import bisect
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import triage  # noqa: E402
import recon_wasm  # noqa: E402

TH = {"region_bytes": 2048, "partial_max": 20, "depth": 1, "func_count": 200, "text_bytes": 65536,
      "ptr_run": 16, "max_lines": 300}

GOALS = {
    "input-check": (
        r"(?i)correct|wrong|flag|passw|serial|licen[cs]e|invalid|congrat|nope|try again|success|fail|\bkey\b",
        r"^(strcmp|strncmp|memcmp|bcmp|strcasecmp|wcscmp|scanf|__isoc99_scanf|__stdio_common_vfscanf|fgets|getline"
        r"|gets|read|fd_read|ReadConsoleA|ReadConsoleW|lstrcmpA|lstrcmpW|CompareStringA|CompareStringW)$"),
    "network": (
        r"(?i)https?://|\b(?:\d{1,3}\.){3}\d{1,3}\b|\bhost\b|user-agent|\bGET \b|\bPOST \b",
        r"^(socket|connect|bind|listen|accept|send|sendto|recv|recvfrom|getaddrinfo|gethostbyname|inet_pton|inet_addr"
        r"|WSAStartup|WSASocketW|InternetOpenA|InternetOpenW|InternetConnectA|InternetConnectW|HttpSendRequestA"
        r"|HttpSendRequestW|WinHttpOpen|WinHttpConnect|URLDownloadToFileA|URLDownloadToFileW)$"),
    "file": (
        r"(?i)\.(?:conf|cfg|ini|json|txt|log|dat)\b|/etc/|/tmp/|[A-Z]:\\|config",
        r"^(fopen|fopen64|open|open64|openat|fread|fwrite|fscanf|stat|unlink|_wfopen|CreateFileA|CreateFileW"
        r"|ReadFile|WriteFile|DeleteFileA|DeleteFileW)$"),
    "crypto": (
        r"(?i)\baes\b|sha-?\d|\bmd5\b|encrypt|decrypt|cipher|\biv\b",
        r"^(Crypt\w+|BCrypt\w+|EVP_\w+|AES_\w+|SHA\d*_\w+|MD5_\w+|RAND_bytes)$"),
    "inventory": (None, None),
    "overview": (None, None),
}
# 알려진 암호 상수 (파일 안 바이트 패턴, 길이)
CRYPTO_CONST = {
    "AES S-box": (bytes.fromhex("637c777bf26b6fc53001672bfed7ab76"), 256),
    "AES inv S-box": (bytes.fromhex("52096ad53036a538bf40a39e81f3d7fb"), 256),
    "SHA-256 K": (bytes.fromhex("982f8a4291443771cffbc0b5a5dbb5e9"), 256),
    "MD5 T": (bytes.fromhex("78a46ad756b7c7e8db702024eecebdc1"), 256),
    "CRC32 table": (bytes.fromhex("00000000963007772c610eeeba510999"), 1024),
}
CRYPTO_IMM = {0x9E3779B9: "TEA/XTEA delta", 0x61C88647: "TEA delta (neg)"}

# 이름이 남아 있을 때(wasm 이름 섹션 등) 표준 라이브러리·런타임 함수를 가려내는 규칙
LIB_RE = re.compile(
    r"^<?(core|std|alloc|compiler_builtins|dlmalloc|hashbrown|memchr|addr2line|gimli|miniz_oxide|rustc_demangle"
    r"|object|adler2?|wasi|panic_unwind|panic_abort|libc|unwind|backtrace)::"
    r"|^(__|_start$|_initialize$|abort$|exit$|dl(malloc|free|realloc|memalign)|mem(cpy|move|set|cmp|chr)$|str\w*$"
    r"|bcmp$|malloc$|free$|calloc$|realloc$|rust_|__rust|__wasi|__wasm|func_\d+$)")
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\t(.*)$")
HDR_RE = re.compile(r"^([0-9a-f]+) <([^>]+)>:$")
SEC_RE = re.compile(r"^Disassembly of section (\S+):")
PREFIX_RE = re.compile(r"^(?:(?:notrack|bnd|lock|repn?[ez]?|data16|cs|ds)\s+)+")
COMMENT_RE = re.compile(r"#\s+(?:0x)?([0-9a-f]+)")
DIRECT_RE = re.compile(r"^(?:0x)?([0-9a-f]+)\b")
IMM_RE = re.compile(r"\$0x([0-9a-f]+)")


def die(msg: str):
    print(f"recon: {msg}", file=sys.stderr)
    sys.exit(2)


def sh(*cmd: str) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout


# ---------------------------------------------------------------- 명령어 해석
def parse_insn(text: str):
    """objdump 한 명령(주소 뒤 텍스트) → (간선 종류, 도착 주소). 간선이 아니면 (None, None)."""
    t = PREFIX_RE.sub("", text.strip())
    parts = t.split(None, 1)
    if not parts:
        return None, None
    mn, rest = parts[0], (parts[1] if len(parts) > 1 else "")
    base = mn[:-1] if mn in ("callq", "calll", "jmpq", "jmpl") else mn   # 이전 objdump의 크기 접미사
    if base in ("call", "jmp"):
        if rest.startswith("*"):
            m = COMMENT_RE.search(rest)
            if m:
                return ("call_slot" if base == "call" else "jmp_slot"), int(m.group(1), 16)
            return "indirect", None
        m = DIRECT_RE.match(rest)
        if m:
            return base, int(m.group(1), 16)
        return None, None
    if mn.startswith("j") or mn.startswith("loop"):
        return None, None          # 조건 분기 (함수 내부 흐름)
    m = COMMENT_RE.search(rest)
    if m:
        return "ref", int(m.group(1), 16)
    m = IMM_RE.search(rest)
    if m:
        return "imm", int(m.group(1), 16)
    return None, None


def parse_pe_imports(text: str, image_base: int) -> dict:
    out, in_dll = {}, False
    for line in text.splitlines():
        if "DLL Name:" in line:
            in_dll = True
            continue
        if not line.strip():
            in_dll = False
            continue
        if in_dll:
            f = line.split()
            if len(f) >= 4 and re.fullmatch(r"[0-9a-f]{6,16}", f[0]):
                out[image_base + int(f[0], 16)] = f[3]
    return out


# ---------------------------------------------------------------- 대상 적재
class Bin:
    def __init__(self, path: str):
        self.path = path
        self.raw = open(path, "rb").read()
        self.fmt = triage.file_format(path)
        self.is_elf = self.fmt.startswith("elf")
        self.is_pe = self.fmt.startswith("pe")
        self.ptr = 8 if "64" in self.fmt else 4
        self.secs = triage.sections(path)
        self.code = [s for s in self.secs if "CODE" in s["flags"]]
        self.lo = min((s["vma"] for s in self.code), default=0)
        self.hi = max((s["vma"] + s["size"] for s in self.code), default=0)
        self.text_bytes = sum(s["size"] for s in self.code)
        self.image_base = 0
        if self.is_pe:
            m = re.search(r"ImageBase\s+([0-9a-f]+)", sh("objdump", "-p", path))
            self.image_base = int(m.group(1), 16) if m else 0
        self.relocs = sh("readelf", "-rW", path) if self.is_elf else ""
        self.pie = self.is_elf and "DYN" in sh("readelf", "-h", path)
        self.nsym = triage.func_symbols(path)
        m = re.search(r"start address (0x[0-9a-f]+)", sh("objdump", "-f", path))
        self.entry = int(m.group(1), 16) if m else None

    def sec_of(self, va: int):
        for s in self.secs:
            if s["vma"] <= va < s["vma"] + s["size"]:
                return s
        return None

    def read_va(self, va: int, n: int) -> bytes:
        s = self.sec_of(va)
        if not s or "CONTENTS" not in s["flags"]:
            return b""
        o = s["off"] + va - s["vma"]
        return self.raw[o:o + min(n, s["vma"] + s["size"] - va)]

    def va_of_off(self, off: int):
        for s in self.secs:
            if "CONTENTS" in s["flags"] and s["off"] <= off < s["off"] + s["size"]:
                return s["vma"] + off - s["off"], s
        return None, None


def func_bounds(b: Bin):
    plt = [s for s in b.secs if s["name"].startswith(".plt")]
    in_plt = lambda a: any(s["vma"] <= a < s["vma"] + s["size"] for s in plt)
    rng = {}
    if b.is_elf:
        for m in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", sh("readelf", "--debug-dump=frames", b.path)):
            s, e = int(m.group(1), 16), int(m.group(2), 16)
            if e > s and not in_plt(s):
                rng[s] = max(rng.get(s, 0), e)
        method = "eh_frame"
    else:
        pd = [s for s in b.secs if s["name"] == ".pdata"]
        if pd:
            raw = b.raw[pd[0]["off"]:pd[0]["off"] + pd[0]["size"]]
            for i in range(0, len(raw) - 11, 12):
                s, e = int.from_bytes(raw[i:i + 4], "little"), int.from_bytes(raw[i + 4:i + 8], "little")
                if s and e > s:
                    rng[b.image_base + s] = max(rng.get(b.image_base + s, 0), b.image_base + e)
        method = "pdata"
    if not rng:
        return None, "estimated"
    if b.entry and b.entry not in rng and not any(s <= b.entry < e for s, e in rng.items()):
        nxt = min((s for s in rng if s > b.entry), default=b.hi)
        rng[b.entry] = nxt
    return rng, method


def merge_call_targets(rng: dict, targets, hi: int) -> dict:
    """경계 표에 없는 직접 call 대상을 함수로 보충 (PE .pdata는 leaf 함수를 싣지 않음)."""
    out = dict(rng)
    starts = sorted(out)
    for t in sorted(targets):
        i = bisect.bisect_right(starts, t) - 1
        if i >= 0 and t < out[starts[i]]:
            continue
        j = bisect.bisect_right(starts, t)
        out[t] = starts[j] if j < len(starts) else hi
        starts.insert(j, t)
    return out


def string_objs(b: Bin) -> dict:
    out = {}
    for enc in ("s", "l"):
        for line in sh("strings", "-a", "-t", "x", "-n", "4", "-e", enc, b.path).splitlines():
            m = re.match(r"\s*([0-9a-f]+)\s(.*)", line)
            if not m:
                continue
            va, s = b.va_of_off(int(m.group(1), 16))
            if va is None or "CODE" in s["flags"] or s["name"] in (".dynstr", ".strtab", ".gnu.version", ".gnu.version_r", ".dynsym"):
                continue
            text = m.group(2)
            out[va] = (text, len(text) * (2 if enc == "l" else 1) + 1)
    return out


def imports(b: Bin, plt_names: dict) -> dict:
    if b.is_pe:
        return parse_pe_imports(sh("objdump", "-p", b.path), b.image_base)
    out = dict(plt_names)
    for line in b.relocs.splitlines():
        f = line.split()
        if len(f) >= 5 and (f[2].endswith("JUMP_SLOT") or f[2].endswith("GLOB_DAT")):
            try:
                out[int(f[0], 16)] = f[4].split("@")[0]
            except ValueError:
                pass
    return out


def disassemble(b: Bin):
    insns, plt_names, sec = [], {}, ""
    for line in sh("objdump", "-d", "-w", "--no-show-raw-insn", b.path).splitlines():
        m = SEC_RE.match(line)
        if m:
            sec = m.group(1)
            continue
        m = HDR_RE.match(line)
        if m:
            if m.group(2).endswith("@plt"):
                plt_names[int(m.group(1), 16)] = m.group(2)[:-4]
            continue
        m = INSN_RE.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2), sec))
    return insns, plt_names


# ---------------------------------------------------------------- 그래프
class Graph:
    def __init__(self, b):
        self.b = b
        self.wasm = isinstance(b, recon_wasm.WasmBin)
        if self.wasm:
            recon_wasm.build(self, b)
            return
        self.names = {}
        insns, plt_names = disassemble(b)
        self.insns = insns
        rng, self.bounds = func_bounds(b)
        if rng is None:
            starts = set(triage.parse_call_targets("\n".join("\t" + t for _, t, _ in insns), b.lo, b.hi))
            if b.entry:
                starts.add(b.entry)
            ss = sorted(starts)
            rng = {s: (ss[i + 1] if i + 1 < len(ss) else b.hi) for i, s in enumerate(ss)}
        else:
            targets = triage.parse_call_targets("\n".join("\t" + t for _, t, sec in insns if not sec.startswith(".plt")),
                                                b.lo, b.hi)
            rng = merge_call_targets(rng, {t for t in targets if t not in plt_names}, b.hi)
        self.funcs = dict(sorted(rng.items()))
        self.fstarts = list(self.funcs)
        self.imports = imports(b, plt_names)
        self.strings = string_objs(b)
        self.sstarts = sorted(self.strings)
        self.edges = []     # (from_insn, from_func, to_addr, kind)
        self._build()
        self.tables = self._tables()

    def func_of(self, a):
        if a is None:
            return None
        i = bisect.bisect_right(self.fstarts, a) - 1
        if i >= 0 and a < self.funcs[self.fstarts[i]]:
            return self.fstarts[i]
        return None

    def string_at(self, a):
        i = bisect.bisect_right(self.sstarts, a) - 1
        if i >= 0:
            s = self.sstarts[i]
            if a < s + self.strings[s][1]:
                return s
        return None

    def _build(self):
        b = self.b
        for a, t, sec in self.insns:
            kind, to = parse_insn(t)
            if kind is None:
                continue
            f = self.func_of(a)
            if kind == "jmp" and (f is None or self.func_of(to) == f):
                continue                                   # 함수 내부 점프
            if kind == "imm" and (b.pie or b.sec_of(to) is None or to < 0x1000):
                continue                                   # 주소가 아닌 숫자
            if kind in ("jmp_slot", "jmp") and sec.startswith(".plt"):
                continue                                   # PLT 스텁 자체
            if kind == "imm" and to in CRYPTO_IMM:
                pass
            self.edges.append((a, f, to, kind))
        # 데이터 안의 포인터
        if b.pie:
            for line in b.relocs.splitlines():
                f = line.split()
                if len(f) >= 4 and f[2].endswith("_RELATIVE"):
                    try:
                        self.edges.append((int(f[0], 16), None, int(f[-1], 16), "ptr"))
                    except ValueError:
                        pass
        else:
            lo = min(s["vma"] for s in b.secs) if b.secs else 0
            hi = max(s["vma"] + s["size"] for s in b.secs) if b.secs else 0
            for s in b.secs:
                if "DATA" not in s["flags"] or "CONTENTS" not in s["flags"] or s["name"] in (".pdata", ".reloc"):
                    continue
                blob = b.raw[s["off"]:s["off"] + s["size"]]
                for i in range(0, len(blob) - b.ptr + 1, b.ptr):
                    v = int.from_bytes(blob[i:i + b.ptr], "little")
                    if lo <= v < hi and v >= 0x1000:
                        self.edges.append((s["vma"] + i, None, v, "ptr"))

    def _tables(self):
        code_ptr = sorted(a for a, f, to, k in self.edges if k == "ptr" and self.b.lo <= to < self.b.hi)
        tables, run = [], []
        for a in code_ptr:
            if run and a - run[-1] == self.b.ptr:
                run.append(a)
            else:
                if len(run) >= TH["ptr_run"]:
                    tables.append((run[0], run[-1] + self.b.ptr))
                run = [a]
        if len(run) >= TH["ptr_run"]:
            tables.append((run[0], run[-1] + self.b.ptr))
        return tables

    def table_at(self, a):
        for s, e in self.tables:
            if s <= a < e:
                return s
        return None

    def is_lib(self, a) -> bool:
        n = self.names.get(a)
        return bool(n) and bool(LIB_RE.match(n))

    def parse(self, t: str):
        return recon_wasm.parse(self, self.b, t) if self.wasm else parse_insn(t)

    def describe(self, a):
        """주소 → (종류, 표시 문자열)"""
        if a is None:
            return "unknown", "?"
        if self.wasm:
            return recon_wasm.describe_extra(self, a)
        if a in self.imports:
            return "import", f"import:{self.imports[a]}"
        f = self.func_of(a)
        if f is not None:
            return "func", (hex(f) if f == a else f"{hex(f)}+{a - f:#x}")
        s = self.string_at(a)
        if s is not None:
            txt = self.strings[s][0][:40].replace("\t", " ")
            return "string", (f"str:{txt!r}" if s == a else f"str:{txt!r}+{a - s:#x}")
        t = self.table_at(a)
        if t is not None:
            return "table", f"table@{hex(t)}" + (f"+{a - t:#x}" if a != t else "")
        sec = self.b.sec_of(a)
        if sec is not None:
            return "data", f"{sec['name']}+{a - sec['vma']:#x}"
        return "unknown", hex(a)


# ---------------------------------------------------------------- 출발점·탐색
def find_seeds(g: Graph, goal: str, anchors_opt: list):
    sre, ire = GOALS[goal]
    seeds = {}   # 주소 -> 설명
    extra = [a for a in anchors_opt if not re.fullmatch(r"0x[0-9a-fA-F]+", a)]
    pats = [re.compile(p) for p in ([sre] if sre else []) + extra]
    for va, (txt, _) in g.strings.items():
        if any(p.search(txt) for p in pats):
            seeds[va] = f"str:{txt[:40]!r}"
    if ire:
        ip = re.compile(ire)
        for a, n in g.imports.items():
            if ip.match(n) or any(p.search(n) for p in [re.compile(x) for x in extra]):
                seeds[a] = f"import:{n}"
    # 이름이 남아 있는 내부 함수 (wasm 이름 섹션 등): 외부 함수 단서와 같은 규칙으로 출발점에 넣는다
    for a, n in getattr(g, "names", {}).items():
        short = re.split(r"::|\.", n)[-1] if "::" in n else n
        if (ire and re.match(ire, short)) or any(re.search(x, n) for x in extra):
            seeds[a] = f"func:{n[:60]}"
    if goal == "crypto":
        for name, (pat, ln) in CRYPTO_CONST.items():
            for m in re.finditer(re.escape(pat), g.b.raw):
                va, _ = g.b.va_of_off(m.start())
                if va is not None:
                    seeds[va] = f"const:{name}"
        for a, f, to, k in g.edges:
            if k == "imm" and to in CRYPTO_IMM and f is not None:
                seeds[a] = f"const:{CRYPTO_IMM[to]}"
    direct = [int(a, 16) for a in anchors_opt if re.fullmatch(r"0x[0-9a-fA-F]+", a)]
    return seeds, direct


def seed_hits(g: Graph, seeds: dict):
    """출발 주소를 참조하는 함수 → 출발점 설명 집합"""
    hits = defaultdict(set)
    lens = {}
    for va in seeds:
        if va in g.strings:
            lens[va] = g.strings[va][1]
        elif seeds[va].startswith("const:AES") or seeds[va].startswith("const:SHA") or seeds[va].startswith("const:MD5"):
            lens[va] = 256
        elif seeds[va].startswith("const:CRC"):
            lens[va] = 1024
        else:
            lens[va] = 1
    starts = sorted(seeds)
    for a, f, to, k in g.edges:
        if f is None or to is None:
            if f is not None and seeds.get(a, "").startswith("const:"):
                hits[f].add(seeds[a])
            continue
        i = bisect.bisect_right(starts, to) - 1
        if i >= 0 and to < starts[i] + lens[starts[i]]:
            hits[f].add(seeds[starts[i]])
    # 데이터 포인터를 거쳐 문자열을 참조하는 경우 (문자열 포인터 표)
    ptr_from = {}
    for a, f, to, k in g.edges:
        if k == "ptr":
            i = bisect.bisect_right(starts, to) - 1
            if i >= 0 and to < starts[i] + lens[starts[i]]:
                ptr_from[a] = seeds[starts[i]]
    if ptr_from:
        for a, f, to, k in g.edges:
            if f is not None and k in ("ref", "imm") and to in ptr_from:
                hits[f].add(ptr_from[to] + " (via ptr)")
    return hits


def explore(g: Graph, anchors: list, depth: int):
    calls_out, calls_in = defaultdict(set), defaultdict(set)
    for a, f, to, k in g.edges:
        tf = g.func_of(to) if to is not None else None
        if f is None:
            if k == "ptr" and tf is not None and tf == to:
                pass
            continue
        if k in ("call", "jmp") and tf is not None and tf != f:
            calls_out[f].add(tf)
            calls_in[tf].add(f)
        elif k in ("ref", "imm") and tf is not None and tf == to and tf != f:
            calls_out[f].add(tf)       # 함수 주소를 값으로 사용 (포인터 전달)
            calls_in[tf].add(f)
    anchor_set = set(anchors)
    dist, path = {}, {}
    q = deque()
    for a in anchors:
        dist[a], path[a] = 0, [hex(a)]
        q.append(a)
    while q:
        f = q.popleft()
        if dist[f] >= depth or (f not in anchor_set and g.is_lib(f)):
            continue                     # 라이브러리 함수 너머로는 넓히지 않는다
        for n in sorted(calls_out[f]):
            if n not in dist:
                dist[n], path[n] = dist[f] + 1, path[f] + [hex(n)]
                q.append(n)
    for a in anchors:   # 호출자 1단계
        for c in sorted(calls_in[a]):
            if c not in dist:
                dist[c], path[c] = 1, [hex(c) + "(caller)", hex(a)]
    return dist, path, calls_out, calls_in


def fallback_seeds(g: Graph):
    taken = set()
    for a, f, to, k in g.edges:
        if k in ("ptr", "ref", "imm") and to in g.funcs:
            taken.add(to)
    if g.b.entry in g.funcs:
        taken.add(g.b.entry)
    return sorted(taken)


# ---------------------------------------------------------------- 검사 사슬
EV = [  # (종류, 호출 대상 이름 정규식) — 위에서부터 처음 맞는 것
    ("exit", r"(?i)(^|[^a-z])(exit|_exit|abort|proc_exit|panic\w*|process::exit)"),
    ("input", r"(?i)read_line|fd_read|(^|[^a-z])(read|scanf|__isoc99_scanf|vfscanf|__stdio_common_vfscanf|fgets|getline|gets|getchar|fgetc|recv|recvfrom)$|ReadConsole|ReadFile"),
    ("compare", r"(?i)memcmp|bcmp|strn?cmp|strcasecmp|wcscmp|lstrcmp|CompareString|PartialEq|::eq\b|(^|_)eq(_|$)|equal|check|verify|valid"),
    ("sink", r"(?i)spawn|Command|(^|[^a-z])(system|popen|execv\w*|execl\w*)$|CreateProcess|ShellExecute|WinExec|authori[sz]|success|grant"),
    ("transform", r"(?i)sha\d*|md5|crc|hash|digest|update|finish|finali[sz]e|hmac|aes|encrypt|decrypt|cipher|xor|encode|decode|base64|hex"),
    ("output", r"(?i)print|puts|fputs|fwrite|(^|[^a-z])write$|fd_write|send$|_print|WriteConsole|WriteFile"),
]
EV_RE = [(k, re.compile(p)) for k, p in EV]


def classify_call(desc: str):
    name = desc.split("import:", 1)[-1]
    m = re.search(r"<(.+)>", name)
    if m:
        name = m.group(1)
    for k, rx in EV_RE:
        if rx.search(name):
            return k, name
    return None, name


def build_chains(g, funcs: list, limit: int = 8):
    """함수 안 명령 순서대로 입력·변환·상수·비교·출력·종료·실행 사건을 모으고, 입력마다 단계를 나눈다."""
    addrs = [a for a, _, _ in g.insns]
    chains = []
    for f in funcs:
        if len(chains) >= limit:
            break
        i = bisect.bisect_left(addrs, f)
        events = []
        while i < len(addrs) and addrs[i] < g.funcs[f]:
            a, t, _ = g.insns[i]
            i += 1
            kind, to = g.parse(t)
            if kind in ("call", "call_slot", "jmp_slot", "jmp") and to is not None:
                full = g.names.get(to) or g.describe(to)[1]        # 분류는 잘리지 않은 전체 이름으로
                k, name = classify_call(full)
                name = re.sub(r"::h[0-9a-f]{16}$", "", name)       # 표시용: Rust 해시 접미사 제거
                if k is None and g.func_of(to) is not None and not g.is_lib(g.func_of(to)) and g.names.get(to):
                    k = "transform"            # 이름 있는 프로그램 자체 함수 호출
                if k:
                    events.append((a, k, name[:60]))
            elif kind == "indirect":
                events.append((a, "indirect", "간접 호출"))
            elif kind in ("ref", "imm") and to is not None:
                typ, d = g.describe(to)
                if typ == "string":
                    events.append((a, "const", d[:60]))
                elif typ in ("data", "table"):
                    events.append((a, "const", d[:40]))
        if not any(k in ("input", "compare") for _, k, _ in events):
            continue
        stages, cur = [], None
        def new():
            return {"inputs": [], "transforms": [], "consts": [], "compares": [], "outputs": [], "sinks": [],
                    "exits": [], "indirect": 0, "events": []}
        cur = new()
        for a, k, name in events:
            if k == "input" and (cur["inputs"] or cur["events"]):
                stages.append(cur)
                cur = new()
            key = {"input": "inputs", "transform": "transforms", "const": "consts", "compare": "compares",
                   "output": "outputs", "sink": "sinks", "exit": "exits"}.get(k)
            if key:
                cur[key].append(name)
            else:
                cur["indirect"] += 1
            cur["events"].append(f"{a:#x} {k:9} {name}")
        stages.append(cur)
        chains.append({"addr": hex(f), "name": g.names.get(f, ""), "stages": stages})
    return chains


def write_chains(chains: list, out: Path):
    d = out / "chain"
    d.mkdir(parents=True, exist_ok=True)
    for c in chains:
        L = [f"; 검사 사슬: {c['addr']} {c['name']}"]
        for n, s in enumerate(c["stages"]):
            L.append(f"\n[단계 {n}{' (준비)' if not s['inputs'] else ''}]")
            L += s["events"]
        (d / f"{int(c['addr'], 16):x}.txt").write_text("\n".join(L) + "\n")


def chain_lines(chains: list, max_lines: int = 40):
    L = []
    for c in chains:
        L.append(f"- {c['addr']} {c['name'][:50]}")
        n = 0
        for s in c["stages"]:
            if not s["inputs"] and not s["compares"] and not s["sinks"]:
                continue
            n += 1
            parts = []
            if s["inputs"]:
                parts.append("입력 " + ", ".join(dict.fromkeys(s["inputs"]))[:60])
            if s["transforms"]:
                parts.append("변환 " + ", ".join(dict.fromkeys(s["transforms"]))[:80])
            if s["consts"]:
                parts.append("상수 " + ", ".join(dict.fromkeys(s["consts"]))[:100])
            if s["compares"]:
                parts.append("비교 " + ", ".join(dict.fromkeys(s["compares"]))[:60])
            if s["exits"]:
                parts.append("종료 " + ", ".join(dict.fromkeys(s["exits"]))[:40])
            if s["sinks"]:
                parts.append("실행·성공 " + ", ".join(dict.fromkeys(s["sinks"]))[:60])
            if s["indirect"]:
                parts.append(f"간접 호출 {s['indirect']}")
            L.append(f"  - 단계 {n}: " + " → ".join(parts))
        if len(L) >= max_lines:
            break
    return L[:max_lines]


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    cnt = [0] * 256
    for x in data:
        cnt[x] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in cnt if c)


def packed_signal(b: Bin, g: Graph):
    names = {s["name"] for s in b.secs}
    if {"UPX0", "UPX1"} & names or b"UPX!" in b.raw[:4096] or b"UPX!" in b.raw[-4096:]:
        return "UPX 표식"
    big = max(b.code, key=lambda s: s["size"], default=None)
    if big:
        e = entropy(b.raw[big["off"]:big["off"] + big["size"]])
        if e > 7.2 and len(g.imports) < 8:
            return f"코드 섹션 엔트로피 {e:.2f}, import {len(g.imports)}개"
    return None


def decide(f: dict, th: dict):
    if f["packed"]:
        return "stop", "C1", "패킹 의심: 언패킹 없이는 정적 분석 의미 없음"
    if f["goal"] == "inventory":
        return "full", "C2", "전체 함수 목록이 과제"
    if f["goal"] == "overview" and not f["anchors"]:
        if f["stripped"] and f["text_bytes"] >= th["text_bytes"]:
            return "full", "C3", "구조 지도만 필요하지만 스트립된 큰 프로그램이라 전체 분석"
        return "none", "C3", "구조 지도만 필요"
    if f["anchors"]:
        if f["region_bytes"] <= th["region_bytes"] and not f["region_indirect"] and not f["region_tables"]:
            return "none", "C4", f"관심 영역 {f['region_bytes']}바이트, 간접 호출·테이블 없음 → 디스어셈블로 충분"
        why = []
        if f["region_bytes"] > th["region_bytes"]:
            why.append(f"관심 영역 {f['region_bytes']}바이트 > {th['region_bytes']}")
        if f["region_indirect"]:
            why.append(f"간접 호출 {f['region_indirect']}개")
        if f["region_tables"]:
            why.append(f"코드 포인터 테이블 {f['region_tables']}개")
        return "partial", "C5", ", ".join(why)
    if f["func_count"] < th["func_count"] and f["text_bytes"] < th["text_bytes"]:
        return "none", "C6", "단서 없음, 작은 프로그램 → 주소가 저장된 함수와 진입점 주변 디스어셈블"
    return "full", "C7", "단서 없음, 큰 프로그램 → 전체 분석 후 목록에서 탐색"


# ---------------------------------------------------------------- 실행 단계
def ghidra_dir(out: Path) -> str:
    """Ghidra 프로젝트 위치: 환경변수 > 현재 폴더에 미리 만들어 둔 ./_ghidra > 출력 폴더 아래"""
    if os.environ.get("RE_GHIDRA_DIR"):
        return os.environ["RE_GHIDRA_DIR"]
    if os.path.isdir("_ghidra"):
        return os.path.abspath("_ghidra")
    return str(Path(out).resolve() / "_ghidra")


def run_ghidra(target: str, addrs: list, mode: str, out: Path):
    wrap = HERE / "ghidra_re.sh"
    gdir_s = ghidra_dir(out)
    env = dict(os.environ, RE_TARGET=target, RE_MAX_LINES="100000000", RE_GHIDRA_DIR=gdir_s)
    info = {"ran": False, "mode": mode, "analyze": "", "error": "", "dir": gdir_s}
    t0 = time.time()
    r = subprocess.run(["bash", str(wrap), "analyze"], capture_output=True, text=True, env=env)
    info["analyze"] = r.stdout.strip()
    if r.returncode != 0:
        info["error"] = (r.stderr.strip().splitlines() or ["analyze 실패"])[-1]
        return info
    info["ran"] = True
    gdir = Path(gdir_s)
    if mode == "partial" and addrs:
        r = subprocess.run(["bash", str(wrap), "decomp", *[hex(a) for a in addrs]], capture_output=True, text=True, env=env)
        if r.returncode != 0:
            info["error"] = (r.stderr.strip().splitlines() or ["decomp 실패"])[-1]
        else:
            ddir = out / "decomp"
            ddir.mkdir(parents=True, exist_ok=True)
            chunks = re.split(r"(?m)^(?=// function \S+ @ 0x[0-9a-f]+$)", r.stdout)
            wrote = 0
            for c in chunks:
                m = re.match(r"// function \S+ @ 0x([0-9a-f]+)", c)
                if m:
                    (ddir / f"{m.group(1)}.c").write_text(c)
                    wrote += 1
            if not wrote:
                (ddir / "all.c").write_text(r.stdout)
    if mode == "full" and (gdir / "functions.tsv").exists():
        (out / "ghidra_functions.tsv").write_text((gdir / "functions.tsv").read_text())
    info["sec"] = round(time.time() - t0, 1)
    return info


def write_disasm(g: Graph, funcs: list, out: Path):
    d = out / "disasm"
    d.mkdir(parents=True, exist_ok=True)
    by_func = defaultdict(list)
    want = set(funcs)
    for a, t, _ in g.insns:
        f = g.func_of(a)
        if f in want:
            kind, to = g.parse(t)
            note = ""
            if kind and to is not None:
                note = f"    ; {kind} → {g.describe(to)[1]}"
            by_func[f].append(f"{a:x}:\t{t}{note}")
    for f in funcs:
        (d / f"{f:x}.s").write_text(f"; function {hex(f)}  size={g.funcs[f] - f}\n" + "\n".join(by_func[f]) + "\n")


def write_data(g: Graph, refs: list, out: Path):
    d = out / "data"
    d.mkdir(parents=True, exist_ok=True)
    for a in refs:
        blob = g.b.read_va(a, 256)
        if not blob:
            continue
        lines = [f"{a + i:x}: " + " ".join(f"{x:02x}" for x in blob[i:i + 16]).ljust(48) + " "
                 + "".join(chr(x) if 32 <= x < 127 else "." for x in blob[i:i + 16]) for i in range(0, len(blob), 16)]
        fname = f"mem_{a - recon_wasm.MEM:x}" if g.wasm and a >= recon_wasm.MEM else f"{a:x}"
        (d / f"{fname}.hex").write_text(f"; {g.describe(a)[1]}\n" + "\n".join(lines) + "\n")


IMPORT_CATS = {
    "파일": r"(?i)^(f?open|fopen64|openat|f?read|f?write|fclose|close|stat|unlink|CreateFile|ReadFile|WriteFile|DeleteFile|_wfopen)",
    "네트워크": r"(?i)^(socket|connect|bind|listen|accept|send|recv|getaddrinfo|gethostbyname|inet_|WSA|Internet|Http|WinHttp|URLDownload)",
    "프로세스": r"(?i)^(fork|exec|system|popen|CreateProcess|ShellExecute|WinExec|ptrace|kill|signal)",
    "메모리·코드": r"(?i)^(mmap|mprotect|VirtualAlloc|VirtualProtect|dlopen|dlsym|LoadLibrary|GetProcAddress)",
    "콘솔 입출력": r"(?i)^(printf|puts|scanf|__isoc99_scanf|fgets|getchar|putchar|fputs|__stdio_common_v|__acrt_iob_func|ReadConsole|WriteConsole|GetStdHandle)",
    "문자열·비교": r"(?i)^(str|mem|wcs|lstr|CompareString)",
    "암호": r"(?i)^(Crypt|BCrypt|EVP_|AES_|SHA|MD5|RAND_)",
    "WASI 입출력": r"^(fd_|path_|poll_oneoff|args_|environ_)",
    "WASI 프로세스·시간": r"^(proc_|clock_|random_get|sched_yield)",
    "WASI 소켓": r"^sock_",
    "시간·난수": r"(?i)^(time|clock|rand|srand|GetTickCount|QueryPerformance|Sleep|sleep)",
}


def lang_hints(b: Bin, g: Graph):
    h = []
    names = {s["name"] for s in b.secs}
    if ".gopclntab" in names or b"runtime.gopanic" in b.raw:
        h.append("Go")
    if b"rust_panic" in b.raw or b"/rustc/" in b.raw:
        h.append("Rust")
    if any(n.startswith("_Z") for n in g.imports.values()) or b"St9exception" in b.raw:
        h.append("C++")
    if b"mscoree.dll" in b.raw.lower() or b"_CorExeMain" in b.raw:
        h.append(".NET")
    return h or ["C 추정"]


FORMAT_TOOLS = {
    "wasm": ("WebAssembly", "wasm-objdump -x (섹션·import·export), wasm-objdump -d (명령), wasm-decompile (의사코드), "
             "wasm2wat (텍스트 형식). 실행: node 또는 wasm-interp"),
    "dex": ("Android DEX", "jadx"), "apk": ("Android APK", "jadx"),
    "java": ("Java class/jar", "jadx 또는 javap -c"),
    "dotnet": (".NET 어셈블리", "monodis/ilspycmd (설치된 경우)"),
    "macho": ("Mach-O", "objdump --macho (지원 범위 제한)"),
    "script": ("스크립트·텍스트", "직접 읽기"),
}


def sniff_format(path: str):
    head = open(path, "rb").read(64)
    if head.startswith(b"\x00asm"):
        return "wasm"
    if head.startswith(b"dex\n"):
        return "dex"
    if head.startswith(b"PK\x03\x04"):
        return "apk" if path.endswith(".apk") else "java"
    if head[:4] == b"\xca\xfe\xba\xbe":
        return "java"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    if head.startswith(b"#!"):
        return "script"
    return None


def write_unsupported(a, out: Path, kind: str):
    name, tools = FORMAT_TOOLS[kind]
    reason = f"지원하지 않는 형식: {name} ({kind}) — recon은 ELF/PE만 구조·주소 참조를 분석한다"
    result = {"routine": "recon/v2", "target": a.target, "goal": a.goal, "format": kind,
              "decision": {"decision": "unsupported", "rule": "C0", "reason": reason}, "tools": tools,
              "ghidra": {"ran": False}, "region": [], "anchors": [], "seeds": [], "fallback": False}
    (out / "recon.json").write_text(json.dumps(result, ensure_ascii=False, indent=1))
    (out / "structure.md").write_text(
        f"# 구조 지도: {a.target}\n\n## 1. 기본 정보\n- 형식 {name}\n\n## 5. Ghidra 결정\n"
        f"- 결정 **unsupported** (C0): {reason}\n\n## 7. 다음 단계\n"
        f"- 이 루틴의 자동 분석은 건너뛴다. 형식에 맞는 도구로 직접 구조를 파악한다: {tools}\n"
        f"- 2단계(분석 노트)와 3단계(goal별 절차·검증) 지침은 그대로 따른다.\n")
    print(f"recon: decision=unsupported (C0) format={kind} → {out}/structure.md")
    return 0


def main_recon(a):
    if not os.path.isfile(a.target):
        die(f"대상 없음: {a.target}")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    kind = sniff_format(a.target)
    if kind is None and triage.file_format(a.target) == "unknown":
        kind = "script"
    if kind is not None and kind != "wasm":
        return write_unsupported(a, out, kind)
    th = dict(TH, depth=a.depth, region_bytes=a.th_region_bytes, partial_max=a.th_partial_max)
    t0 = time.time()
    b = recon_wasm.WasmBin(a.target) if kind == "wasm" else Bin(a.target)
    g = Graph(b)

    seeds, direct = find_seeds(g, a.goal, a.anchor or [])
    hits = seed_hits(g, seeds)
    anchors = sorted(set(hits) | {d for d in direct if g.func_of(d) is not None} | {g.func_of(d) for d in direct if g.func_of(d)})
    if getattr(g, "names", None):
        user = [x for x in anchors if not g.is_lib(x)]
        if user:
            anchors = user               # 이름이 있으면 프로그램 자신의 함수만 앵커로
    fallback = False
    if not anchors and a.goal not in ("inventory", "overview"):
        anchors, fallback = fallback_seeds(g), True
    dist, path, calls_out, calls_in = explore(g, anchors, th["depth"]) if anchors else ({}, {}, defaultdict(set), defaultdict(set))
    if not dist and not anchors:
        _, _, calls_out, calls_in = explore(g, [], 0)

    region = sorted(dist, key=lambda f: (dist[f], g.is_lib(f), f))
    rset = set(region)
    region_bytes = sum(g.funcs[f] - f for f in region)
    region_indirect = sum(1 for x, f, to, k in g.edges if f in rset and k == "indirect")
    region_tables = len({g.table_at(to) for x, f, to, k in g.edges if f in rset and to is not None and g.table_at(to)})
    data_refs = []
    for x, f, to, k in g.edges:
        if f in rset and k in ("ref", "imm") and to is not None and g.describe(to)[0] in ("data", "table", "string"):
            if to not in data_refs:
                data_refs.append(to)
    chain_funcs = [f for f in region if dist[f] == 0 and not g.is_lib(f)] + \
                  [f for f in region if dist[f] == 1 and not g.is_lib(f)]
    chains = build_chains(g, chain_funcs) if not fallback or region else []
    packed = packed_signal(b, g)
    facts = {"packed": packed, "goal": a.goal, "anchors": len(anchors) if not fallback else 0,
             "region_bytes": region_bytes, "region_indirect": region_indirect, "region_tables": region_tables,
             "func_count": len(g.funcs), "text_bytes": b.text_bytes, "stripped": b.nsym == 0, "fallback": fallback}
    decision, rule, reason = decide(facts, th)
    if fallback and decision == "full":
        region, dist = [], {}

    # 실행
    disasm_funcs = region[: th["partial_max"] * 2] if region else ([b.entry] if b.entry in g.funcs else [])
    if decision != "stop":
        write_disasm(g, disasm_funcs, out)
        write_data(g, data_refs[:50], out)
        write_chains(chains, out)
    ghidra = {"ran": False, "mode": decision}
    decomp_targets = sorted(region, key=lambda f: (dist[f], -(g.funcs[f] - f)))[: th["partial_max"]]
    if decision in ("partial", "full") and not a.no_ghidra:
        if g.wasm:
            ghidra = recon_wasm.decompile(a.target, g, decomp_targets, decision, out)
        else:
            ghidra = run_ghidra(a.target, decomp_targets, decision, out)
    elif decision in ("partial", "full"):
        ghidra["error"] = "--no-ghidra 지정: 결정만 기록"

    # 표
    def strs_of(f):
        s = []
        for x, ff, to, k in g.edges:
            if ff == f and to is not None:
                st = g.string_at(to)
                if st is not None and g.strings[st][0] not in s:
                    s.append(g.strings[st][0])
        return s
    edge_lines = ["from_insn\tfrom_func\tto_addr\tto_obj\tkind"]
    for x, f, to, k in g.edges:
        edge_lines.append(f"{x:#x}\t{hex(f) if f is not None else '-'}\t{hex(to) if to is not None else '-'}\t"
                          f"{g.describe(to)[1] if to is not None else '-'}\t{k}")
    (out / "xrefs.tsv").write_text("\n".join(edge_lines) + "\n")
    anchor_set = set(anchors)
    funcs_rows = []
    lines = ["addr\tsize\tcallers\tcallees\tanchor\tdistance\tstrings"]
    for f, e in g.funcs.items():
        row = {"addr": hex(f), "size": e - f, "callers": len(calls_in[f]), "callees": len(calls_out[f]),
               "anchor": f in anchor_set, "distance": dist.get(f)}
        funcs_rows.append(row)
        if f in rset or len(lines) < 5000:
            lines.append(f"{f:#x}\t{e - f}\t{row['callers']}\t{row['callees']}\t{'Y' if f in anchor_set else ''}\t"
                         f"{'' if f not in dist else dist[f]}\t{' | '.join(strs_of(f)[:3]) if f in rset else ''}")
    (out / "functions.tsv").write_text("\n".join(lines) + "\n")
    reg_rows = [{"addr": hex(f), "name": g.names.get(f, ""), "lib": g.is_lib(f), "distance": dist[f],
                 "path": "→".join(path[f]), "size": g.funcs[f] - f, "why": sorted(hits.get(f, []))} for f in region]
    (out / "region.tsv").write_text("addr\tdistance\tpath\tsize\twhy\n" + "".join(
        f"{r['addr']}\t{r['distance']}\t{r['path']}\t{r['size']}\t{'; '.join(r['why'])}\n" for r in reg_rows))

    cats = {}
    for n in set(g.imports.values()):
        for c, p in IMPORT_CATS.items():
            if re.match(p, n):
                cats.setdefault(c, []).append(n)
    result = {
        "routine": "recon/v2", "target": a.target, "goal": a.goal, "format": b.fmt, "size": len(b.raw),
        "stripped": b.nsym == 0, "pie": b.pie, "bounds": g.bounds, "lang": lang_hints(b, g), "packed": packed,
        "import_categories": {c: sorted(v) for c, v in cats.items()}, "imports": len(g.imports),
        "functions": funcs_rows if len(funcs_rows) <= 20000 else funcs_rows[:20000],
        "func_count": len(g.funcs), "text_bytes": b.text_bytes, "tables": [hex(s) for s, _ in g.tables],
        "seeds": sorted(set(seeds.values())), "anchors": [hex(x) for x in anchors], "fallback": fallback,
        "region": reg_rows, "region_bytes": region_bytes, "region_indirect": region_indirect,
        "region_tables": region_tables, "data_refs": [hex(x) for x in data_refs[:50]],
        "check_chains": [{k: v for k, v in c.items()} | {"stages": [{k: v for k, v in s.items() if k != "events"}
                                                                   for s in c["stages"]]} for c in chains],
        "decision": {"decision": decision, "rule": rule, "reason": reason}, "ghidra": ghidra,
        "thresholds": th, "elapsed_sec": round(time.time() - t0, 1),
    }
    (out / "recon.json").write_text(json.dumps(result, ensure_ascii=False, indent=1))
    (out / "structure.md").write_text(structure_md(result, g, out, th))
    print(f"recon: decision={decision} ({rule}) anchors={len(anchors)} region={len(region)} → {out}/structure.md")
    return 0


NEXT = {
    "none": "disasm/ 의 함수를 region.tsv 거리 순서(0 → 1)로 읽는다. 비교 대상·상수는 data/ 에 있다.",
    "partial": "decomp/ 의 C 코드를 거리 순서로 읽고, 상수와 분기 조건은 같은 주소의 disasm/ 로 대조한다. 비교 대상은 data/.",
    "full": "ghidra_functions.tsv(또는 functions.tsv)에서 크기·참조 문자열로 후보를 고른 뒤 "
            "`recon.py xref --to/--from 주소`와 `ghidra_re.sh decomp 주소`로 필요한 함수만 연다.",
    "stop": "패킹 의심. 정적 분석을 계속하지 말고 근거와 함께 보고한다.",
}


def structure_md(r: dict, g: Graph, out: Path, th: dict) -> str:
    L = [f"# 구조 지도: {r['target']}", ""]
    L += ["## 1. 기본 정보",
          f"- 형식 {r['format']} · 크기 {r['size']}바이트 · 코드 {r['text_bytes']}바이트 · 스트립 {'예' if r['stripped'] else '아니오'}"
          f" · PIE {'예' if r['pie'] else '아니오'} · 함수 경계 {r['bounds']}",
          f"- 언어 흔적: {', '.join(r['lang'])} · 패킹: {r['packed'] or '신호 없음'}", ""]
    L += ["## 2. 하는 일 (외부 의존)", f"- import {r['imports']}개"]
    for c, v in r["import_categories"].items():
        L.append(f"- {c} {len(v)}: {', '.join(v[:8])}{' …' if len(v) > 8 else ''}")
    L.append("")
    top = sorted(g.funcs.items(), key=lambda x: -(x[1] - x[0]))[:10]
    L += ["## 3. 함수 지도", f"- 함수 {r['func_count']}개 · 코드 포인터 테이블 {len(r['tables'])}개"
          + (f" ({', '.join(r['tables'][:5])})" if r["tables"] else ""),
          "- 큰 함수 상위 10: " + ", ".join(f"{s:#x}({e - s})" for s, e in top), ""]
    L += ["## 4. 목적 관련 위치", f"- goal={r['goal']} · 단서 {len(r['seeds'])}개"
          + (": " + ", ".join(r["seeds"][:8]) if r["seeds"] else ""),
          f"- 앵커 {len(r['anchors'])}개{' (대체 규칙: 주소가 저장된 함수·진입점)' if r['fallback'] else ''}: "
          + ", ".join(r["anchors"][:10]),
          f"- 관심 영역 {len(r['region'])}개 함수, {r['region_bytes']}바이트, 간접 호출 {r['region_indirect']}, 테이블 {r['region_tables']}",
          ""]
    named = any(row.get("name") for row in r["region"])
    if named:
        L += ["| 주소 | 이름 | 거리 | 크기 | 경로 | 단서 |", "|---|---|---|---|---|---|"]
    else:
        L += ["| 주소 | 거리 | 크기 | 경로 | 단서 |", "|---|---|---|---|---|"]
    for row in r["region"][:40]:
        nm = (row.get("name", "")[:50] + (" (lib)" if row.get("lib") else "")) if named else None
        L.append(f"| {row['addr']} | " + (f"{nm} | " if named else "")
                 + f"{row['distance']} | {row['size']} | {row['path']} | {'; '.join(row['why'])[:60]} |")
    if len(r["region"]) > 40:
        L.append(f"| … | | | {len(r['region']) - 40}개 더 (region.tsv) | |")
    if r.get("check_chains"):
        L += ["", "## 4-1. 검사 사슬 (함수 안 명령 순서: 입력마다 단계가 나뉨, 전체는 chain/)"]
        L += chain_lines(r["check_chains"])
    d = r["decision"]
    gh = r["ghidra"]
    L += ["", "## 5. Ghidra 결정", f"- 결정 **{d['decision']}** ({d['rule']}): {d['reason']}",
          f"- 실행: {'예' if gh.get('ran') else '아니오'}" + (f" · {gh.get('analyze', '')}" if gh.get("analyze") else "")
          + (f" · 오류: {gh['error']}" if gh.get("error") else ""), ""]
    files = sorted(str(p.relative_to(out)) for p in out.rglob("*") if p.is_file() and p.name != "structure.md")
    L += ["## 6. 산출물", f"- {len(files)}개: " + ", ".join(files[:30]) + (" …" if len(files) > 30 else ""), ""]
    nxt = NEXT[d["decision"]]
    if r["format"] == "wasm":
        nxt = nxt.replace("C 코드", "의사코드(.dcmp, wasm-decompile)")
    L += ["## 7. 다음 단계", f"- {nxt}"]
    if r["format"] == "wasm":
        L += ["- 주소는 Code 섹션 파일 오프셋(wasm-objdump -d 기준), 데이터는 mem:0x… (선형 메모리 주소)",
              "- 실행(허용된 경우): `printf '%s\\n' '<입력>' | timeout 30 wasm-interp --wasi <대상>`",
              "- 추가 디컴파일: decomp/module.dcmp 에서 함수 이름으로 grep"]
    L += [
          f"- 이 주소를 누가 참조하나: `python3 -I {HERE / 'recon.py'} xref --to 0x<주소> --out {out}`",
          f"- 이 함수가 무엇을 참조하나: `python3 -I {HERE / 'recon.py'} xref --from 0x<주소> --out {out}`"]
    if r["format"] != "wasm" and d["decision"] in ("partial", "full", "none"):
        L.append(f"- 함수 추가 디컴파일 (여러 주소를 한 번에): `RE_TARGET={r['target']} RE_GHIDRA_DIR={ghidra_dir(out)} "
                 f"bash {HERE / 'ghidra_re.sh'} decomp 0x<주소> [0x<주소> ...]`")
    return "\n".join(L[: th["max_lines"]]) + "\n"


def main_xref(a):
    p = Path(a.out) / "xrefs.tsv"
    if not p.exists():
        die(f"{p} 없음 — 먼저 recon 실행")
    rows = p.read_text().splitlines()
    hdr, rows = rows[0], rows[1:]
    if a.to:
        x = int(a.to, 16)
        sel = [r for r in rows if r.split("\t")[2] != "-" and int(r.split("\t")[2], 16) == x]
    else:
        x = int(getattr(a, "from"), 16)
        sel = [r for r in rows if r.split("\t")[1] != "-" and int(r.split("\t")[1], 16) == x
               or int(r.split("\t")[0], 16) == x]
    print(hdr)
    for r in sel[: TH["max_lines"]]:
        print(r)
    if len(sel) > TH["max_lines"]:
        print(f"... ({len(sel)}줄 중 {TH['max_lines']}줄 표시, 전체: {p})")
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "xref":
        ap = argparse.ArgumentParser(prog="recon.py xref")
        grp = ap.add_mutually_exclusive_group(required=True)
        grp.add_argument("--to")
        grp.add_argument("--from")
        ap.add_argument("--out", default="work/recon")
        return main_xref(ap.parse_args(argv[1:]))
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--goal", required=True, choices=list(GOALS))
    ap.add_argument("--anchor", action="append", help="추가 단서: 정규식(문자열·import 이름) 또는 0x주소")
    ap.add_argument("--out", default="work/recon")
    ap.add_argument("--no-ghidra", action="store_true")
    ap.add_argument("--depth", type=int, default=TH["depth"])
    ap.add_argument("--th-region-bytes", type=int, default=TH["region_bytes"])
    ap.add_argument("--th-partial-max", type=int, default=TH["partial_max"])
    try:
        a = ap.parse_args(argv)
    except SystemExit as e:
        return 2 if e.code else 0
    return main_recon(a)


if __name__ == "__main__":
    sys.exit(main())
