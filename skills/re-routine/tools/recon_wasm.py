"""recon의 WebAssembly 지원: wabt(wasm-objdump, wasm-decompile)로 같은 주소 참조 그래프를 만든다.

주소 규칙 (한 공간에 겹치지 않게 나눈다)
- 함수·명령: Code 섹션 안의 파일 오프셋 (wasm-objdump -d 가 출력하는 값 그대로)
- 선형 메모리 데이터: MEM + 메모리 주소 (표시는 mem:0x...)
- import 함수: IMP + 함수 인덱스
- 함수 테이블(Elem) 칸: TAB + 칸 번호 * 4
"""
import re
import subprocess
from collections import defaultdict
from pathlib import Path

MEM = 1 << 40
IMP = 1 << 44
TAB = 1 << 46

HDR = re.compile(r"^([0-9a-f]+) func\[(\d+)\](?: <(.+)>)?:$")
INS = re.compile(r"^ ([0-9a-f]+): [0-9a-f ]+\| (.*)$")
IMPORT = re.compile(r"^ - func\[(\d+)\] sig=\d+(?: <[^>]*>)? <- ([\w.$-]+)\.([\w$-]+)")
ELEM = re.compile(r"^  - elem\[(\d+)\] = (?:ref\.func:)?func\[(\d+)\]")
EXPORT = re.compile(r"^ - func\[(\d+)\](?: <[^>]*>)? -> \"([^\"]+)\"")


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace").stdout


def sanitize(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", name)


def uleb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s; s += 7
        if x < 0x80:
            return r, i


def sleb(b, i):
    r = s = 0
    while True:
        x = b[i]; i += 1
        r |= (x & 0x7F) << s; s += 7
        if x < 0x80:
            if x & 0x40:
                r -= 1 << s
            return r, i


def data_segments(raw: bytes):
    """[(메모리 주소, bytes)] — 활성 세그먼트만 (i32.const 오프셋)"""
    i, segs = 8, []
    while i < len(raw):
        sid = raw[i]; i += 1
        size, i = uleb(raw, i)
        end = i + size
        if sid == 11:
            n, j = uleb(raw, i)
            for _ in range(n):
                flags, j = uleb(raw, j)
                addr = None
                if flags == 2:
                    _, j = uleb(raw, j)
                if flags in (0, 2):
                    if raw[j] == 0x41:
                        addr, j = sleb(raw, j + 1)
                    while raw[j] != 0x0B:
                        j += 1
                    j += 1
                ln, j = uleb(raw, j)
                if addr is not None:
                    segs.append((addr & 0xFFFFFFFF, raw[j:j + ln]))
                j += ln
        i = end
    return segs


class WasmBin:
    """recon.Bin 과 같은 속성을 흉내 낸다 (main_recon이 쓰는 것만)."""

    def __init__(self, path: str):
        self.path = path
        self.raw = open(path, "rb").read()
        self.fmt = "wasm"
        self.is_elf = self.is_pe = False
        self.pie = False
        self.ptr = 4
        self.secs, self.code, self.relocs, self.image_base = [], [], "", 0
        self.segs = data_segments(self.raw)
        m = re.search(r"Code start=0x([0-9a-f]+) end=0x([0-9a-f]+)", sh("wasm-objdump", "-h", path))
        self.lo, self.hi = (int(m.group(1), 16), int(m.group(2), 16)) if m else (0, 0)
        self.text_bytes = self.hi - self.lo
        self.entry = None
        self.nsym = 0

    def seg_of(self, mem: int):
        for k, (a, d) in enumerate(self.segs):
            if a <= mem < a + len(d):
                return k, a, d
        return None

    def sec_of(self, va: int):
        if va >= MEM and va < IMP:
            s = self.seg_of(va - MEM)
            if s:
                k, a, d = s
                return {"name": f"data[{k}]", "vma": MEM + a, "size": len(d), "flags": "CONTENTS, DATA", "off": 0}
        return None

    def read_va(self, va: int, n: int) -> bytes:
        if not (MEM <= va < IMP):
            return b""
        s = self.seg_of(va - MEM)
        if not s:
            return b""
        k, a, d = s
        o = va - MEM - a
        return d[o:o + n]


def build(g, b: WasmBin):
    """recon.Graph 인스턴스 g 의 필드를 wasm 기준으로 채운다."""
    x = sh("wasm-objdump", "-x", b.path)
    g.imports = {}
    for line in x.splitlines():
        m = IMPORT.match(line)
        if m:
            g.imports[IMP + int(m.group(1))] = m.group(3)
    exports = {}
    for line in x.splitlines():
        m = EXPORT.match(line)
        if m:
            exports[int(m.group(1))] = m.group(2)
    elem = []
    for line in x.splitlines():
        m = ELEM.match(line)
        if m:
            elem.append((int(m.group(1)), int(m.group(2))))

    insns, heads = [], []
    for line in sh("wasm-objdump", "-d", b.path).splitlines():
        m = HDR.match(line)
        if m:
            heads.append((int(m.group(1), 16), int(m.group(2)), m.group(3) or f"func_{m.group(2)}"))
            continue
        m = INS.match(line)
        if m:
            insns.append((int(m.group(1), 16), m.group(2).strip(), "code"))
    g.insns = insns
    g.funcs, g.names, g.idx2addr = {}, {}, {}
    for k, (off, idx, name) in enumerate(heads):
        end = heads[k + 1][0] if k + 1 < len(heads) else b.hi
        g.funcs[off] = end
        g.names[off] = name
        g.idx2addr[idx] = off
    for a in list(g.imports):
        g.idx2addr[a - IMP] = a
    g.fstarts = list(g.funcs)
    g.bounds = "wasm-code"
    b.nsym = sum(1 for n in g.names.values() if not n.startswith("func_"))
    for idx, nm in exports.items():
        if nm == "_start" and idx in g.idx2addr:
            b.entry = g.idx2addr[idx]
    g.exports = {g.idx2addr[i]: n for i, n in exports.items() if i in g.idx2addr}

    # 문자열: 데이터 세그먼트 안 출력 가능한 연속 구간
    g.strings = {}
    for a, d in b.segs:
        for m in re.finditer(rb"[\x20-\x7e\t]{4,}", d):
            g.strings[MEM + a + m.start()] = (m.group().decode("latin-1"), len(m.group()) + 1)
    g.sstarts = sorted(g.strings)

    # 간선
    g.edges = []
    for a, t, _ in insns:
        kind, to = parse(g, b, t)
        if kind:
            g.edges.append((a, g.func_of(a), to, kind))
    for a, d in b.segs:                    # 데이터 안의 메모리 포인터 (Rust 문자열 조각 표 등)
        for i in range(0, len(d) - 3, 4):
            v = int.from_bytes(d[i:i + 4], "little")
            if v >= 0x1000 and b.seg_of(v):
                g.edges.append((MEM + a + i, None, MEM + v, "ptr"))
    for slot, fidx in elem:                # 함수 테이블 칸 → 함수 (간접 호출 후보)
        if fidx in g.idx2addr:
            g.edges.append((TAB + slot * 4, None, g.idx2addr[fidx], "ptr"))
    g.tables = [(TAB, TAB + len(elem) * 4)] if len(elem) >= 16 else []


def parse(g, b: WasmBin, t: str):
    m = re.match(r"^call (\d+)\b", t)
    if m:
        return "call", g.idx2addr.get(int(m.group(1)))
    if t.startswith("call_indirect") or t.startswith("return_call_indirect"):
        return "indirect", None
    m = re.match(r"^i32\.const (-?\d+)", t)
    if m:
        v = int(m.group(1)) & 0xFFFFFFFF
        if v >= 0x1000 and b.seg_of(v):
            return "ref", MEM + v
    return None, None


def describe_extra(g, a):
    if a is None:
        return None
    if IMP <= a < TAB:
        return "import", f"import:{g.imports.get(a, '?')}"
    if a >= TAB:
        return "table", f"table+{a - TAB:#x}"
    if MEM <= a < IMP:
        s = g.string_at(a)
        if s is not None:
            txt = g.strings[s][0][:40]
            return "string", (f"str:{txt!r}" if s == a else f"str:{txt!r}+{a - s:#x}")
        return "data", f"mem:{a - MEM:#x}"
    f = g.func_of(a)
    if f is not None:
        n = g.names.get(f, "")
        return "func", (f"{hex(f)}<{n[:40]}>" if f == a else f"{hex(f)}+{a - f:#x}")
    return "unknown", hex(a)


def decompile(target: str, g, targets: list, mode: str, out: Path):
    """Ghidra 대신 wasm-decompile. 전체 모듈을 한 번 디컴파일해 함수별로 나눈다."""
    info = {"ran": False, "mode": mode, "tool": "wasm-decompile", "error": ""}
    r = subprocess.run(["timeout", "600", "wasm-decompile", target], capture_output=True, text=True, errors="replace")
    if r.returncode != 0:
        info["error"] = (r.stderr.strip().splitlines() or ["wasm-decompile 실패"])[-1]
        return info
    info["ran"] = True
    ddir = out / "decomp"
    ddir.mkdir(parents=True, exist_ok=True)
    (ddir / "module.dcmp").write_text(r.stdout)
    blocks = {}
    cur, buf = None, []
    for line in r.stdout.splitlines():
        m = re.match(r"^(?:export )?function ([A-Za-z0-9_]+)\(", line)
        if m:
            if cur:
                blocks[cur] = "\n".join(buf)
            cur, buf = m.group(1), [line]
        elif cur:
            buf.append(line)
    if cur:
        blocks[cur] = "\n".join(buf)
    by_name = {sanitize(n): a for a, n in g.names.items()}
    for n, a in list(by_name.items()):
        if a in getattr(g, "exports", {}):
            by_name.setdefault(sanitize(g.exports[a]), a)
    wrote = 0
    want = set(targets) if mode == "partial" else set()
    for n, body in blocks.items():
        a = by_name.get(n)
        if a is not None and a in want:
            (ddir / f"{a:x}.dcmp").write_text(f"// function {g.names.get(a, n)} @ {hex(a)}\n{body}\n")
            wrote += 1
    info["functions_written"] = wrote
    return info
