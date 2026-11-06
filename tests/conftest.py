import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

TINY_C = r'''
#include <stdio.h>
#include <string.h>
__attribute__((noinline)) int check(const char *s) { return strcmp(s, "s3cr3t") == 0; }
int main(void) {
    char b[64];
    if (scanf("%63s", b) != 1) return 1;
    puts(check(b) ? "Correct" : "Wrong");
    return 0;
}
'''


def many_c(n: int = 300) -> str:
    fs = "\n".join(f"__attribute__((noinline)) int f{i}(int x) {{ return x * {i} + 1; }}" for i in range(n))
    calls = "\n".join(f"    s += f{i}(argc);" for i in range(n))
    return f"#include <stdio.h>\n{fs}\nint main(int argc, char **argv) {{\n    int s = 0;\n{calls}\n    printf(\"%d\\n\", s);\n    return 0;\n}}\n"


def table_c(n: int = 20) -> str:
    hs = "\n".join(f"static int h{i}(int a) {{ return a + {i}; }}" for i in range(n))
    tbl = ", ".join(f"h{i}" for i in range(n))
    return (f"#include <stdio.h>\n{hs}\nint (*const tbl[{n}])(int) = {{ {tbl} }};\n"
            "int main(void) { int c, a = 0; while ((c = getchar()) != EOF) a = tbl[c % " + str(n) + "](a);\n"
            "  puts(a == 1234 ? \"Correct\" : \"Wrong\"); return 0; }\n")


def build(tmp_path: Path, name: str, src: str, *flags: str) -> Path:
    c = tmp_path / f"{name}.c"
    c.write_text(src)
    out = tmp_path / name
    subprocess.run(["gcc", "-O1", *flags, "-o", str(out), str(c)], check=True)
    return out


def stripped_copy(p: Path) -> Path:
    q = p.with_name(p.name + "_s")
    shutil.copy(p, q)
    subprocess.run(["strip", str(q)], check=True)
    return q


@pytest.fixture
def tiny(tmp_path):
    return build(tmp_path, "tiny", TINY_C)


@pytest.fixture
def tiny_pie(tmp_path):
    return build(tmp_path, "tiny_pie", TINY_C, "-fPIE", "-pie")


# ---- recon 루틴용 합성 프로그램 ----
FILL = r'''
static int pad0(int x){return x*3+1;} static int pad1(int x){return pad0(x)^7;} static int pad2(int x){return pad1(x)+pad0(x);}
__attribute__((noinline)) int util_a(int x){return pad2(x)*2;} __attribute__((noinline)) int util_b(int x){return util_a(x)-1;}
'''
DEC = r'''
static void dec(char*o,const unsigned char*e,int n){for(int i=0;i<n;i++)o[i]=e[i]^0x55; o[n]=0;}
static const unsigned char E_OK[]={0x16,0x3a,0x27,0x27,0x30,0x36,0x21}, E_NG[]={0x02,0x27,0x3a,0x3b,0x32};
'''
PLAIN_C = "#include <stdio.h>\n#include <string.h>\n" + FILL + r'''
__attribute__((noinline)) int check(const char*s){return strcmp(s,"s3cr3t")==0;}
int main(void){char b[64]; if(scanf("%63s",b)!=1)return 1; util_b(3); puts(check(b)?"Correct":"Wrong"); return 0;}
'''
HIDDEN_C = "#include <stdio.h>\n#include <string.h>\n" + FILL + DEC + r'''
__attribute__((noinline)) int check(const char*s){char k[8]; dec(k,(const unsigned char*)"\x26\x66\x36\x27\x66\x21",6); return memcmp(s,k,6)==0;}
int main(void){char b[64],m[16]; if(!fgets(b,64,stdin))return 1; util_b(1); if(check(b))dec(m,E_OK,7); else dec(m,E_NG,5); puts(m); return 0;}
'''
INDIRECT_C = "#include <stdio.h>\n" + FILL + DEC + r'''
__attribute__((noinline)) int check(const char*s){static const unsigned char t[]={0x26,0x66,0x36,0x27,0x66,0x21}; for(int i=0;i<6;i++) if((s[i]^0x55)!=t[i]) return 0; return 1;}
int (*volatile fp)(const char*) = check;
int main(void){char b[64],m[16]; int c,i=0; while((c=getchar())!=EOF && c!='\n' && i<63) b[i++]=c; b[i]=0; util_b(2); if(fp(b))dec(m,E_OK,7); else dec(m,E_NG,5); fputs(m,stdout); return 0;}
'''
NETWORK_C = "#include <stdio.h>\n#include <string.h>\n#include <sys/socket.h>\n#include <netinet/in.h>\n#include <arpa/inet.h>\n#include <unistd.h>\n" + FILL + r'''
__attribute__((noinline)) int load_cfg(const char*p){FILE*f=fopen(p,"r"); if(!f)return -1; int v=0; fscanf(f,"%d",&v); fclose(f); return v;}
__attribute__((noinline)) int beacon(int port){int s=socket(AF_INET,SOCK_STREAM,0); struct sockaddr_in a={0}; a.sin_family=AF_INET; a.sin_port=htons(port); inet_pton(AF_INET,"10.0.0.5",&a.sin_addr); if(connect(s,(void*)&a,sizeof a)==0) send(s,"ping",4,0); close(s); return 0;}
int main(int c,char**v){int p=load_cfg("/etc/app.conf"); util_b(p); return beacon(p>0?p:8080);}
'''


def nm_addr(binary, sym: str) -> int:
    for l in subprocess.run(["nm", str(binary)], capture_output=True, text=True).stdout.splitlines():
        p = l.split()
        if len(p) == 3 and p[2] == sym:
            return int(p[0], 16)
    raise AssertionError(f"{sym} not in {binary}")


@pytest.fixture
def synth(tmp_path):
    """name -> (stripped binary, {symbol: address from unstripped})"""
    def make(name, src, *flags, syms=("main", "check")):
        p = build(tmp_path, name, src, *flags)
        truth = {s: nm_addr(p, s) for s in syms}
        return stripped_copy(p), truth
    return make


# ---- wasm 합성 모듈 (WAT → wasm, 이름 섹션 포함) ----
WASM_WAT = r'''
(module
  (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (param i32 i32 i32 i32) (result i32)))
  (memory (export "memory") 2)
  (data (i32.const 1048576) "Correct\00Wrong\00s3cr3t\00")
  (data (i32.const 1048700) "\00\00\10\00\08\00\10\00")
  (data (i32.const 1048800) "assertion failed: index out of range\00")
  (table 20 funcref)
  (elem (i32.const 0) $h0 $h1 $h2 $h3 $h4 $h5 $h6 $h7 $h8 $h9 $h10 $h11 $h12 $h13 $h14 $h15 $h16 $h17)
  (func $h0 (result i32) i32.const 0) (func $h1 (result i32) i32.const 1) (func $h2 (result i32) i32.const 2)
  (func $h3 (result i32) i32.const 3) (func $h4 (result i32) i32.const 4) (func $h5 (result i32) i32.const 5)
  (func $h6 (result i32) i32.const 6) (func $h7 (result i32) i32.const 7) (func $h8 (result i32) i32.const 8)
  (func $h9 (result i32) i32.const 9) (func $h10 (result i32) i32.const 10) (func $h11 (result i32) i32.const 11)
  (func $h12 (result i32) i32.const 12) (func $h13 (result i32) i32.const 13) (func $h14 (result i32) i32.const 14)
  (func $h15 (result i32) i32.const 15) (func $h16 (result i32) i32.const 16) (func $h17 (result i32) i32.const 17)
  (func $memcmp (param i32 i32 i32) (result i32) local.get 0 local.get 1 i32.sub)
  (func $core::panicking::panic (result i32) i32.const 1048800 i32.const 7 i32.const 3 call $memcmp)
  (func $std::io::stdio::_print (result i32) i32.const 1048800 drop call $core::panicking::panic)
  (func $util (param i32) (result i32) local.get 0 i32.const 3 i32.mul)
  (func $std::io::stdio::stdin::h3ba79430e7fd8603 (result i32) i32.const 0)
  (func $std::io::stdio::Stdin::read_line::h2de664dad9d64378 (param i32) (result i32) local.get 0)
  (func $alloc::string::String::core::cmp::PartialEq::eq::h032a4a88972dfeb8 (param i32 i32) (result i32) local.get 0 local.get 1 i32.eq)
  (func $check (param i32) (result i32) local.get 0 i32.const 1048590 i32.const 6 call $memcmp i32.eqz)
  (func $main (export "main") (result i32)
    call $std::io::stdio::stdin::h3ba79430e7fd8603 call $std::io::stdio::Stdin::read_line::h2de664dad9d64378 drop
    i32.const 1048590 i32.const 1048584 call $alloc::string::String::core::cmp::PartialEq::eq::h032a4a88972dfeb8 drop
    i32.const 1 call $util drop
    call $std::io::stdio::_print drop
    i32.const 2000 call $check
    if (result i32) i32.const 1048576 else i32.const 1048584 end
    drop i32.const 0 call_indirect (result i32))
  (func $_start (export "_start") call $main drop)
)
'''


@pytest.fixture
def wasm_mod(tmp_path):
    w = tmp_path / "m.wat"
    w.write_text(WASM_WAT)
    out = tmp_path / "m.wasm"
    subprocess.run(["wat2wasm", "--debug-names", str(w), "-o", str(out)], check=True)
    return out


TWOSTAGE_C = r'''
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static unsigned mix(const char*s){unsigned h=5381; while(*s) h=h*33+(unsigned char)*s++; return h;}
int main(void){
  char a[64], b[64];
  printf("password: "); if (scanf("%63s", a) != 1) return 1;
  if (strcmp(a, "hunter2") != 0) { puts("denied"); exit(1); }
  printf("code: "); if (!fgets(b, 64, stdin)) return 1;
  if (!fgets(b, 64, stdin)) return 1;
  if (mix(b) != 0x1234567u && memcmp(b, "42\n", 3) != 0) { puts("bad code"); exit(1); }
  puts("welcome"); system("sh");
  return 0;
}
'''
