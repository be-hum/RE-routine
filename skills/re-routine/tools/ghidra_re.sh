#!/usr/bin/env bash
# Ghidra headless 래퍼 — 분석 결과를 캐시하고 출력 줄 수를 제한한다. 주소는 objdump/readelf 기준 VA.
#   ghidra_re.sh analyze               대상 분석 + 함수·문자열 목록 생성 (sha256이 같으면 재사용)
#   ghidra_re.sh list [정규식]          함수 목록 (addr name size callers callees strings), 큰 함수 순
#   ghidra_re.sh xrefs 정규식           문자열 → 참조하는 함수 주소
#   ghidra_re.sh decomp ADDR [ADDR..]   지정 함수만 디컴파일 (한 번에 여러 개 권장 — 호출마다 JVM 기동)
# 환경변수: GHIDRA_HOME(~/tools/ghidra) RE_TARGET(기본: ./target/ 안의 유일한 파일) RE_GHIDRA_DIR(./_ghidra) RE_MAX_LINES(300) RE_TIMEOUT(600)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
GHIDRA_HOME="${GHIDRA_HOME:-$HOME/tools/ghidra}"
AH="$GHIDRA_HOME/support/analyzeHeadless"
TARGET="${RE_TARGET:-}"
WORK="${RE_GHIDRA_DIR:-./_ghidra}"
MAX_LINES="${RE_MAX_LINES:-300}"
TO="${RE_TIMEOUT:-600}"

die () { echo "ghidra_re: $*" >&2; exit 2; }
usage () { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
cap () {
  local n; n=$(wc -l < "$1")
  head -n "$MAX_LINES" "$1"
  if (( n > MAX_LINES )); then echo "... (${n}줄 중 ${MAX_LINES}줄 표시, 전체: $1)"; fi
}
is_elf () { readelf -h "$1" >/dev/null 2>&1; }
file_base () {
  local b
  if is_elf "$1"; then b=$(readelf -lW "$1" | awk '$1=="LOAD"{print $3}' | sort | head -n1)
  else b=$(objdump -p "$1" | awk '$1=="ImageBase"{print "0x"$2}'); fi
  echo "${b:-0x0}"
}
need_tsv () { [[ -s "$WORK/functions.tsv" ]] || die "분석 결과 없음 — 먼저 'ghidra_re.sh analyze' 실행"; }
run_ah () {
  [[ -x "$AH" ]] || die "analyzeHeadless 없음: $AH (GHIDRA_HOME 확인)"
  local log="$WORK/$1.log"; shift
  mkdir -p "$WORK/home" "$WORK/xdg/config" "$WORK/xdg/cache" "$WORK/tmp"
  local rc=0
  XDG_CONFIG_HOME="$WORK/xdg/config" XDG_CACHE_HOME="$WORK/xdg/cache" \
  _JAVA_OPTIONS="-Djava.io.tmpdir=$WORK/tmp -Duser.home=$WORK/home -XX:-UsePerfData" \
    timeout -k 10 "$TO" "$AH" "$@" -scriptPath "$HERE/ghidra_scripts" > "$log" 2>&1 || rc=$?
  if (( rc == 124 || rc == 137 )); then die "시간 초과(${TO}s). 로그: $log"; fi
  if (( rc != 0 )); then tail -n 20 "$log" >&2; die "analyzeHeadless 실패 rc=$rc. 로그: $log"; fi
  # analyzeHeadless는 postScript 예외에도 0으로 끝나므로 로그로 판정
  if grep -q 'SCRIPT ERROR' "$log"; then grep -A5 'SCRIPT ERROR' "$log" | head -n 8 >&2; die "Ghidra 스크립트 오류. 로그: $log"; fi
}
resolve_target () {
  [[ -n "$TARGET" ]] && return 0
  local f=()
  [[ -d target ]] && mapfile -t f < <(find target -maxdepth 1 -type f | sort)
  if (( ${#f[@]} == 1 )); then TARGET="${f[0]}"; return 0; fi
  die "분석 대상을 정할 수 없음 (./target/ 안 파일 ${#f[@]}개) — RE_TARGET=target/<대상> 을 지정"
}

cmd_analyze () {
  resolve_target
  [[ -f "$TARGET" ]] || die "대상 없음: $TARGET"
  local sha; sha=$(sha256sum "$TARGET" | cut -d' ' -f1)
  if [[ -s "$WORK/functions.tsv" && "$(cat "$WORK/sha256" 2>/dev/null)" == "$sha" ]]; then
    echo "cached: $(( $(wc -l < "$WORK/functions.tsv") - 1 )) functions ($WORK)"; return 0
  fi
  rm -rf "$WORK/proj.gpr" "$WORK/proj.rep" "$WORK/functions.tsv" "$WORK/strings.tsv" "$WORK/sha256"
  local fb; fb=$(file_base "$TARGET")
  local lo=()
  if is_elf "$TARGET" && (( fb == 0 )); then lo=(-loader ElfLoader -loader-imagebase 0); fi
  local t0=$SECONDS
  run_ah analyze "$WORK" proj -import "$(realpath "$TARGET")" "${lo[@]}" \
    -postScript ExportFunctions.java "$WORK/functions.tsv" "$fb"
  [[ -s "$WORK/functions.tsv" ]] || die "functions.tsv 생성 실패 (로그: $WORK/analyze.log)"
  echo "$sha" > "$WORK/sha256"; echo "$fb" > "$WORK/file_base"; basename "$TARGET" > "$WORK/program"
  echo "analyzed: $(( $(wc -l < "$WORK/functions.tsv") - 1 )) functions in $((SECONDS - t0))s ($WORK)"
}
cmd_list () {
  need_tsv
  local out="$WORK/list.txt"
  { head -n1 "$WORK/functions.tsv"
    tail -n +2 "$WORK/functions.tsv" | { if [[ -n "${1:-}" ]]; then grep -E -- "$1" || true; else cat; fi; } \
      | sort -t $'\t' -k3,3nr; } > "$out"
  cap "$out"
}
cmd_xrefs () {
  need_tsv; [[ -n "${1:-}" ]] || die "사용: xrefs 정규식"
  local out="$WORK/xrefs.txt"
  { head -n1 "$WORK/strings.tsv"; tail -n +2 "$WORK/strings.tsv" | { grep -E -- "$1" || true; }; } > "$out"
  cap "$out"
}
cmd_decomp () {
  need_tsv; (( $# )) || die "사용: decomp ADDR [ADDR...]"
  local key="$*" out
  if (( $# <= 3 )) && [[ "$key" =~ ^[0-9a-fA-Fx\ ]+$ ]]; then out="$WORK/decomp_${key// /_}.c"
  else out="$WORK/decomp_$(printf '%s' "$key" | sha1sum | cut -c1-12).c"; fi
  run_ah decomp "$WORK" proj -process "$(cat "$WORK/program")" -noanalysis -readOnly \
    -postScript DecompileAt.java "$out" "$(cat "$WORK/file_base")" "$@"
  [[ -s "$out" ]] || die "디컴파일 출력 없음. 로그: $WORK/decomp.log"
  cap "$out"
}

[[ $# -ge 1 ]] || usage
mkdir -p "$WORK"; WORK="$(cd "$WORK" && pwd)"
cmd=$1; shift
case "$cmd" in
  analyze) cmd_analyze ;;
  list)    cmd_list "$@" ;;
  xrefs)   cmd_xrefs "$@" ;;
  decomp)  cmd_decomp "$@" ;;
  *)       usage ;;
esac
