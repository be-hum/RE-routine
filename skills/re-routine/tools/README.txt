분석 도구 (<스킬>/tools — 스킬을 불러올 때 표시되는 Base directory + /tools)

1) recon — 구조 파악 + 목적 관련 함수 찾기 + Ghidra 범위 결정을 한 번에 (수 초 ~ 수십 초)
   python3 -I <스킬>/tools/recon.py <대상> --goal <goal> [--anchor 정규식|0x주소] [--out <작업>/recon] [--no-ghidra]
   goal: input-check | network | file | crypto | inventory | overview
   결과: <작업>/recon/structure.md (먼저 읽을 구조 지도), region.tsv(관심 영역), functions.tsv, xrefs.tsv,
         disasm/<주소>.s, decomp/<주소>.c (Ghidra 결정이 partial일 때), data/<주소>.hex
         chain/<주소>.txt (검사 사슬: 함수 안 명령 순서대로 입력→변환→상수→비교→종료·성공, 입력마다 단계 구분)
   주소 참조 조회 (Ghidra 없이 즉시):
     python3 -I <스킬>/tools/recon.py xref --to 0x<주소> --out <작업>/recon     이 주소를 참조하는 명령·함수
     python3 -I <스킬>/tools/recon.py xref --from 0x<주소> --out <작업>/recon   이 함수가 참조하는 주소

2) Ghidra headless 래퍼 — 주소는 모두 objdump/readelf 기준 VA
   RE_TARGET=<대상> RE_GHIDRA_DIR=<작업>/recon/_ghidra 를 앞에 붙여 쓴다.
   (RE_TARGET 을 생략하면 현재 폴더의 ./target/ 안 유일한 파일, RE_GHIDRA_DIR 을 생략하면 ./_ghidra)
   bash <스킬>/tools/ghidra_re.sh analyze              분석 + 함수/문자열 목록 생성 (결과가 있으면 즉시 재사용)
   bash <스킬>/tools/ghidra_re.sh list [정규식]         함수 목록: addr name size callers callees strings (큰 함수 순)
   bash <스킬>/tools/ghidra_re.sh xrefs 정규식          문자열 → 그 문자열을 참조하는 함수 주소
   bash <스킬>/tools/ghidra_re.sh decomp ADDR [ADDR..]  지정 함수만 디컴파일. 호출마다 수 초 걸리므로 여러 주소를 한 번에 넘긴다.
   출력은 RE_MAX_LINES(기본 300)줄에서 잘리며, 전체는 안내된 파일에서 grep 한다.
   decomp 는 같은 Ghidra 폴더를 잠그므로 병렬로 여러 번 호출하지 말고, 주소 여러 개를 한 번에 넘긴다.
   디컴파일 결과는 추정이다. 상수와 분기 조건은 objdump 로 해당 주소를 직접 확인한다.
   recon 결과의 structure.md 7절에 이 대상에 맞춘 정확한 명령이 적혀 있다.

3) triage (recon 에 포함됨, 단독 사용 가능)
   python3 -I <스킬>/tools/triage.py <대상> [--task flag|functions|general] [--json]
