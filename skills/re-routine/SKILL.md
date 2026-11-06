---
name: re-routine
description: Standard binary reverse-engineering routine for native (ELF/PE) and WebAssembly programs. A bundled script (recon) maps the program's structure, follows address references from goal-related clues to the functions that matter, extracts the input-check chain, and recommends a Ghidra/decompiler scope; the model then picks the analysis method from a catalog, records a short plan, works through the check chain stage by stage, switches methods when stuck, finishes with a goal-specific playbook, and passes a verification gate before reporting. Use when asked to reverse engineer, analyze, or find how a binary works, what input it accepts, what it talks to, or what its functions do.
---

# re-routine v1: 사실 수집 → 계획 → 수행·전환 → 목적별 마무리 → 검증·보고

이 스킬에 딸린 도구는 **이 스킬 폴더의 `tools/`**에 있다. 스킬을 불러올 때 표시되는 "Base directory" 경로에 `/tools`를 붙인 것이다. 이하 `<스킬>/tools`로 적는다.
- 도구 설명: `<스킬>/tools/README.txt`
- 스크립트가 사실을 모으고, **분석 방법은 스스로 고른다**. 단계는 순서대로 진행한다.

## 0. 공통 규칙 (모든 단계)
- **대상과 작업 폴더**
  - 대상 파일 경로를 확인한다. 이하 `<대상>`.
  - 작업 폴더는 대상 파일이 있는 폴더의 `work/`다(사용자가 정하면 그것). 이하 `<작업>`.
  - 중간 산출물과 임시 파일은 모두 `<작업>` 안에 둔다.
- **작업 위치**
  - 1단계 첫 명령의 `pwd` 출력(절대 경로)을 기억하고, 경로는 절대 경로 문자열로 쓴다. 환경변수는 명령 사이에 유지되지 않는다.
  - `cd`가 필요하면 `(cd <작업> && ...)`처럼 **서브셸**로만 쓴다. 셸의 현재 위치는 명령 사이에 유지되므로, 맨 `cd`를 쓰면 이후 파일이 엉뚱한 곳에 생긴다.
- **실행 정책**
  - 대상 프로그램 실행과 디버거 구동은 사용자가 허용했거나 과제가 허용할 때만 한다.
  - 허용 여부가 분명하지 않으면 정적 분석과 정방향 재구현으로 검증하고, 실행하면 확인할 수 있는 것을 보고에 적는다.
  - 통신하거나 작업 폴더 밖에 쓰는 프로그램은 실행하지 않는다.
- **명령 위생**
  - 실행, 디버거, 오래 걸릴 수 있는 스크립트에는 `timeout 60` 이하를 붙인다. gdb는 `gdb -batch -nx`로만 실행한다.
  - 큰 출력은 `<작업>`에 저장한 뒤 `grep`이나 `head`로 본다.
- **근거**
  - 모든 주장에는 주소를 붙인다.
  - 디컴파일 결과는 추정이다. 상수, 비교 크기, 분기 조건은 명령어나 데이터 바이트로 대조한다.
- **근거 수준**
  - `seen`: 실제 실행 결과, 또는 바이너리 바이트와의 정확한 대조가 있을 때만
  - `inferred`: 정황으로 추론했을 때
  - `unknown`: 근거가 없을 때 (지어내지 않는다)

## 1. 사실 수집 (첫 번째 분석 호출)
1. 요청에서 `--goal` 하나를 고른다. 요청에 나온 단어나 주소는 `--anchor '<정규식>'` / `--anchor 0x<주소>`로 더한다.

   | goal | 요청 예 |
   |---|---|
   | `input-check` | 올바른 입력·비밀번호·플래그·라이선스 |
   | `network` | 통신 대상과 메시지 형식 |
   | `file` | 읽고 쓰는 파일과 형식 |
   | `crypto` | 암호·해시 알고리즘과 키 |
   | `inventory` | 전체 함수 목록과 이름·역할 |
   | `overview` | 위에 해당 없음, 무엇을 하는 프로그램인지 |

2. 실행한다:

       pwd; python3 -I <스킬>/tools/recon.py <대상> --goal <goal> [--anchor ...] --out <작업>/recon; cat <작업>/recon/structure.md

3. structure.md에서 다음을 읽는다.
   - 1~3절: 형식, 언어, 외부 의존, 함수 지도
   - 4절: 관심 영역 (단서 주소에서 참조를 따라간 함수, 출발점에서의 거리)
   - 4-1절 **검사 사슬**: 함수 안의 입력 → 변환 → 상수 → 비교 → 종료·성공 순서. 입력을 받을 때마다 단계가 나뉜다.
   - 5절 Ghidra 결정 (`none` / `partial` / `full`): **추천**이다.
   - 7절: 추가 조회와 디컴파일에 쓸 **정확한 명령**
4. 결정이 `stop`(패킹 의심)이면 근거와 함께 보고하고 끝낸다.
5. 결정이 `unsupported`(ELF/PE/wasm이 아닌 형식)면 형식에 맞는 도구를 스스로 찾아 같은 사실(함수, 문자열, 호출 관계)을 모은 뒤 2단계로 간다.
6. `objdump`가 없는 등 도구가 부족하면 무엇이 필요한지 사용자에게 알린다.

## 2. 계획 → `<작업>/plan.md`
아래 **방법 목록**에서 이 프로그램에 맞는 방법을 고르고, 실행하기 전에 짧게 적는다. recon 추천을 그대로 따르면 두세 줄이면 된다.

| 방법 | 고르는 신호 |
|---|---|
| 명령어 수준 정적 분석 | 검증 함수가 작고 간접 호출·테이블이 없음 (관심 영역 크기는 런타임 함수 때문에 커 보일 수 있음) |
| 디컴파일 | 함수가 크거나 간접 호출·테이블·VM 신호가 있음, 구조체·반복이 많음 |
| 실제 실행 관찰 | 실행이 허용되고 입력에 따라 출력이 달라짐, 여러 단계의 입력을 받음 |
| 디버거·트레이스 | 실행 중에만 값이 드러남 (풀린 문자열, 계산된 키, 간접 호출 대상). 실행 허용 필요 |
| 재구현 + 탐색 | 변환이 해시처럼 거꾸로 풀 수 없음 → 정방향을 재구현하고 후보를 탐색 |
| 참조 따라가기 | 관심 영역 밖의 함수나 데이터가 필요함 (structure.md 7절의 `xref` 명령) |

```
## 선택
- 방법: <순서대로>
- 이유: <structure.md의 어떤 사실(절·주소) 때문인지>   (추천과 다르면 그 이유도)
## 단계별 계획
- 검사 사슬 단계마다: 무엇을 복원·확인할지
## 전환 기록
- (진행 중 추가) <바꾼 방법> ← <이유>
```

## 3. 수행과 전환
- 검사 사슬이 여러 단계면 **단계마다 따로** 조건을 복원한다. 앞 단계를 통과해야 다음 단계에 도달하므로 순서대로 확인한다.
- 디컴파일이 더 필요하면 structure.md 7절의 `ghidra_re.sh decomp` 명령에 주소를 여러 개 묶어 넘긴다(병렬 호출 금지). wasm이면 `<작업>/recon/decomp/module.dcmp`에서 함수 이름으로 찾는다.
- **바꾸는 조건**
  - 같은 방법으로 tool call 6회 동안 새로 확인된 사실이 없으면 방법 목록에서 다른 방법으로 바꾼다.
  - 도구가 동작하지 않으면(지원 안 함, 실행 실패) 즉시 같은 목적의 다른 수단을 찾는다. 예: 실행기가 안 되면 다른 런타임을 쓴다.
  - 바꿀 때마다 plan.md의 전환 기록에 적는다.

## 4. 목적별 마무리 (goal 하나만)
### 4-input-check
1. 변환 단계를 `<작업>/solve.py`로 재구현한다. 비교 대상은 `<작업>/recon/data/`에서 바이트 그대로 가져온다.
2. 역연산으로 입력을 구한다. 어려우면 바이트·블록 단위 탐색을 쓴다. 줄바꿈 포함 여부, 패딩, 길이 제한도 검사 사슬과 코드에서 확인한다.
3. 보고: 검증 루틴 주소, 단계별 입력, 프로그램이 출력·요구하는 형식 그대로의 값.
### 4-network
대상(호스트·IP·포트·URL), 메시지 형식(필드 순서·길이·고정값), 동작 조건을 주소와 함께 정리한다.
### 4-file
경로(조립 코드 포함), 여는 방식, 데이터 형식(필드·오프셋·검사 조건)을 정리한다.
### 4-crypto
알고리즘(상수 단서, 라운드 구조), 모드, 키·IV의 출처와 위치를 정리한다. 재구현을 시험 벡터나 바이너리 안의 데이터와 대조한다.
### 4-inventory
`<작업>/recon/functions.tsv`(필요하면 `ghidra_functions.tsv`)의 모든 함수에 항목을 만든다. 호출자가 많은 함수와 문자열을 참조하는 함수부터 정한다. 근거가 없으면 `unknown`으로 둔다.
### 4-overview
목적(한두 문장), 진입점부터 주요 기능까지의 흐름, 구성 요소, 외부에 영향을 주는 동작을 정리한다. 모든 주장에 주소를 붙인다.

## 5. 검증과 보고
- **검증 게이트** (보고하기 전에 필수)
  - input-check:
    - 실행이 허용되면 후보 입력으로 성공 경로에 도달하는지 확인하고, 한 글자 바꾼 입력이 실패하는지도 확인한다(반증).
    - 실행할 수 없으면 정방향 재구현이 비교 대상 바이트를 정확히 재현하는지 확인한다.
  - network / file / crypto: 값을 데이터 바이트·시험 벡터와 대조한다.
  - inventory: 무작위 5개 항목의 근거를 다시 확인한다.
  - overview: 모든 주장에 주소가 붙어 있는지 확인한다.
- **결과**
  - 사용자나 과제가 정한 형식과 파일이 있으면 그것을 따른다.
  - 없으면 `<작업>/result.json`에 결론, 근거 주소, 근거 수준(`confidence`)을 쓰고, 다음 필드를 더한다.
    - `"routine": "re-routine/v1"`
    - `"recon_goal"`, `"recon_decision"`
    - `"methods"`: 실제로 쓴 방법 목록(순서대로)
    - `"switches"`: 방법을 바꾼 횟수
    - `"plan"`: plan.md 경로
- **형식**
  - 값(flag, 키, 경로 등)은 프로그램이 쓰는 형식을 **그대로** 적는다. 입력값이 다르면 `input` 필드에 따로 적는다.
  - 입력이 여러 줄이면 줄 순서대로 적는다.
- **마지막 확인**: 결과 파일을 썼다면 `test -f <절대경로> && python3 -I -c 'import json,sys; json.load(open(sys.argv[1]))' <절대경로> && echo OK`로 확인한다.
- 사용자에게는 결론, 핵심 근거(주소), 근거 수준, 확인하지 못한 것을 짧게 보고한다.
