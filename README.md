# RE-routine

Claude Code plugin for reverse-engineering native (ELF/PE) and WebAssembly binaries.

A bundled script (`recon`) maps the program, follows references from goal-related clues to the functions that matter, extracts the input-check chain, and recommends a decompilation scope. The model then picks an analysis method, records a short plan, works the check chain stage by stage, and passes a verification gate before reporting. Skill instructions are written in Korean.

ELF/PE/WebAssembly 바이너리 분석용 Claude Code 플러그인입니다. 스크립트가 구조와 검사 사슬을 모으고, 모델이 방법을 골라 단계별로 풀고 검증한 뒤 보고합니다.

## 설치 / Install

```
/plugin marketplace add be-hum/RE-routine
/plugin install re-routine@re-routine
```

로컬 클론에서: `/plugin marketplace add /path/to/RE-routine`

## 필요한 도구 / Requirements

| 도구 | 필수 여부 | 용도 |
|---|---|---|
| python3 3.9+ | 필수 | recon |
| binutils (`objdump`, `readelf`, `strings`, `nm`) | ELF/PE 필수 | 구조와 명령 해석 |
| wabt (`wasm-objdump`, `wasm-decompile`) | wasm 분석 시 | wasm 해석·디컴파일 |
| Ghidra (`GHIDRA_HOME`, 기본 `~/tools/ghidra`) | 선택 | ELF/PE 디컴파일. 없으면 디스어셈블만 사용 |
| gdb, node | 선택 | 실행 확인·추적 |

## 사용 / Usage

```
/re-routine targets/crackme/crackme 이 받는 올바른 입력을 찾아줘
```

- 산출물은 대상 파일 폴더의 `work/` 아래에 생깁니다 (`recon/structure.md`, `plan.md`, `result.json`).
- 대상 프로그램은 사용자가 허용할 때만 실행합니다. 허용하지 않으면 정적 분석과 정방향 재구현으로 검증합니다.
- 목적(`--goal`): `input-check`, `network`, `file`, `crypto`, `inventory`, `overview`

도구별 사용법: [skills/re-routine/tools/README.txt](skills/re-routine/tools/README.txt)

## 구성 / Layout

```
.claude-plugin/        plugin.json, marketplace.json
skills/re-routine/
  SKILL.md             분석 지침
  tools/               recon.py, recon_wasm.py, triage.py, ghidra_re.sh, ghidra_scripts/
evals/                 claude plugin eval 케이스
tests/                 도구 단위 테스트 (pytest)
```

## 평가 / Evals

`evals/`의 두 케이스는 작성자가 직접 만든 stripped x86-64 ELF 예제입니다. 실행은 `twostage-run` 케이스에서만 허용됩니다.

| case | binary | sha256 (앞 16자) |
|---|---|---|
| serial12-static | `evals/serial12-static/files/serial12` | `e88c6f981dd948a2` |
| twostage-run | `evals/twostage-run/files/twostage` | `c46df4d37d1ad590` |

```
claude plugin eval .
```

## 테스트 / Tests

```
python3 -m pytest -q tests
```

gcc와 binutils가 필요합니다. 실제 Ghidra 테스트는 `GHIDRA_HOME`이 있을 때만 돕니다.

## License

MIT
