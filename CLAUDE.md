# CLAUDE.md
> Last updated: 2026-05-28

## Progress

```
Pipeline: input package name → Layer 0 → Layer 1 → Layer 2 → Layer 3 → risk score

Layer 0  [████████████████████] DONE   Metadata check (no execution)
Layer 1  [░░░░░░░░░░░░░░░░░░░░] TODO   Static analysis (no execution)
Layer 2  [░░░░░░░░░░░░░░░░░░░░] TODO   Dynamic — simple run (Docker)
Layer 3  [░░░░░░░░░░░░░░░░░░░░] TODO   Dynamic — condition mutation (Docker)
Scoring  [░░░░░░░░░░░░░░░░░░░░] TODO   Aggregate risk score
```

### Layer 0 — What's built
```
src/                            Rust implementation (replaces Python layer0/)
  checker.rs    run_layer0(name) → CheckResult {verdict, findings}
  registry.rs   npm registry + downloads API (reqwest blocking)
  typosquat.rs  levenshtein() + check_typosquat() vs top_packages.txt (~240 pkgs)
  age_check.rs  age < 7 days + download spike ratio (5x threshold)
  maintainer.rs compares first-version vs latest-version maintainer set
  namespace.rs  unscoped name vs top_scoped_packages.txt (~80 scoped pkgs)
  models.rs     Verdict enum, Finding type, CheckResult struct
  main.rs       CLI: npm-pre-scan [--json] [--no-color] <pkg> [<pkg>...]

layer0/data/top_packages.txt        — embedded at compile time; add entries to extend coverage
layer0/data/top_scoped_packages.txt — embedded at compile time; add entries to extend coverage

Binary: npm-pre-scan [--json] [--no-color] <pkg> [<pkg>...]
        exit 0=PASS  1=SUSPECT  2=BLOCK

Legacy Python (kept for reference):
  layer0/*.py, run_layer0.py

Severity rules:
  typosquat distance=1  → BLOCK
  typosquat distance=2  → SUSPECT
  namespace conflict    → BLOCK
  age<7d + spike        → SUSPECT
  maintainer change     → SUSPECT
  (any BLOCK present)   → verdict BLOCK
  (any SUSPECT, no BLOCK) → verdict SUSPECT
```

### Dummy packages — verification status
| Package | Target layer | Prior layers | Status |
|---|---|---|---|
| dummy_typosquat (`expres`) | Layer 0 | — | VERIFIED: BLOCK (typosquat distance=1 from express) |
| dummy_obfuscated | Layer 1 | L0 PASS | not built |
| dummy_install_time | Layer 2 | L0-1 PASS | not built |
| dummy_import_time | Layer 2 | L0-1 PASS | not built |
| dummy_timebomb | Layer 3 | L0-2 PASS | not built |
| dummy_env_triggered | Layer 3 | L0-2 PASS | not built |
| dummy_api_triggered | Layer 3 | L0-2 PASS | not built |

## Goal
npm 패키지 레지스트리를 대상으로 한 **동적 공급망 공격 탐지 프로토타입** 구현.
정적 분석(HCR 등) 중심의 기존 논문 측정 방법론을 보완하여, 실제 행동 기반 탐지 파이프라인을 Layer 0~3 구조로 구축한다.

## Tech Stack
- 언어: Rust (파이프라인 오케스트레이션), Node.js (npm 패키지 실행 환경)
- 컨테이너: Docker (샌드박스 격리)
- 모니터링: strace (syscall), tcpdump (네트워크), DNS 쿼리 로깅
- 시계 조작: libfaketime
- 타이포스쿼팅 탐지: Levenshtein 거리 계산
- 더미 패키지: 각 공격 유형별 npm 패키지 직접 제작

## Decisions Made
- **스코프**: npm 단독 프로토타입으로 시작 (PyPI/Maven/NuGet 확장은 이후)
- **그룹화 기준**: 탐지에 필요한 분석 방법 + 실행 비용 기준으로 Layer화
- **검증 방식**: 더미 패키지를 레이어별로 개별 제작 → 해당 레이어에서만 탐지되고 이전 레이어에서는 통과되는 것을 확인
- **더미 패키지 검증 순서**: 레이어 완성 즉시 해당 더미 패키지 검증 (전체 완성 후 일괄 검증 X)

## Architecture

### Layer 0: 메타데이터 검사 (실행 불필요)
```
입력: 패키지명
검사:
  - 타이포스쿼팅: 상위 1000개 패키지와 Levenshtein 거리 ≤ 2
  - 등록 이력: 패키지 나이 < 7일 + 다운로드 급등
  - maintainer: 최근 소유자 변경 여부 (npm audit signatures)
  - 네임스페이스: unscoped 패키지가 scoped 인기 패키지와 충돌
출력: PASS / SUSPECT / BLOCK
```

### Layer 1: 정적 분석 (실행 불필요)
```
입력: package.json + 소스코드 (tarball 압축 해제)
검사:
  - install script 존재 여부 (pre/post/install)
  - 난독화 탐지: eval(Buffer.from(...,'base64')), hex 문자열
  - 의심 문자열: process.env, ~/.ssh, /etc/passwd
  - 네트워크 관련 import: axios/node-fetch/http 조합
  - 동적 require: require(변수) 패턴
  - 이전 버전 대비 diff (새로 추가된 코드 블록)
출력: 위험 신호 목록 + 점수
```

### Layer 2: 동적 분석 — 단순 실행
```
환경: Docker 컨테이너 (네트워크 격리)
실행:
  1. npm install → install-time 행동 관찰
  2. node -e "require('패키지명')" → import-time 관찰
모니터링:
  - strace: 파일 접근 (read/write/open)
  - 네트워크: tcpdump + DNS 쿼리 로깅
  - 프로세스: child_process.exec/spawn 감지
출력: syscall 로그 + 네트워크 로그
```

### Layer 3: 동적 분석 — 조건 변조
```
환경: Layer 2 컨테이너 + 변조 레이어
시나리오 (순차 실행):
  - 시계 조작: libfaketime으로 +30일, +90일, +180일
  - 환경 위장: HOME=/home/developer, USER=dev, CI 환경변수 제거
  - 호스트명 위장: 일반 개발자 PC명으로
  - API 퍼징: export 함수를 더미 인자로 자동 호출
출력: 각 시나리오별 행동 diff (Layer 2 기준선 대비)
```

## Implementation Tasks
- [x] Layer 0: npm registry API 연동 + Levenshtein 타이포스쿼팅 탐지 구현
- [x] Layer 0: dummy_typosquat 패키지 제작 및 탐지 검증
- [ ] Layer 1: tarball 다운로드 + 정적 분석기 구현 (install script, 난독화, 의심 문자열)
- [ ] Layer 1: dummy_obfuscated 패키지 제작 및 탐지 검증
- [ ] Layer 2: Docker 샌드박스 환경 구성 (strace + tcpdump + DNS 로깅)
- [ ] Layer 2: npm install + require() 자동 실행 및 로그 수집
- [ ] Layer 2: dummy_install_time, dummy_import_time 패키지 제작 및 검증
- [ ] Layer 3: libfaketime 통합 + 시계 조작 시나리오 구현
- [ ] Layer 3: 환경변수 위장 + API 퍼징 구현
- [ ] Layer 3: dummy_timebomb, dummy_env_triggered, dummy_api_triggered 패키지 제작 및 검증
- [ ] 신뢰도 점수 통합: 각 레이어 출력 → 단일 리스크 스코어로 집계
- [ ] 전체 파이프라인 연결 및 E2E 테스트

## Constraints
- npm 단독 프로토타입 (PyPI/Maven/NuGet 확장은 향후)
- Docker 컨테이너 필수 (호스트 시스템 보호)
- Layer 0 → 1 → 2 → 3 순으로 조기 배제 구조 유지 (비용 낮은 레이어 먼저)
- 더미 패키지는 실제 npm publish 없이 로컬 테스트 환경에서만 사용

## Dummy Package Checklist
| 패키지명 | 탐지 레이어 | 이전 레이어 통과 여부 |
|---|---|---|
| dummy_typosquat | Layer 0 | - |
| dummy_obfuscated | Layer 1 | Layer 0 PASS |
| dummy_install_time | Layer 2 | Layer 0-1 PASS |
| dummy_import_time | Layer 2 | Layer 0-1 PASS |
| dummy_timebomb | Layer 3 (시계 조작) | Layer 0-2 PASS |
| dummy_env_triggered | Layer 3 (환경 위장) | Layer 0-2 PASS |
| dummy_api_triggered | Layer 3 (API 퍼징) | Layer 0-2 PASS |

## References
- 논문: 패키지 레지스트리의 다각적 위험도 측정 방법론 (KIISC, 진행 중)
- 데이터: OpenSSF malicious-packages GitHub repo
- 선행 연구: MalOSS (Duan et al., NDSS 2021), OSSF Package Analysis (strace 기반)
- arXiv:2512.14739 (DAF 수치 출처)
- WSL 환경: \\wsl.localhost\Ubuntu\home\hpschkk\npm_pre_scan\

---
Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

Tradeoff: These guidelines bias toward caution over speed. For trivial tasks, use judgment.

1. Think Before Coding
Don't assume. Don't hide confusion. Surface tradeoffs.

Before implementing:

State your assumptions explicitly. If uncertain, ask.
If multiple interpretations exist, present them - don't pick silently.
If a simpler approach exists, say so. Push back when warranted.
If something is unclear, stop. Name what's confusing. Ask.
2. Simplicity First
Minimum code that solves the problem. Nothing speculative.

No features beyond what was asked.
No abstractions for single-use code.
No "flexibility" or "configurability" that wasn't requested.
No error handling for impossible scenarios.
If you write 200 lines and it could be 50, rewrite it.
Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

3. Surgical Changes
Touch only what you must. Clean up only your own mess.

When editing existing code:

Don't "improve" adjacent code, comments, or formatting.
Don't refactor things that aren't broken.
Match existing style, even if you'd do it differently.
If you notice unrelated dead code, mention it - don't delete it.
When your changes create orphans:

Remove imports/variables/functions that YOUR changes made unused.
Don't remove pre-existing dead code unless asked.
The test: Every changed line should trace directly to the user's request.

4. Goal-Driven Execution
Define success criteria. Loop until verified.

Transform tasks into verifiable goals:

"Add validation" → "Write tests for invalid inputs, then make them pass"
"Fix the bug" → "Write a test that reproduces it, then make it pass"
"Refactor X" → "Ensure tests pass before and after"
For multi-step tasks, state a brief plan:

1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.
> This file is auto-maintained by the code-sync skill. Do not edit manually unless necessary.
