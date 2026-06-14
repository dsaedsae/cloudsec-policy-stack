# 교육용으로 쓰기 (instructor · 사내교육 가이드)

이 저장소는 따라치기 슬라이드가 아니라 **빈 파일에서 통제를 직접 재구현하면 기존 검증 하네스가
자동 채점**하는 트랙이다. 그래서 보안/플랫폼 엔지니어 온보딩, 부트캠프, 대학 실습, CISO팀 워크숍에
그대로 쓸 수 있다. **MIT 라이선스 — 자유롭게 포크·도입.**

## 두 트랙

| 트랙 | 모듈 | 환경 | 즉시성 |
|---|---|---|---|
| **무클러스터** | M0(Cedar 인가) · M1(checkov) · M6(에이전트 ABAC+ReBAC) · M7(formal/z3) | Python만 (+M6 Part B는 Docker) | **GitHub Codespaces로 0설치, 브라우저 즉시** |
| **클러스터** | M2(신원 VAP) · M3(Cilium) · M4(Tetragon) · M5(암호화) · M8(kill 경계) | kind + Docker + **RAM ~6–8GB** | 로컬 또는 큰 머신, `up → 채점 → down` 한 세션 |

## 빠른 시작 (3택)

1. **브라우저 (강추, 코호트용):** 저장소에서 **Code ▸ Codespaces ▸ Create** → 컨테이너가 의존성을
   자동 설치 → 터미널에서 `python labs/m0/grade.py --ext`. 학습자 1인 1 Codespace = 설치 지원 0.
2. **로컬 (Linux/macOS):** `make setup` → `make m0` (또는 `make progress`로 진도 표). 클러스터 트랙은
   `make up` → `make verify` → `make down`.
3. **Windows:** [labs/SETUP.md](../labs/SETUP.md)의 Track A/B (PowerShell + Git Bash, choco/winget).

## 채점·진도·리셋

- **자동 채점:** 각 모듈에 그레이더가 딸려 있다(`labs/<m>/grade.*`). 학습자는 `labs/<모듈>/` 안의
  작업 파일만 편집하고, **canonical(정답지)은 그레이더가 채점 후 자동 복원**한다 — 스택은 항상
  known-good로 돌아온다.
- **진도 한눈에:** `make progress`(=`python scripts/progress.py`)가 무클러스터 모듈을 실제로 돌려
  `done / todo / cluster`를 표로 보여준다.
- **학습자 간 리셋:** `git restore labs/` 또는 새 Codespace. canonical은 어차피 자동 복원되므로 별도
  정리 부담이 적다.

## 아젠다 예시

- **반나절(무클러스터):** M0(인가 as-code) → M1(쉬프트레프트) → M6(에이전트 위임). Codespaces만으로.
- **1일:** 위 + 클러스터 한 세션(`up`)에서 M2→M3→M4→M5 연속 → `down`.
- **자기주도:** [labs/README.md](../labs/README.md)의 사다리대로. 각 모듈 ~20분~수시간(README 헤더에 표기).

## 왜 이 방식이 가르치기 좋은가 (차별점)

- **통과 ≠ 증명:** M0은 *빈 정책으로도 일부 Deny가 공짜로 통과*함을 보여주고(default-deny), 뮤테이션
  테스트로 "통과하는 스위트 ≠ 좋은 스위트"를 체감시킨다.
- **막지 *못*하는 것도 가르친다:** 각 통제의 잔여위험을 정직하게 명시한다(예: M4 셸-kill은 이름 바꾼
  바이너리에 우회됨 → M8에서 경계를 측정). 과대주장이 아니라 *경계를 아는* 엔지니어를 만든다.
- **면접 직결:** 각 모듈의 "학습 성과(면접에서 말할 수 있는 것)" + 구두 문답(접힌 답안) + 캡스톤 노트.

## 규제 맥락 (한국 금융)

전체가 FSC 「금융분야 망분리 개선 로드맵」의 **다층보안(MLS) 보상통제**에 매핑돼 있어, 금융권 보안
교육에 직접 쓸 수 있다 — [MLS 매핑](financial-mls-mapping.md). *(교육용이며 법률/금융 자문이나 공식
컴플라이언스 매핑은 아니다.)*
