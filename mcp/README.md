# mcp/ — cloudsec-tutor MCP 서버 (학습용, 선택)

`cloudsec-policy-stack` 재구현 트랙([../TUTOR.md](../TUTOR.md) 참고)을 **소크라테스식으로 돕되 답을 흘리지 않는** 로컬 MCP 서버. 네 클론에서 stdio로 띄우고 MCP 클라이언트(Claude Desktop 등)를 붙이면, AI가 **진도·채점·힌트·문제정의·답 가린 레슨**에만 접근한다 — **정답지를 읽는 도구 자체가 없다.**

## TUTOR.md 와의 관계 (보완, 대체 아님)

- **[TUTOR.md](../TUTOR.md)** = *프롬프트* 방화벽. claude.ai/ChatGPT/Claude Code 어디서나 붙여넣어 쓴다. 하지만 그 AI가 repo 파일을 자유롭게 읽을 수 있으면, 결국 "안 흘리겠다는 약속"에 기댄다.
- **이 MCP 서버** = *구조적* 방화벽. AI가 **오직 이 서버를 통해서만** repo에 닿을 때, 노출 표면이 고정 allowlist로 묶여 정답지 파일은 **물리적으로 도달 불가**다. 자유 `read_file(path)` 도구가 없다.
- 둘을 같이 쓰면 가장 강하다: `socratic_tutor` 프롬프트(이 서버가 제공) + 도구들.

## 노출 도구 (정답 없음)

| 도구 | 하는 일 | 안 하는 일 |
|---|---|---|
| `list_progress()` | 무클러스터 모듈(M0/M1/M6/M7) 실제 채점 → done/todo 진도 | — |
| `grade(module)` | 모듈 채점기 실행 → 점수·PASS/FAIL·(실패 시) 요건 힌트. 클러스터 모듈은 `up→grade→down` 안내로 SKIP | 정답지·canonical diff·기대값 표 **반환 안 함** |
| `hint(module)` | 채점기 `--hint` 수준 요건 넛지(채점기가 스스로 "정답 아님"이라 명시하는 고도) | 코드/정답 **아님** |
| `read_spec(module)` | 모듈이 *대상으로 작성*하는 열람-OK 스펙(Cedar `schema/entities/requests`, `probes.yaml`) = "무엇을 만들지" | 정답지 아님 |
| `read_lesson(module)` | 모듈 README의 **prose·요건·Socratic 질문·shell 명령**. 접힌 구두문답 *답* + worked 정책/매니페스트/DSL 코드(모든 비-shell 펜스, 태그 불문) + 작성자가 표시한 가이드 답-walk 구역(`TUTOR:CUT`)은 가려서 반환 | 접힌-답·LEARN.md·정답 코드·답-walk **노출 안 함** |
| `socratic_tutor` (프롬프트) | TUTOR.md의 붙여넣기 시스템 프롬프트를 그대로 제공 | — |

## 방화벽이 막는 것 / 못 막는 것 (정직하게)

**구조적으로 막는다** (`firewall_test.py`가 81개 체크로 증명, CI 회귀방지 가능):
- 모든 모듈의 노출 allowlist ∩ 정답지 denylist = ∅.
- `read_guarded()`는 정답지(`cedar/policies.cedar`·`formal/cross_layer.py`·`*/LEARN.md` 등)·`*.solution.*`·`site/` 사본을 거부(대소문자·`//`·`..` 정규화 우회 + repo 밖 경로 이탈도 차단).
- `read_lesson`은 **세 겹**으로 worked 답을 제거: ① 접힌 `<details>` 답(`open`·summary-less 포함) ② *모든 비-shell 펜스 코드*(cedar/yaml/fga/cel/untagged… 태그 불문 — shell 명령·prose만 유지) ③ 작성자가 `TUTOR:CUT`로 표시한 가이드 답-walk(README의 "정책 한 줄씩"·핵심-힌트 표 등). 검증: 6개 모듈에서 canonical 답파일의 verbatim 3연속줄 무재현 + red-team이 찾은 정확한 누수 토큰(예: m6 `delegated_by_max_classification`, m4 `action: Sigkill`, m3 `/accounts/[^/]+`) 부재를 테스트가 단언.

**범위 한 가지 (정직하게):** verbatim 무덤프 보증은 답이 *유도해야 할 정책 로직*인 모듈(m0·m2–m8·m10)에 강제된다. **M1은 예외** — 목표가 스캐너 결과 *트리아지*고, 그 수정은 PSS-`restricted` 표준 securityContext(공개 K8s 하드닝, 이 repo 공개 사이트·모든 CIS/NSA 가이드에 있음)라 *유도할 비밀*이 아니다. 그래서 M1의 CKV 그룹핑 교육표는 가리지 않는다(가리면 보안 이득 0에 랩만 망가진다).

**못 막는다 — 알고 써라** (DRM이 아니라 *정직한 학습 보조*다):
- 서버를 로컬에서 돌리는 너는 **디스크에 repo 전체**를 갖고 있다 → 네 에디터로 `cedar/policies.cedar`를 직접 열 수 있다. 방화벽은 *AI가 이 서버를 통해 너에게 중계하는 것*을 묶지, *사람이 직접 여는 것*을 막지 않는다.
- AI가 이 서버 **밖의** 도구(파일시스템 MCP, 셸 등)도 동시에 갖고 있으면 그 경로로 정답지를 읽을 수 있다 → **이 서버만 붙이거나**, TUTOR.md 프롬프트와 함께 써라.
- 정답지는 어차피 공개 docs 사이트·repo에 있다(졸업 후 `diff`용). 목표는 "*스스로 쓰기 전에 답을 들이밀지 않게*"지 비밀 유지가 아니다.

## 설치 / 연결

```powershell
# repo 루트의 .venv (그래더가 쓰는 그 인터프리터)
pip install -r requirements-dev.txt    # 그래더 의존성 (이미 있으면 생략)
pip install -r requirements-mcp.txt    # mcp==1.28.0
```

MCP 클라이언트 설정(예: Claude Desktop `claude_desktop_config.json`) — **절대경로**로:

```json
{
  "mcpServers": {
    "cloudsec-tutor": {
      "command": "C:\\path\\to\\cloudsec-policy-stack\\.venv\\Scripts\\python.exe",
      "args": ["C:\\path\\to\\cloudsec-policy-stack\\mcp\\tutor_server.py"]
    }
  }
}
```

직접 띄워 확인:

```powershell
.venv\Scripts\python.exe mcp\tutor_server.py    # stdio — 클라이언트가 붙는다
```

## 클러스터 모듈

`grade()`는 무클러스터 모듈(M0/M1/M6/M7)만 직접 채점한다. M2–M5·M8–M11은 kind 클러스터가 필요해 **SKIP + `scripts/up` 세션에서 돌릴 명령**을 안내한다(절차: [`runbooks/00-lab-cluster-session.md`](../runbooks/00-lab-cluster-session.md) · [`labs/SETUP.md`](../labs/SETUP.md)).

## 방화벽 자가검증

```powershell
.venv\Scripts\python.exe mcp\firewall_test.py    # 누수 있으면 exit 1
```

`firewall.py`는 `mcp` 의존성이 없어 단독 단위테스트가 된다 — "방화벽을 누가 검증하나"의 답이 이 파일이다.
