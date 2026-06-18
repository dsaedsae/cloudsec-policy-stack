# 캡스톤 · 면접 노트 (M0–M6 + 심화 M7–M9를 졸업한 뒤)

7개 코어 모듈(M0–M6)을 직접 재구현했다면, 이제 **보여줄 것**을 만든다. 아래를 채우면 그대로
포트폴리오 요약이자 면접 답변이 된다. 각 모듈 3칸: **무엇을 재구현했나 / 막는 것 / 막지
*못*하는 것**(정직하게 — 한계를 아는 것이 실력이다). 앵커 한 줄은 시작점일 뿐, 네 말로 다시 써라.
M7–M9는 *심화*다: 새 통제가 아니라 기존 스택을 형식검증(M7)·측정(M8)·침해가정 렌즈(M9)로 재조명하므로,
"무엇을 만들었나"보다 **"무엇을 *증명/측정*했나"**로 말하는 게 정확하다.

> 채우는 법: 각 모듈 README의 **구두 문답**(접힌 답안)을 보지 말고 먼저 말로 답한 뒤, 여기 옮겨라.

---

## M0 · Cedar 인가 (ABAC + RBAC)
- **재구현:** _빈 정책에서 owner/한도/역할/동결 인가를 Cedar로 작성, 11/11._
- **막는 것:** _권한 없는 조회·초과/음수 이체·동결 계좌 이체 (per-request 인가)._
- **못 막는 것(정직):** _앵커 — Deny는 default-deny로 공짜로 맞을 수 있다(통과≠증명); 경계값 없으면 뮤턴트가 산다._

## M1 · 쉬프트레프트 (checkov)
- **재구현:** _하든드 안 된 워크로드의 16개 결함을 수정, Failed 0._
- **막는 것:** _배포 *전에* 잘못된 securityContext/권한/리소스 누락을 정적으로._
- **못 막는 것:** _앵커 — 스캐너는 매니페스트만 본다(런타임 행동은 못 봄); 스킵 남발은 위험을 가린다._

## M2 · 신원 (admission CEL)
- **재구현:** _라벨↔SA 일관성 VAP의 CEL, 위조 DENY/정합 ADMIT 5/5._
- **막는 것:** _label≠SA 위조(kubectl run --labels app=api → default SA → 거부)._
- **못 막는 것:** _앵커 — 자기일관 위조(app:api+api-sa)는 못 막는다 → SA-use 게이트·SPIFFE가 닫는다._

## M3 · 네트워크 (Cilium L3/L7/egress)
- **재구현:** _default-deny에서 최소권한 홉(web→api→db) + L7, 7/7._
- **막는 것:** _횡이동·우회 경로·egress 비콘/유출(인터넷·메타데이터·apiserver)._
- **못 막는 것:** _앵커 — 위치로 신뢰하지 않음이 핵심; 과차단도 결함(가용성)._

## M4 · 런타임 (Tetragon eBPF)
- **재구현:** _data tier 셸 exec만 골라 SIGKILL, id=0 + sh=137 — 선택적 프리미티브(selector 문법)._
- **막는 것:** _침해 후(post-exploit) 데이터 티어에서 *나이브* 셸 실행._
- **못 막는 것(정직):** _앵커 — 선택적 룰은 renamed-binary(`/tmp/x sh`)·execveat·fd-exec로 우회되고(`matchBinaries`는 호출자 매칭), 셸 없는 nc/python·다른 tier·노드 루트는 범위 밖. **그래서 shipped 기본은 zero-exec**(execve+execveat 전부 Sigkill — id도 137; M8 측정·ADR 0001)이고 M4는 그 출발점이다(ED2/ED3=CONFIGURED/NOT_COVERED)._

## M5 · 암호화 (전송 + 저장)
- **재구현:** _ET1(크로스노드 WireGuard) 채점 + capture-wg/etcd 직접 실행·해석._
- **막는 것:** _노드 간 도청(전송), 디스크/백업 유출(저장 etcd AES-CBC)._
- **못 막는 것:** _앵커 — 평문0은 *보강* 증거지 결정적 아님(캡슐화); 사용 중(in-use) 암호화는 범위 밖._

## M6 · 프런티어 (agent-ABAC + ReBAC)
- **재구현:** _AI 에이전트 위임을 Cedar 교집합 + ASI08 위임깊이 cap·홉별 클램프·출처 게이트(17/17) + OpenFGA 관계그래프(11/11)로._
- **막는 것:** _confused-deputy — 과잉권한 에이전트가 저권한 대행사용자 데이터에 닿는 것._
- **못 막는 것(정직):** _앵커 — 라이브 에이전트 런타임/게이트웨이가 아니라 위임 *인가 정책*의 단위테스트; 교집합은 비소유 데이터 한정(owner override)._

## M7 · 형식 검증 (cross-layer, z3)
- **재구현:** _Cilium L7 엣지 × Cedar PDP의 교차계층 일관성을 z3 유한도메인 체크로 — SHADOWED(`ViewAuditLog`: Cedar permit인데 L7이 경로 드롭=죽은 규칙) / UNGATED(L7 도달가능한데 PDP 게이트 부재). 세 입력 모두 진짜 아티팩트에서 유도(cedarpy 실평가·netpol 전사·`main.py` AST 워크)._
- **막는 것:** _어느 단일 층 테스트도 못 잡는 *연접* 결함 — 특히 UNGATED(라우트가 `authorize()`를 떨어뜨린 사일런트 인가우회=BOLA의 전제). `--ungate-transfer`로 발화시켜 exit 1, CI 게이트가 살아있음을 증명._
- **못 막는 것(정직):** _앵커 — 도메인이 action 3개라 z3는 파이썬 컴프리헨션과 *바이트 동일*(기법 시연이지 unbounded 검증 아님 — 진짜 심볼릭은 cedar-policy-symcc). per-action 일관성만 봄 → L7정규식↔FastAPI 라우트 불일치·context의존 permit(amount=−1)은 범위 밖. SHADOWED는 버그가 아니라 명시화(warning/exit 0); 판정은 사람 몫._

## M8 · 런타임 kill 경계 (detection ≠ prevention)
- **재구현:** _M4 선택적 셸-kill의 경계를 *라이브로 측정* — `verify-runtime-scope`로 Phase1 선택적(id=0/sh=137) → Phase2 zero-exec(id=137, 이름·arg0 무관·execveat 포함)의 델타를 보이고 shipped 기본으로 복원. 메트릭은 불변(80%): 통제 가감이 아니라 증거를 정직하게 진화._
- **막는 것:** _execve+Sigkill은 **pre-image-load**(셸이 첫 명령 전에 죽음)라 prevention-grade. zero-exec는 데이터 티어의 *모든* exec를 두 진입점(`sys_execve`+`sys_execveat`) 후킹으로 죽여 renamed-binary·fd-exec까지 닫음._
- **못 막는 것(정직):** _앵커 — write()는 동기 process-kill이어도 커널이 이미 바이트를 씀(detection-grade, prevention엔 Sigkill+Override 필요). io_uring(`IORING_OP_READ`)은 *기본 syscall 정책*에 blind — "Tetragon이 우회됐다"가 아니라 LSM/KRSI가 해법. zero-exec는 `tier: data` 한정(web/api는 정상 exec 있어 NOT_COVERED, 과잉차단도 결함). restart-tolerance는 이미지가 아니라 Tetragon 부착-창 덕(fragile)._

## M9 · 침해 가정 (블래스트 반경 봉쇄)
- **재구현:** _web 파드 제로데이 RCE를 *가정*하고 `grade.sh`로 봉쇄 경계를 라이브 측정 — 횡이동(L3 `000`/L7 `403`)·유출(egress→인터넷·메타데이터·apiserver `000`)·권한상승(SA 권한0 `can-i=no`)·데이터티어 도달 시 exec `137`. 익스플로잇은 안 돌림; `probe-web`이 web과 *동일 Cilium 신원*이라 네트워크-정책 등가._
- **막는 것:** _제로데이를 막는 정책은 *없다*(미지엔 시그니처가 없음) → 현실적 답은 시그니처 없이 작동하는 봉쇄: default-deny·SA 권한0·zero-exec가 *기본 금지*로 횡이동·유출·권한상승 경로 자체를 닫음. break-and-fix로 egress 한 줄 열면 BREACH로 뒤집힘을 확인._
- **못 막는 것(정직):** _앵커 — 봉쇄는 피해를 *줄이지* 없애지 않는다. 같은 티어 내부 피해(web이 합법적으로 하는 것), 위조 가능한 데모 X-User(JWT enforce 전), 허용 egress(DNS)의 covert 채널, io_uring 회피, 노드 루트·하이퍼바이저 탈출·공급망은 전부 잔여._

---

## 한 문단 요약 (이력서/포트폴리오용)
_예: "금융 망분리 완화(MLS) 보상통제 스택의 7개 통제(인가·스캔·신원·네트워크·런타임·암호화·에이전트
위임)를 빈 파일에서 직접 재구현하고, 각 repo의 실행 가능한 채점기로 검증했다. 각 통제가 막는 것과
막지 못하는 것을 정직하게 구분할 수 있다."_ — 네 경험으로 다시 써라.
