# M4 — 런타임: Tetragon eBPF로 셸 실행 차단

<div class="lab-pills">
<span class="lab-progress">모듈 5 / 7</span> · <span class="lab-badge">스택 Tetragon eBPF</span> · <span class="lab-badge">소요 ~20–35m</span> · <span class="lab-badge cluster">클러스터 필요 · RAM ~6–8GB</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

**미션:** data tier 파드에서 셸(`/bin/sh` 류) 실행을 커널에서 즉시 SIGKILL하되, 정상 바이너리는
건드리지 않는 **선택적** TracingPolicy를 작성한다. DB 컨테이너가 셸을 띄울 일은 없다 — 그건 침입이다.

> **학습 성과 (면접에서 말할 수 있는 것):** 셸 exec만 *선택적으로* SIGKILL하는 TracingPolicy를 작성하고, 이 룰이 *못* 막는 것(나이브 직접 execve만 잡음 — renamed/execveat 우회, M8에서 측정)을 정직히 말할 수 있다. → [캡스톤 M4](../capstone.md)

**클러스터 필요.** **편집 파일:** `labs/m4/tracingpolicy.yaml` (selectors).

> 선행: M2/M3 권장(같은 세션). 배경: [`docs/04-runtime.md`](../../docs/04-runtime.md).

> **selector 문법이 막막하면 → [배우기 모드: LEARN.md](LEARN.md).** kprobe 한 개(matchArgs Postfix + Sigkill)를 주석과 함께 읽고 → operator를 빈칸으로 채우고 → 나머지는 직접. 이 룰이 못 막는 우회까지 짚어준다.

---

## 왜 런타임 통제인가

네트워크 정책·Cedar·admission은 *요청 전/시점*에 막는다. 하지만 워크로드가 *이미 털린 후*엔
아무것도 안 본다. Tetragon(eBPF)은 런타임을 *지속* 감시한다 — data tier에서 셸 exec이 보이면
침입으로 간주하고 커널에서 죽인다.

**무슨 공격을 막나:** *post-exploit 페이로드 실행*이다. 앱 RCE(역직렬화·SSTI·log4shell류)로 코드 실행이
잡히면 다음 손동작은 거의 항상 셸을 띄워 발판(reverse shell, `sh -i`, 정찰·횡적 이동)을 만드는 것이다.
data tier db는 정상 운영에서 자식을 fork-exec할 일이 없다(프로브가 httpGet이라 exec조차 안 탄다) — 거기서
보이는 셸 exec은 정의상 침입이다. 통제 지점이 execve인 이유: 새 프로그램을 돌리려면 결국 execve(2)를
호출해야 하고, 그 첫 인자(arg0)가 실행 파일 경로다. 진입을 kprobe로 후킹해 경로를 보고 SIGKILL하면 셸은
첫 명령 전(이미지 로드 이전)에 죽는다 — detection이 아니라 prevention이다.

> **정직한 범위(과장 금지):** 이 룰은 *셸 **이름**의 직접 execve*만 죽인다(arg0 Postfix). 셸을 **다른
> 이름으로** 띄우면 우회된다(renamed-binary/execveat/fd-exec — Q4). 정확한 주장은 "셸을 못 띄운다"가
> 아니라 "나이브 직접 셸-명 execve를 죽인다". 그 경계를 *라이브로 측정*하는 게 **[M8](../m8/README.md)**,
> 강건한 답은 **zero-exec**(execve+execveat 전부 Sigkill)·distroless다 — matchBinaries는 *호출자*를 매칭해
> 답이 아니다([THREAT_MODEL](../../THREAT_MODEL.md) 잔여위험). 그 zero-exec가 실제 shipped 기본
> (`k8s/tracingpolicy.yaml`)이고 이 랩은 그 *출발점인 학습용 프리미티브*다. 강건화 기록:
> [ADR 0001](../../docs/decisions/0001-data-tier-zero-exec.md).

## Step 0 — 베이스라인

> 클러스터가 떠 있다고 가정한다(M2~M5 한 세션). 안 떴으면 PowerShell에서 `scripts\up.ps1` 먼저.
> 채점기는 **Git Bash**에서 (forward slash). [SETUP](../SETUP.md).

```bash
# Git Bash 창에서:
kubectl cluster-info --context kind-cloudsec   # 떴는지 확인 (에러면 → PowerShell: scripts\up.ps1)
bash labs/m4/grade.sh        # 시작: selectors가 비어서 아무것도 안 죽인다 → 셸이 살아서(rc=0) FAIL
```

> 빈 selectors는 "매칭 없음 → 액션 없음" → 셸이 안 죽는다. 즉 통제가 *없다*. `id`는 당연히 산다.
> **둘 다 살아있으면 "통제 없음"이지 "선택적 kill"이 아니다.**

## Step 1 — selectors 작성

`labs/m4/tracingpolicy.yaml`의 selectors를 채워라:

```yaml
selectors:
  - matchArgs:
      - index: 0
        operator: "Postfix"
        values: ["/sh", "/bash", "/dash", "/ash", "/busybox"]
    matchActions:
      - action: Sigkill
```

<!-- TUTOR:CUT -->
- `index: 0` = execve의 첫 인자(실행 파일 경로).
- `operator: "Postfix"` = 경로가 그 값으로 *끝나면* 매칭. `/bin/sh`·`/usr/bin/bash` 등 접두가 달라도
  잡는다. `/usr/bin/id`는 목록에 없으니 안 잡힌다 → **선택적**.
- `action: Sigkill` = 커널에서 즉시 종료(rc=137).

**전체 정책 한 줄씩(정답지 기준):** `tracingpolicy.solution.yaml`을 위에서 아래로 — 각 줄이 *없으면*
무엇이 깨지는지가 그 줄의 존재 이유다.

| 줄 | 의미 | 빠지면 |
|---|---|---|
| `podSelector.matchLabels.tier: data` | 이 정책은 `tier: data` 라벨 파드에만 붙는다. | 라벨 없으면 web/api까지 셸 kill → 정상 셸 쓰는 티어가 깨진다(과잉, ED3 범위 밖). |
| `kprobes[].call: "sys_execve"` | 후킹 지점 = execve syscall 진입. | 다른 syscall이면 exec를 아예 못 본다. |
| `syscall: true` | call 값을 raw 함수명이 아닌 *syscall*로 해석(아키텍처별 `__x64_sys_execve` 래핑을 Tetragon이 처리). | 생략하면 심볼명을 직접 맞춰야 하고 이식성이 깨진다. |
| `args[].index: 0` + `type: "string"` | execve 첫 인자를 문자열로 읽겠다고 *선언*. 이게 있어야 아래 `matchArgs`가 그 인자를 검사할 수 있다. | 인자를 안 읽으면 matchArgs가 검사할 대상이 없다. |
| `selectors[].matchArgs[].operator: "Postfix"` | "경로가 values 중 하나로 *끝나면*" 참. | `Equal`이면 `/bin/sh`를 못 잡는다(Step 2-②). 비우면 매칭 0 → 아무것도 안 죽음. |
| `values: ["/sh","/bash","/dash","/ash","/busybox"]` | 죽일 셸 이름 목록(접두 무시). `/usr/bin/id`는 없음 → 생존. | 좁으면 우회(`/dash`만 빼도 dash 생존), 넓으면 과잉(Step 2-③). |
| `matchActions[].action: Sigkill` | 매칭 시 커널에서 SIGKILL. | 비우면 "매칭은 되는데 액션 없음" → 안 죽음. `sigkill`/`SIGKILL` 오타도 무효(대소문자 정확히 `Sigkill`). |

`args`(무엇을 *읽을지*)와 `selectors.matchArgs`(읽은 걸 *어떻게 판정할지*)는 별개라 둘 다 `index: 0`을
가리켜야 같은 인자를 본다 — 위 표의 4행·5행이 짝이다.
<!-- /TUTOR:CUT -->

```bash
bash labs/m4/grade.sh        # id=0 PASS + sh=137 PASS → M4 GRADUATED. 채점 후 canonical 복원.
```

## Step 2 — break-and-fix (예측 → 확인)

1. `values`를 `["/sh"]` 하나만 남긴다 → `sh`는? `bash`는? (이 데모 이미지엔 어떤 셸이 있나 — busybox 기반이면?)
2. `operator`를 `"Postfix"`에서 `"Equal"`로 바꾼다 → `/bin/sh`로 실행되면 매칭되나? (Equal은 정확히 그 문자열)
3. `values`에 `/id`를 추가한다 → `id` 케이스는? (이제 과잉 kill — 정상 바이너리를 죽인다)
4. `matchActions`를 `[]`로 비운다(나머지는 그대로) → `sh`는? (매칭은 되는데 액션이 없다)
5. `values`에 `Postfix`로 `["/sh"]`를 두되 `kprobe.args` 블록(`index:0/type:string` 선언)을 통째로 지운다 → apply는 되나? `sh`는 죽나?

<details><summary>2번 후 열 것</summary>Equal은 인자가 정확히 "/sh"여야 매칭. 실제 exec 경로는 "/bin/sh"라 매칭 안 됨 → 셸이 살아남아 FAIL. 그래서 경로 접두를 모르는 상황엔 Postfix가 맞다. 통제는 *실제 관측되는 값*에 맞춰야 한다.</details>
<details><summary>3번이 가르치는 것</summary>과잉 차단도 결함이다 — 정상 운영(헬스체크가 id류를 쓸 수 있음)을 깨면 가용성 사고. 채점기가 "id는 살아야 PASS"를 요구하는 이유: 선택성이 핵심이지 "다 죽이기"가 아니다.</details>
<details><summary>4번 예측 → 확인</summary>예측: matchArgs가 참이라 죽을 것 같다? 아니다. selector는 "조건(matchArgs) AND 액션(matchActions)"이다 — 액션이 비면 매칭돼도 *할 일이 없어* 셸이 산다(rc=0). 채점은 sh=137을 기대하므로 FAIL. matchArgs는 "언제", matchActions는 "무엇을"이고 둘 다 있어야 통제가 성립한다.</details>
<details><summary>5번이 가르치는 것 (조용한 실패의 함정)</summary>apply는 *성공한다* — 스키마상 args는 필수가 아니다. 그래서 위험하다: 정책이 적용됐다고 안심하지만, arg를 읽도록 *선언*하지 않으면 matchArgs가 검사할 인자 데이터가 없어 매칭이 안 잡힐 수 있다(셸 생존, rc=0). "apply 성공 = 통제 작동"이 아니다. 통제는 항상 *동작*으로 검증해야 한다(grade.sh의 rc 확인) — 이게 채점기를 신뢰하고 yaml lint를 신뢰하지 않는 이유다.</details>

### 흔한 실수 (실제로 막히는 지점)

- **`syscall: true` 누락.** 빼면 환경에 따라 후킹이 안 붙어 *FAIL인데 정책은 로드된 것처럼* 보인다(표 3행).
- **eBPF 로드 지연.** apply 직후 바로 테스트하면 아직 attach 전이라 셸이 산다 → false FAIL.
  grade.sh가 `sleep 6`을 두는 이유. 수동 테스트 땐 몇 초 기다려라.
- **rc=137 vs 143.** grade.sh는 둘 다 PASS로 친다 — 시그널 전달 타이밍/셸 래핑에 따라 137(SIGKILL)이
  143(SIGTERM)으로 보일 수 있어서다. 죽었다는 사실이 핵심.

## Step 3 — 구두 문답

1. <details><summary>왜 "셸이 죽었다"만으로는 부족하고 "id는 살았다"도 같이 봐야 하나?</summary>전부 죽이는 정책(또는 파드가 그냥 안 떠서 모든 exec 실패)도 "셸 죽음"을 만족한다. id가 rc=0으로 살아야 "셸만 골라 죽인다 + 파드는 건강하다"가 증명된다 — false-pass 방지(이 repo의 적대적 검증이 실제로 이 클래스의 false-pass를 잡았다).</details>
2. <details><summary>eBPF 런타임 통제가 admission/netpol과 다른 점은?</summary>admission/netpol은 생성/연결 시점의 *사전* 통제. Tetragon은 실행 중 syscall을 *지속* 관찰하는 사후 탐지·차단. 침해 후(post-exploit) 단계를 본다.</details>
3. <details><summary>Sigkill을 커널에서 하는 것과 사용자공간 에이전트가 죽이는 것의 차이는?</summary>eBPF는 커널에서 syscall 시점에 즉시 죽여 *타이밍 레이스*엔 강하다. 단 "어느 syscall/이름을 후킹하느냐"는 별개 문제다 — arg0-Postfix는 renamed-binary로 쉽게 우회된다(Q4). 사용자공간 에이전트는 폴링/지연이 있어 빠른 공격이 빠져나갈 수 있다.</details>
4. <details><summary>이 통제의 한계(THREAT_MODEL 기준)는?</summary>data tier에만, **셸 *이름*의 직접 execve**만 본다(arg0 Postfix). 그래서 셸을 *다른 이름으로* 띄우면 우회된다: 쓰기가능 /tmp + busybox로 `cp /bin/busybox /tmp/x && /tmp/x sh`, execveat(별도 syscall, 미후킹), fd-exec(arg0=/proc/self/fd/N). 즉 ED1은 "*나이브* 직접 셸-명 execve를 죽인다"이지 "셸을 못 띄운다"가 아니다 — 강건한 답은 zero-exec(execve+execveat 전부 Sigkill), allowlist가 필요하면 BPF-LSM(matchBinaries 아님 — Q5). 그밖에 nc/python로 셸 없이 하는 짓, 다른 tier, 노드 루트도 범위 밖(평가에서 ED2/ED3는 CONFIGURED/NOT_COVERED). 측정: [M8](../m8/README.md).</details>
5. <details><summary>왜 shipped 기본은 "이름 목록"을 못 버리고 통째로 zero-exec로 갔나? matchBinaries로 nginx만 allowlist하면 안 되나?</summary>`matchBinaries`는 execve의 *호출자* 바이너리를 매칭하지, 새로 뜰 이미지를 매칭하지 않는다. 그래서 `matchBinaries NotIn [nginx]`는 `nginx -v`(호출자=런타임 exec shim)를 잘못 죽이면서, nginx-RCE로 띄운 셸(호출자=nginx)은 *놓친다* — "어떤 바이너리가 실행되나"엔 틀린 도구. data tier db는 정당하게 exec할 일이 0(PID1 본체 + httpGet 프로브)이므로, 이름·호출자 whack-a-mole 대신 `sys_execve`+`sys_execveat` 전부 SIGKILL이 정답. 이름 기반 allowlist가 *정말* 필요하면 arg0 문자열이 아니라 BPF-LSM(`bprm_check_security`)의 바이너리 신원이어야 한다. 근거: [ADR 0001](../../docs/decisions/0001-data-tier-zero-exec.md).</details>
6. <details><summary>zero-exec가 db의 entrypoint(PID1)도 execve로 뜨는데 왜 db가 CrashLoop 안 하나? distroless면 안전한가?</summary>restart-tolerance는 *이미지*가 아니라 Tetragon의 **enforcement-attach 창** 덕분이다 — 컨테이너 PID1 entrypoint의 execve가 정책 attach *이전*에 일어나 빠져나간다(이미지 무관, alpine·distroless 둘 다 라이브로 Ready 확인). fragile하다: 더 빠른 attach는 entrypoint를 죽여 CrashLoop을 낼 수 있다. distroless의 진짜 이점은 *restart-safety가 아니라 이미지층*이다 — chainguard/nginx는 `/bin/sh`·busybox가 *애초에 없어*(정책 적용 전에 이미 "no such file") 공격자가 쓰기가능 마운트에 바이너리를 *심어야만* 한다. 즉 distroless(셸 제거) + zero-exec(심은 것도 kill)는 *2중* 방어지 같은 방어가 아니다. 라이브 caveat: `k8s/tracingpolicy.yaml` 헤더 / [ADR 0001](../../docs/decisions/0001-data-tier-zero-exec.md).</details>
7. <details><summary>execve는 SIGKILL이 prevention인데, 같은 Tetragon으로 파일 write를 SIGKILL하면 그것도 prevention인가?</summary>아니다 — kill *타이밍*이 다르다. execve+Sigkill은 *이미지 로드 이전*에 죽여 셸이 첫 명령조차 못 한다(prevention-grade). 하지만 write() 같은 I/O syscall은 Tetragon 문서가 명시하듯 *SIGKILL이 바이트 미기록을 보장하지 않는다* — 프로세스가 동기적으로 죽어도 커널이 이미 일부 I/O를 수행했을 수 있다(detection-point ≠ prevention-point). I/O를 prevention-grade로 하려면 Sigkill+**Override**(syscall 자체에 에러 반환)가 필요하다 — "Tetragon=차단"이 아니라 *어느 syscall이냐*가 prevention/detection을 가른다. 배경: [`docs/04-runtime.md`](../../docs/04-runtime.md) "kill 타이밍".</details>

> **현실 연결:** Log4Shell(CVE-2021-44228)의 전형적 체인은 JNDI로 코드 실행 → 곧바로 reverse
> shell(`bash -i`/nc)로 발판 확보였다. data tier에서 셸 exec을 커널에서 끊으면 *그 다음 손동작*을
> 차단한다(RCE 자체는 앞 계층 문제). 컨테이너를 최소 표면으로 운영(불필요한 셸·도구 제거)하라는
> NIST SP 800-190의 권고를 distroless + zero-exec가 구현한다.

## 더 깊이 (1차 출처)

- Tetragon TracingPolicy / kprobe·selectors 문법: <https://tetragon.io/docs/concepts/tracing-policy/>
- selector operator(Postfix/Equal/Prefix…)·matchArgs·matchActions: <https://tetragon.io/docs/concepts/tracing-policy/selectors/>
- enforcement(Sigkill/Override)와 kill 타이밍 caveat: <https://tetragon.io/docs/concepts/enforcement/>
- 이 repo의 강건화 결정: [ADR 0001](../../docs/decisions/0001-data-tier-zero-exec.md) · 잔여위험: [`THREAT_MODEL.md`](../../THREAT_MODEL.md)
- 컨테이너 최소화 표준: NIST SP 800-190 (Application Container Security Guide)

## 졸업 기준

- [ ] `grade.sh` **id=0 + sh=137 둘 다 PASS**
- [ ] "둘 다 요구"가 왜 false-pass를 막는지 설명할 수 있다
- [ ] Postfix vs Equal, 과잉 kill이 왜 결함인지 안다
- [ ] 구두 문답을 펼치기 전에 답할 수 있다 (특히 Q5 matchBinaries=호출자, Q7 execve=prevention vs write=detection)
- [ ] 이 룰이 *못* 죽이는 것(renamed-shell `/tmp/x sh`·execveat·fd-exec)을 말할 수 있다 → 강건한 답은 zero-exec(execve+execveat)/distroless(matchBinaries 아님 — 호출자 매칭), [M8](../m8/README.md)에서 라이브 검증
- [ ] `labs/m4/tracingpolicy.solution.yaml`과 비교 (그리고 **실제 shipped 기본은 zero-exec** `k8s/tracingpolicy.yaml`임을 안다 — 이 선택적 룰은 그 출발점)

다음: **M5 — 데이터 암호화 (run & interpret)** (같은 세션에서).
