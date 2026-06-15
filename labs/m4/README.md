# M4 — 런타임: Tetragon eBPF로 셸 실행 차단

<div class="lab-pills">
<span class="lab-progress">모듈 5 / 7</span> · <span class="lab-badge">스택 Tetragon eBPF</span> · <span class="lab-badge">소요 ~20–35m</span> · <span class="lab-badge cluster">클러스터 필요 · RAM ~6–8GB</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

**미션:** data tier 파드에서 셸(`/bin/sh` 류) 실행을 커널에서 즉시 SIGKILL하되, 정상 바이너리는
건드리지 않는 **선택적** TracingPolicy를 작성한다. DB 컨테이너가 셸을 띄울 일은 없다 — 그건 침입이다.

> 🎯 **학습 성과 (면접에서 말할 수 있는 것):** 셸 exec만 *선택적으로* SIGKILL하는 TracingPolicy를 작성하고, 이 룰이 *못* 막는 것(나이브 직접 execve만 잡음 — renamed/execveat 우회, M8에서 측정)을 정직히 말할 수 있다. → [캡스톤 M4](../capstone.md)

**클러스터 필요.** **편집 파일:** `labs/m4/tracingpolicy.yaml` (selectors).

> 선행: M2/M3 권장(같은 세션). 배경: [`docs/04-runtime.md`](../../docs/04-runtime.md).

> **selector 문법이 막막하면 → [배우기 모드: LEARN.md](LEARN.md).** kprobe 한 개(matchArgs Postfix + Sigkill)를 주석과 함께 읽고 → operator를 빈칸으로 채우고 → 나머지는 직접. 이 룰이 못 막는 우회까지 짚어준다.

---

## 왜 런타임 통제인가

네트워크 정책·Cedar·admission은 *요청 전/시점*에 막는다. 하지만 워크로드가 *이미 털린 후*엔
아무것도 안 본다. Tetragon(eBPF)은 런타임을 *지속* 감시한다 — data tier에서 셸 exec이 보이면
침입으로 간주하고 커널에서 죽인다.

> **정직한 범위(과장 금지):** 이 룰은 *셸 **이름**의 직접 execve*만 죽인다(arg0 Postfix 매칭). 셸을
> **다른 이름으로** 띄우면 우회된다(renamed-binary/execveat/fd-exec — Q4). 즉 "셸을 못 띄운다"가
> 아니라 "나이브 직접 셸-명 execve를 죽인다"가 정확한 주장. 그 경계를 *라이브로 측정*하는 게
> **[M8](../m8/README.md)**(심화)이고, 강건한 답은 **zero-exec**(execve+execveat 전부 Sigkill)·distroless 이미지다 — matchBinaries는 *호출자*를 매칭해 아님(M8 라이브 검증; [THREAT_MODEL](../../THREAT_MODEL.md) 잔여위험).

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

- `index: 0` = execve의 첫 인자(실행 파일 경로).
- `operator: "Postfix"` = 경로가 그 값으로 *끝나면* 매칭. `/bin/sh`·`/usr/bin/bash` 등 접두가 달라도
  잡는다. `/usr/bin/id`는 목록에 없으니 안 잡힌다 → **선택적**.
- `action: Sigkill` = 커널에서 즉시 종료(rc=137).

```bash
bash labs/m4/grade.sh        # id=0 PASS + sh=137 PASS → M4 GRADUATED. 채점 후 canonical 복원.
```

## Step 2 — break-and-fix (예측 → 확인)

1. `values`를 `["/sh"]` 하나만 남긴다 → `sh`는? `bash`는? (이 데모 이미지엔 어떤 셸이 있나 — busybox 기반이면?)
2. `operator`를 `"Postfix"`에서 `"Equal"`로 바꾼다 → `/bin/sh`로 실행되면 매칭되나? (Equal은 정확히 그 문자열)
3. `values`에 `/id`를 추가한다 → `id` 케이스는? (이제 과잉 kill — 정상 바이너리를 죽인다)

<details><summary>2번 후 열 것</summary>Equal은 인자가 정확히 "/sh"여야 매칭. 실제 exec 경로는 "/bin/sh"라 매칭 안 됨 → 셸이 살아남아 FAIL. 그래서 경로 접두를 모르는 상황엔 Postfix가 맞다. 통제는 *실제 관측되는 값*에 맞춰야 한다.</details>
<details><summary>3번이 가르치는 것</summary>과잉 차단도 결함이다 — 정상 운영(헬스체크가 id류를 쓸 수 있음)을 깨면 가용성 사고. 채점기가 "id는 살아야 PASS"를 요구하는 이유: 선택성이 핵심이지 "다 죽이기"가 아니다.</details>

## Step 3 — 구두 문답

1. <details><summary>왜 "셸이 죽었다"만으로는 부족하고 "id는 살았다"도 같이 봐야 하나?</summary>전부 죽이는 정책(또는 파드가 그냥 안 떠서 모든 exec 실패)도 "셸 죽음"을 만족한다. id가 rc=0으로 살아야 "셸만 골라 죽인다 + 파드는 건강하다"가 증명된다 — false-pass 방지(이 repo의 적대적 검증이 실제로 이 클래스의 false-pass를 잡았다).</details>
2. <details><summary>eBPF 런타임 통제가 admission/netpol과 다른 점은?</summary>admission/netpol은 생성/연결 시점의 *사전* 통제. Tetragon은 실행 중 syscall을 *지속* 관찰하는 사후 탐지·차단. 침해 후(post-exploit) 단계를 본다.</details>
3. <details><summary>Sigkill을 커널에서 하는 것과 사용자공간 에이전트가 죽이는 것의 차이는?</summary>eBPF는 커널에서 syscall 시점에 즉시 죽여 *타이밍 레이스*엔 강하다. 단 "어느 syscall/이름을 후킹하느냐"는 별개 문제다 — arg0-Postfix는 renamed-binary로 쉽게 우회된다(Q4). 사용자공간 에이전트는 폴링/지연이 있어 빠른 공격이 빠져나갈 수 있다.</details>
4. <details><summary>이 통제의 한계(THREAT_MODEL 기준)는?</summary>data tier에만, **셸 *이름*의 직접 execve**만 본다(arg0 Postfix). 그래서 셸을 *다른 이름으로* 띄우면 우회된다: 쓰기가능 /tmp + busybox로 `cp /bin/busybox /tmp/x && /tmp/x sh`, execveat(별도 syscall, 미후킹), fd-exec(arg0=/proc/self/fd/N). 즉 ED1은 "*나이브* 직접 셸-명 execve를 죽인다"이지 "셸을 못 띄운다"가 아니다 — 강건한 답은 matchBinaries/sched_process_exec/LSM. 그밖에 nc/python로 셸 없이 하는 짓, 다른 tier, 노드 루트도 범위 밖(평가에서 ED2/ED3는 CONFIGURED/NOT_COVERED). 측정: [M8](../m8/README.md).</details>

## 졸업 기준

- [ ] `grade.sh` **id=0 + sh=137 둘 다 PASS**
- [ ] "둘 다 요구"가 왜 false-pass를 막는지 설명할 수 있다
- [ ] Postfix vs Equal, 과잉 kill이 왜 결함인지 안다
- [ ] 구두 문답 4개 답안 없이
- [ ] 이 룰이 *못* 죽이는 것(renamed-shell `/tmp/x sh`·execveat·fd-exec)을 말할 수 있다 → 강건한 답은 zero-exec(execve+execveat)/distroless(matchBinaries 아님 — 호출자 매칭), [M8](../m8/README.md)에서 라이브 검증
- [ ] `k8s/tracingpolicy.yaml`과 비교

다음: **M5 — 데이터 암호화 (run & interpret)** (같은 세션에서).
