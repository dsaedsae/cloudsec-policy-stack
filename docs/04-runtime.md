# Lab 3 — 런타임 탐지 + 차단 (Tetragon / eBPF)

> **직접 해보기 (재구현 트랙):** TracingPolicy를 직접 작성하라 → **[M4 · Tetragon 런타임](../labs/m4/README.md)** (선택적 kill, 클러스터 필요).

**목표:** 지금까지의 계층은 요청 *전/시점*에 작동한다. 이 계층은 워크로드가 *침해된 후*를 감시한다 —
네트워크 정책과 인가가 덮지 못하는 빈틈이다.

**필요:** [Lab 2](03-network-and-authz.md)의 클러스터(`up.sh`가 Tetragon 설치).

## 차단(Prevention): db 파드의 *모든* exec는 커널에서 죽는다 (zero-exec)

```bash
DBPOD=$(kubectl -n shop get pod -l tier=data -o jsonpath='{.items[0].metadata.name}')
kubectl -n shop exec "$DBPOD" -- sh -c "echo pwned"   # -> exit 137 (SIGKILL)
kubectl -n shop exec "$DBPOD" -- id                   # -> exit 137 (SIGKILL — id도 죽는다)
```

기대 결과: **둘 다** `command terminated with exit code 137` (137 = SIGKILL, by Tetragon).

shipped 룰은 `k8s/tracingpolicy.yaml`의 **zero-exec** `TracingPolicy`다: `tier: data` 파드에서 발생하는
**모든 exec**(`sys_execve` + `sys_execveat`)를 이름·arg0 무관하게 `Sigkill`한다. 데이터스토어는 정당하게
어떤 것도 exec할 일이 없으므로(프로브는 httpGet), 셸 이름을 일일이 쫓는 대신 *전부* 금지한다.

> **왜 셸-이름만이 아니라 전부?** 셸 *이름*만 죽이는 선택적 룰(arg0-Postfix)은 `cp /bin/busybox /tmp/x &&
> /tmp/x sh`(이름 변경)·`execveat`·fd-exec로 우회되고, `matchBinaries`도 *호출자*를 매칭해 틀린 도구다.
> 그 선택적 룰은 이제 **[M4](../labs/m4/README.md) 랩의 학습용 프리미티브**(selector 문법을 익힌다)이고,
> 그 우회를 라이브로 측정해 zero-exec로 강건화한 기록이 **[M8](../labs/m8/README.md)** +
> [ADR 0001](decisions/0001-data-tier-zero-exec.md)다.

## 탐지(Detection): 모든 프로세스 exec이 관측된다

```bash
# 뭔가 실행시킨 뒤, Tetragon의 이벤트 스트림을 읽는다:
kubectl -n shop exec "$DBPOD" -- id 2>/dev/null || true
kubectl -n kube-system logs ds/tetragon -c export-stdout --tail=200 | grep process_exec
```

각 exec의 `binary`·`arguments`·`pod`·프로세스 계보를 볼 수 있다 — 무엇이 어디서 실행됐는지의
포렌식 추적이다.

## 내 것으로 만들기

런타임 룰을 *직접 짜는* 트랙은 **[M4](../labs/m4/README.md)** 다 — 선택적 셸-kill을 빈 골격에서 작성하고
(`matchArgs` Postfix·`Sigkill`), 그게 *왜* 우회되는지 깨달은 뒤 **[M8](../labs/m8/README.md)** 에서 zero-exec
와의 차이를 라이브로 측정한다(`verify-runtime-scope`: 선택적은 `id` 생존, zero-exec는 `id`까지 kill). 손으로
빌드하며 "왜 데이터 티어는 *전부 금지*가 맞나"를 체득하는 경로다.

## 정직한 한계 — syscall 표면의 회피 클래스 (io_uring)

shipped 룰은 **zero-exec**(`sys_execve`+`sys_execveat` 전부 Sigkill, 이름·arg0 무관)라 renamed-binary·
execveat·fd-exec 우회를 닫는다 — `matchBinaries`는 *호출자*를 매칭해 틀린 도구다(위 "왜 전부?" + M8 라이브
검증; allowlist가 필요하면 BPF-LSM). **그래도** 런타임 탐지가 거는 **syscall 표면 자체**엔 arg0 우회와는
다른 차원의 회피 클래스가 있다. 배경: `THREAT_MODEL.md`.
한편 `execve`는 io_uring 오피코드가 없어 io_uring이 *exec 룰*을 우회하진 않지만, **파일/네트워크 같은 광역
syscall-kprobe 룰은 `io_uring`으로 우회될 수 있다** —
공격자가 read/write/connect 대신 io_uring 제출큐로 I/O를 수행하면 감시 중인 syscall이 발동하지
않는다(ARMO "Curing" PoC, 2025). 더 견고한 답은 syscall 표면이 아니라 **LSM 레이어(BPF-LSM / KRSI)**
에 거는 것 — 호출 방식과 무관하게 커널 *연산* 자체를 관측한다(정확히는 Tetragon의 *기본 syscall 정책*이
io_uring에 blind이지 Tetragon 자체가 아니다 — LSM 훅은 본다). 이 데모의 단일 `execve` 룰은 *의도적으로 좁은*
예시이지 일반 런타임-회피 방어가 아니다(잔여위험 — `THREAT_MODEL.md`).

**kill 타이밍 — execve엔 prevention, I/O엔 detection:** execve+Sigkill은 *이미지 load 이전*에 죽여 셸이 첫
명령도 못 한다(prevention-grade). 반면 Tetragon 문서는 *write() 중 SIGKILL이 바이트 미기록을 보장하지 않는다*
고 명시 — 프로세스는 동기적으로 죽어도 커널이 이미 I/O를 했을 수 있다(detection-point ≠ prevention-point).
I/O 룰을 prevention-grade로 하려면 Sigkill+**Override**가 필요하다. **[Lab M8](../labs/m8/README.md)** 은 *범위*를
라이브 측정(`scripts/verify-runtime-scope.ps1`: 선택적 id=0 → zero-exec id=137 델타)하고, I/O write-window는 *탐구*한다(문서화 caveat
+ SKIP-prone 학습 정책, 여기서 미측정); execve pre-image-load 타이밍은 문서화된 kprobe 의미론이다. ED1은
VERIFIED 그대로이고 M8은 그 *의미를 날카롭게* 한다.

---

이것으로 전체 스택이 완성된다: **프로비저닝(Terraform) → 네트워크 L3/L7 + egress(Cilium)
→ 앱 인가(Cedar) → 런타임(Tetragon)**, 각각 시행되고 검증된다. [학습 경로](README.md)로 돌아가기.
