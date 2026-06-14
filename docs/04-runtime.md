# Lab 3 — 런타임 탐지 + 차단 (Tetragon / eBPF)

> 💡 **직접 해보기 (재구현 트랙):** TracingPolicy를 직접 작성하라 → **[M4 · Tetragon 런타임](../labs/m4/README.md)** (선택적 kill, 클러스터 필요).

**목표:** 지금까지의 계층은 요청 *전/시점*에 작동한다. 이 계층은 워크로드가 *침해된 후*를 감시한다 —
네트워크 정책과 인가가 덮지 못하는 빈틈이다.

**필요:** [Lab 2](03-network-and-authz.md)의 클러스터(`up.sh`가 Tetragon 설치).

## 차단(Prevention): db 파드의 셸은 커널에서 죽는다

```bash
DBPOD=$(kubectl -n shop get pod -l tier=data -o jsonpath='{.items[0].metadata.name}')
kubectl -n shop exec "$DBPOD" -- sh -c "echo pwned"
```

기대 결과:

```
command terminated with exit code 137      # 137 = SIGKILL, by Tetragon
```

하지만 **비셸(non-shell)** exec는 여전히 동작한다(룰이 정밀하고, 파드는 건강하게 유지):

```bash
kubectl -n shop exec "$DBPOD" -- id        # uid=101(nginx) ...  — 정상 실행
```

룰은 `k8s/tracingpolicy.yaml`에 있다: `tier: data` 파드에서 셸(`/sh`, `/bash`, `/dash`, `/ash`,
`/busybox`)의 `execve`를 `Sigkill`하는 `TracingPolicy`다. 데이터베이스 컨테이너는 정당하게 셸을 띄울
일이 결코 없으므로, 그 시도는 침입으로 간주된다.

## 탐지(Detection): 모든 프로세스 exec이 관측된다

```bash
# 뭔가 실행시킨 뒤, Tetragon의 이벤트 스트림을 읽는다:
kubectl -n shop exec "$DBPOD" -- id 2>/dev/null || true
kubectl -n kube-system logs ds/tetragon -c export-stdout --tail=200 | grep process_exec
```

각 exec의 `binary`·`arguments`·`pod`·프로세스 계보를 볼 수 있다 — 무엇이 어디서 실행됐는지의
포렌식 추적이다.

## 내 것으로 만들기

`k8s/tracingpolicy.yaml`의 `values:` 목록에 `"/python"`(또는 `/nc`, `/curl`)을 추가하고
`kubectl apply` 한 뒤 db 파드에서 그 바이너리를 exec해 보라 — 이제 그것도 죽는다. 방금 런타임-보안
룰을 직접 작성한 것이다.

## 정직한 한계 — syscall 표면의 회피 클래스 (io_uring)

이 룰은 `sys_execve` kprobe로 **arg0(파일명) postfix**를 본다. ⚠️ **이 룰은 견고한 셸 차단이 아니다(나이브
직접 셸 execve만 죽인다):** `cp /bin/busybox /tmp/x && /tmp/x sh`(이름 변경 → arg0 미매칭)·`execveat`(미후킹
별도 syscall)·fd-exec로 우회된다 — robust 답은 **zero-exec**(`sys_execve`+`sys_execveat`를 모두 후킹해 전부 Sigkill)·**distroless** 이미지다(`matchBinaries`는 *호출자* 바이너리를 매칭해 아님 — M8에서 라이브 검증; allowlist가 필요하면 BPF-LSM). 단순 `cp busybox /tmp/x && /tmp/x sh`는 busybox arg0-dispatch로 셸이 안 됨(실 잔여는 execveat/fd-exec/argv0-spoof). 배경: `THREAT_MODEL.md`.
한편 `execve`는 io_uring 오피코드가 없어 io_uring이 *이 룰*을 우회하진 않지만, **파일/네트워크 같은 광역
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
라이브 측정(`scripts/verify-runtime-scope.ps1`: sh=137/id=0/cat=0)하고, I/O write-window는 *탐구*한다(문서화 caveat
+ SKIP-prone 학습 정책, 여기서 미측정); execve pre-image-load 타이밍은 문서화된 kprobe 의미론이다. ED1은
VERIFIED 그대로이고 M8은 그 *의미를 날카롭게* 한다.

---

이것으로 전체 스택이 완성된다: **프로비저닝(Terraform) → 네트워크 L3/L7 + egress(Cilium)
→ 앱 인가(Cedar) → 런타임(Tetragon)**, 각각 시행되고 검증된다. [학습 경로](README.md)로 돌아가기.
