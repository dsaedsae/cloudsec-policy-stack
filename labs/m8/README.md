# M8 — eBPF kill의 정직한 경계: detection ≠ prevention

<div class="lab-pills">
<span class="lab-progress">심화 / 측정</span> · <span class="lab-badge">스택 Tetragon</span> · <span class="lab-badge">소요 ~30–45m</span> · <span class="lab-badge cluster">클러스터 필요 · RAM ~6–8GB</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

> **선행:** M4(선택적 shell-kill을 *직접 만든다*). M8은 그 통제의 **한계를 측정**한다 — 과장도 과소도 없이.
> **준비:** `scripts/up.ps1`(Tetragon 포함) + Git Bash/PowerShell. 클러스터 없으면 SKIP(FAIL 아님).

**미션:** M4의 `block-shell-in-data-tier`(execve kprobe → Sigkill, `tier: data`)는 셸 실행을 **실제로 막는다**.
M8은 묻는다 — *어디까지* 막나? 언제 막나? 못 막는 건 뭔가? 그걸 **라이브로 측정**해 통제를 정확히 라벨한다.
**메트릭은 변하지 않는다(72% 그대로):** M8은 통제를 더하거나 빼는 게 아니라 *기존 통제의 가장자리를 측정*한다 —
그걸 명시하는 것 자체가 정직한 결과다. ED1("runtime shell-exec kill")은 **VERIFIED 그대로**.

> 🎯 **학습 성과:** 런타임 kill의 정직한 경계를 *라이브로 측정*해 설명할 수 있다 — detection≠prevention, execve(pre-image-load) vs I/O(write window), 그리고 io_uring에 blind한 건 *기본 syscall 정책*이고 LSM/KRSI가 해법이라는 것.

빠른 실행: `.venv` 불필요, 클러스터만.
```powershell
.\scripts\verify-runtime-scope.ps1     # Station A + D 라이브 (sh=137/id=0, cat 생존) + B/C 정직 노트
```

---

## Station A — 선택적 in-kernel kill은 진짜다 (그리고 pre-image-load)

```
sh -c 'echo x'   -> rc=137 (SIGKILL)      id   -> rc=0 (실행됨)
```
execve kprobe가 셸 바이너리(`/sh,/bash,/dash,/ash,/busybox` postfix)에 매칭되면 커널에서 동기적으로 SIGKILL.
여기서 **라이브로 측정한 건 rc(sh=137 / id=0)** 다. 그 위에서 — execve+Sigkill은 **image load *이전*에 죽는다**
("셸이 초기화되기 전")는 것은 **문서화된 Tetragon/Cilium kprobe 의미론**이다(여기서 image-load 타이밍을 직접
측정하진 않았다). 그래서 셸이 자기 코드를 한 줄도 실행하지 못하고, 이것이 execve+Sigkill이 *prevention-grade*인 이유.

> ⚠️ **주장하지 말 것:** wall-clock `kubectl exec`→137 시간으로 "kill 지연 N ms"를 말하지 마라 — 그건 API서버/exec
> 스트림 RTT(수십~수백 ms)이지 sub-ms 커널 kill이 아니다. 숫자를 인용하지 않는다.

## Station B — execve marker 테스트: 돌려보고 *실제* 결과를 보고하라 (예측 금지)

셸이 첫 동작으로 marker 파일을 쓰게 한 뒤 비셸 바이너리로 읽어본다. db 파드는 `readOnlyRootFilesystem`이지만
**루트 fs만 읽기전용**이고 `/tmp`·`/var/cache/nginx`·`/var/run`엔 **쓰기가능 emptyDir가 마운트**돼 있다(`k8s/app.yaml`)
— 즉 셸이 쓸 곳은 *있다*. 그런데도 marker가 안 남는 이유는 **execve+Sigkill이 pre-image-load(문서화 의미론)** 라
셸이 *첫 명령에 도달하기도 전에* 죽기 때문이다. **그래서 "셸이 윈도우 동안 실행됐다"는 측정 가능한 윈도우가
execve엔 존재하지 않는다**(이걸 윈도우라 주장하면 gap 과장 + ED1 과소). 실제 윈도우는 I/O(write)에 있다 → Station C.

## Station C — 진짜 윈도우는 I/O(write)에 있다 (Tetragon 자체 문서 caveat)

Tetragon 문서: *"a SIGKILL sent in a write() system call does not guarantee that the data will not be written."*
즉 write()류 syscall에선 **프로세스는 동기적으로 죽어도 커널이 이미 연산을 수행했을 수 있다** —
*synchronous-process-kill ≠ pre-operation*. 이것이 정직한 "detection-point ≠ prevention-point" 윈도우다.

탐구(측정-전용, 프로덕션 통제 아님): `labs/m8/tracingpolicy-write-window.yaml`(sys_write+Sigkill, **전용 라벨**
`m8-write-window=true`인 throwaway 파드만 — 실행 중 db는 절대 건드리지 않음)을 적용 → 쓰기가능 emptyDir에 한 번
write → SIGKILL → 정책 제거 후 읽어 `bytes>0` 확인. **kind/LinuxKit에선 kprobe가 안 떠 SKIP일 수 있다**(tetragon#4883) —
그럼 SKIP을 정직히 보고하라(FAIL 아님). kprobe 룰을 *prevention-grade*로 만들려면 **Sigkill + Override** 조합이 필요;
우리 셸 룰은 Sigkill-only(=execve엔 prevention, I/O엔 detection)다.

## Station D — 매치 범위: execve-of-shell-names 뿐 (커버리지 갭)

```
id -> rc=0 (비셸 exec 생존)        cat /etc/passwd -> rc=0 (파일 읽기 생존)
```
룰의 범위는 *셸 **이름**의 execve*다(arg0 postfix 매칭). 비셸 바이너리·**비-execve I/O(파일 읽기)** 뿐 아니라
— **더 중요하게** — 셸을 *다른 이름으로* 실행하면 우회된다: `/tmp`에 쓰기가능 emptyDir + busybox가 있어
`cp /bin/busybox /tmp/x && /tmp/x sh`는 arg0=`/tmp/x`라 postfix 미매칭 → kill 안 됨. **execveat**(별도 syscall,
미후킹)·**fd-exec**(arg0=`/proc/self/fd/N`)도 우회한다. 즉 ED1은 "*나이브* 직접 셸 execve를 죽인다"이지 "셸을
못 띄운다"가 아니다(전문가 리뷰가 확인) → ED3 NOT_COVERED 확인. **robust 답:** 해소된 바이너리 매칭
(`matchBinaries` / `sched_process_exec` 트레이스포인트 / LSM `security_bprm_creds_for_exec`) 또는 data-tier exec
allowlist. 별개로, 같은 파일 읽기를 **io_uring**
(`IORING_OP_READ`)으로 하면 Tetragon의 *기본 syscall 정책*엔 안 보인다(ARMO "Curing", 2025) — **단 LSM/KRSI 훅은
본다.** "Tetragon이 우회됐다"가 아니라 "기본 syscall 정책이 io_uring에 blind, LSM 훅이 해법"이 정확한 표현.
(셸 룰 자체는 io_uring과 무관 — io_uring엔 execve 오피코드가 없다. 실제 익스플로잇은 만들지 않는다.)

---

## 졸업 기준
- [ ] **A:** `sh=137 / id=0` 직접 확인 + "execve는 왜 pre-image-load인가" 설명
- [ ] **B:** 실제 결과 보고(예상: marker 없음/쓰기 불가) + readOnlyRootFS 이중차단 이해
- [ ] **C:** write-window를 측정(`bytes>0`) **또는** 정직한 SKIP + "synchronous-process-kill ≠ pre-operation"과 Sigkill vs +Override 설명
- [ ] **D:** 비셸 exec + 파일 읽기 생존 확인 + io_uring/BPF-LSM(KRSI)을 robust 훅으로 지목
- [ ] 헤드라인이 **왜 안 변하나**(72%) 설명 — M8은 통제 가감이 아니라 가장자리 측정

## 구두 문답
1. <details><summary>execve+Sigkill은 prevention-grade인데 write+Sigkill은 왜 detection-grade?</summary>execve는 새 이미지 load *이전*에 죽어 셸 코드가 실행되지 않음(pre-image-load). write()는 프로세스를 동기적으로 죽여도 커널이 이미 바이트를 기록했을 수 있음. prevention-grade로 만들려면 Sigkill+Override.</details>
2. <details><summary>여기서 커버리지 %를 내리는 게 왜 틀린 선택인가?</summary>아무것도 반증되지 않았다(ED1의 셸-kill은 여전히 참). M8은 통제를 더/덜 만들지 않고 *경계를 측정*한다. 내리면 false-underclaim, 올리면 inflation. 안 변하는 게 정직.</details>
3. <details><summary>io_uring 클래스를 닫는 훅은? 왜?</summary>BPF-LSM/KRSI — syscall 표면이 아니라 커널 *연산*을 관측하므로 호출 방식(syscall vs io_uring)과 무관. Tetragon은 LSM 훅도 지원하므로 io_uring을 "볼 수 있다"; blind한 건 *기본 syscall 정책*일 뿐.</details>
4. <details><summary>Tetragon은 io_uring에 "blind"한가? 정확히.</summary>아니다(전부는). ARMO는 "기본 syscall 후킹 기반 탐지가 blind"라 했고, Tetragon은 kprobe+LSM 훅도 지원해 io_uring을 잡을 수 있다. "기본 정책 blind / LSM이 해법"이 정확.</details>

> 정직 메모: **라이브 측정은 rc뿐** — A(sh=137/id=0)·D(cat=0)(`verify-runtime-scope.ps1`). A의 *pre-image-load
> 타이밍*은 문서화 의미론(여기서 미측정). B는 execve가 pre-image-load라 윈도우 없음(쓰기가능 emptyDir는 있으니
> "쓸 곳이 없어서"가 아니다). C(write-window)는 Tetragon 문서화 caveat이며 kind에선 SKIP일 수 있다(미측정).
> M8은 ED1을 바꾸지 않고 그 의미를 *날카롭게* 한다. 배경: [04-runtime](../../docs/04-runtime.md) · [THREAT_MODEL](../../THREAT_MODEL.md).
