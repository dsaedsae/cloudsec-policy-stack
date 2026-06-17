# M8 — eBPF kill의 정직한 경계: detection ≠ prevention

<div class="lab-pills">
<span class="lab-progress">심화 / 측정</span> · <span class="lab-badge">스택 Tetragon</span> · <span class="lab-badge">소요 ~30–45m</span> · <span class="lab-badge cluster">클러스터 필요 · RAM ~6–8GB</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

> **선행:** M4(선택적 shell-kill을 *직접 만든다*). M8은 그 통제의 **한계를 측정**한다 — 과장도 과소도 없이.
> **준비:** `scripts/up.ps1`(Tetragon 포함) + Git Bash/PowerShell. 클러스터 없으면 SKIP(FAIL 아님).

**미션:** M4의 `block-shell-in-data-tier`(선택적 arg0-Postfix 셸-kill)는 셸-*이름*의 execve만 막는 **학습용
프리미티브**다. M8은 그 경계를 **라이브로 측정**한다 — 어디까지 막나? 못 막는 건 뭔가? — 그리고 그 한계가
바로 **shipped 기본이 zero-exec**(`sys_execve`+`sys_execveat` 전부 Sigkill, `k8s/tracingpolicy.yaml`)인 이유임을
보인다. `verify-runtime-scope`는 두 룰을 차례로 적용해 *델타*를 측정한다: 선택적은 `id`를 살리고(갭), zero-exec는
그 `id`까지 죽인다(이름 무관) — 그 뒤 shipped zero-exec로 복원한다.
**메트릭은 변하지 않는다(77.5% 그대로):** ED1은 **VERIFIED 그대로** — M8/[ADR 0001](../../docs/decisions/0001-data-tier-zero-exec.md)은
통제를 더/덜 만든 게 아니라 *증거를 선택적→zero-exec로 정직하게 진화*시키고 기본으로 승격했을 뿐(개수 불변).

> **학습 성과:** 런타임 kill의 정직한 경계를 *라이브로 측정*해 설명할 수 있다 — detection≠prevention, execve(pre-image-load) vs I/O(write window), 그리고 io_uring에 blind한 건 *기본 syscall 정책*이고 LSM/KRSI가 해법이라는 것.

빠른 실행: `.venv` 불필요, 클러스터만. (런닝 db의 TracingPolicy를 잠깐 교체했다가 shipped zero-exec로 복원한다.)
```powershell
.\scripts\verify-runtime-scope.ps1     # Phase1 선택적(id=0/sh=137/cat=0) → Phase2 zero-exec(id=137/sh=137) → 복원
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

> **Phase 1 vs Phase 2 (델타):** 위 `id→0`은 *선택적 룰(M4 프리미티브)* 적용 상태(`verify-runtime-scope` Phase 1)다
> — 셸-이름만 죽이니 `id`는 산다(이게 **갭**). Phase 2는 **shipped zero-exec**를 적용해 그 `id`까지 `rc=137`로 죽인다
> (이름·arg0 무관, execveat 포함). "선택적은 진짜지만 부분적, zero-exec가 그 갭을 닫는 shipped 기본"이 한 줄 요약.

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
못 띄운다"가 아니다(전문가 리뷰가 확인) → ED3 NOT_COVERED 확인. **robust 답(이 랩에서 라이브 검증):** matchBinaries는 *호출자* 바이너리를 매칭하는 **틀린 도구**다(`NotIn [/usr/sbin/nginx]`가 `nginx -v`를 죽이고 nginx 자식인 in-RCE 셸은 놓침). 검증된 답은 **zero-exec** — `sys_execve`+`sys_execveat`를 모두 후킹해 data-tier의 *모든* exec를 Sigkill([`tracingpolicy-data-tier-no-exec.yaml`](tracingpolicy-data-tier-no-exec.yaml): id/sh/renamed-copy/busybox 전부 137, nginx 유지; arg0 무관·execveat 포함). caveat: restart-tolerance는 Tetragon **부착-창** 때문이지 이미지 덕이 아니다 — alpine·distroless(chainguard/nginx) 둘 다 정책 활성 t=0에서 Ready로 올라옴(라이브 검증; PID1 entrypoint execve가 창을 빠져나감·fragile·이미지 무관). **distroless의 진짜 이점은 *이미지층***: chainguard/nginx엔 `/bin/sh`·busybox가 아예 없다(검증 — 정책 이전에 "no such file") → 이미지가 셸을 없애고 런타임 룰이 *주입된* 바이너리를 죽이는 2중 방어. allowlist가 필요하면 **BPF-LSM**. 또한 단순 `cp busybox /tmp/x && /tmp/x sh`는 busybox arg0-dispatch로 셸이 안 됨(실 잔여는 execveat/fd-exec/argv0-spoof). 별개로, 같은 파일 읽기를 **io_uring**
(`IORING_OP_READ`)으로 하면 Tetragon의 *기본 syscall 정책*엔 안 보인다(ARMO "Curing", 2025) — **단 LSM/KRSI 훅은
본다.** "Tetragon이 우회됐다"가 아니라 "기본 syscall 정책이 io_uring에 blind, LSM 훅이 해법"이 정확한 표현.
(셸 룰 자체는 io_uring과 무관 — io_uring엔 execve 오피코드가 없다. 실제 익스플로잇은 만들지 않는다.)

---

## 룰 한 줄씩 읽기 — selective(M4) vs shipped zero-exec

두 룰이 *왜* 다른 결과를 내는지는 YAML 8줄 차이에 다 있다. 직접 대조하라.

**Selective(M4 프리미티브, `labs/m4/tracingpolicy.solution.yaml`):**
```yaml
  kprobes:
    - call: "sys_execve"        # ① execve syscall *하나*만 후킹 (execveat 미후킹 → 갭)
      syscall: true
      args:
        - index: 0
          type: "string"        # ② arg0(실행파일 경로)를 문자열로 읽음 — 이게 우회의 표면
      selectors:
        - matchArgs:
            - index: 0
              operator: "Postfix"          # ③ "경로가 ~로 끝나면" — 접두 무시 = arg0 스푸핑에 취약
              values: ["/sh","/bash","/dash","/ash","/busybox"]   # ④ 이름 화이트리스트 = whack-a-mole
          matchActions:
            - action: Sigkill    # ⑤ 매칭된 것만 죽임 → id는 ④에 없어 생존(=Phase1 갭)
```
①·②·③·④ 네 군데가 전부 **공격자가 통제하는 입력에 의존**한다: ①은 *다른 syscall*(execveat)로, ②③④는
*다른 arg0*(`/tmp/x sh`, `/proc/self/fd/N`)로 빠져나간다. selector가 정밀할수록 빠져나갈 틈이 늘어난다.

**Shipped zero-exec(`tracingpolicy-data-tier-no-exec.yaml` = `k8s/tracingpolicy.yaml` verbatim):**
```yaml
  podSelector:
    matchLabels:
      tier: data                # ⓐ "어디서": tier=data 라벨 파드 전부 (db). web/api는 무관 = ED3 NOT_COVERED
  kprobes:
    - call: "sys_execve"        # ⓑ
      syscall: true
      selectors:
        - matchActions:
            - action: Sigkill    # ⓒ args/matchArgs가 *없다* → 무조건 kill. 읽을 arg0가 없으니 스푸핑할 표면도 없다
    - call: "sys_execveat"      # ⓓ 두 번째 진입점도 후킹 → execveat 우회 닫힘
      syscall: true
      selectors:
        - matchActions:
            - action: Sigkill
```
selective가 "*무엇을* 죽일지 고르는" 룰이라면 zero-exec는 "데이터 티어에선 *exec라는 행위 자체*가 위반"이라는
룰이다 — ⓒ에서 `args`/`matchArgs`를 통째로 들어내 **매칭 표면을 0으로** 만든 게 핵심. 고를 게 없으면 속일 것도 없다.

> **왜 syscall이 둘인가 (ⓑ vs ⓓ):** `execve(path, argv, envp)`는 경로 문자열로 프로그램을 적재하고,
> `execveat(dirfd, path, argv, envp, flags)`는 **fd 기준 상대경로**로 적재한다(같은 image-load 동작, 다른 진입점).
> `execveat`는 `AT_EMPTY_PATH` 플래그로 *이미 열린 fd만으로* exec할 수 있어 fd-exec(`/proc/self/fd/N`)의 토대다.
> 커널 ABI상 둘은 **별개의 syscall 번호**라 `sys_execve` kprobe 하나는 `sys_execveat`를 절대 보지 못한다 — selective의
> ① 갭이 바로 이것. zero-exec는 두 진입점을 모두 후킹해 "어느 문으로 들어와도 exec면 죽는다"를 만든다. (fd-exec도
> 결국 execve(at) 경로를 지나가므로 ⓑ·ⓓ로 커버된다.)

(`matchBinaries`로 "`nginx`만 허용"하는 allowlist가 왜 거꾸로 동작하는지는 Station D + 구두문답 #5.)

---

## 심화 — 2중 방어: distroless 이미지 + zero-exec (라이브 검증)

zero-exec 룰(`tracingpolicy-data-tier-no-exec.yaml` = **shipped 기본** `k8s/tracingpolicy.yaml`)은 *런타임* 층이다. 그 위에 **이미지 층**을 더하면
— 데이터 티어 이미지를 **셸-free(distroless)** 로 — 진짜 defense-in-depth가 된다:

- **이미지 층:** distroless엔 `/bin/sh`·busybox가 *아예 없다*. 털린 컨테이너가 기댈 셸이 없다.
- **런타임 층:** 그래도 공격자가 쓰기가능 마운트에 바이너리를 *써넣고* 실행하면 zero-exec 룰이 죽인다.

```bash
# (kind+Tetragon 위에서) 런타임 층 + distroless db 적용
kubectl apply -f labs/m8/tracingpolicy-data-tier-no-exec.yaml
kubectl apply -f labs/m8/app-db-distroless.yaml
kubectl wait --for=condition=Ready pod/db-distroless --timeout=120s
# 이미지 층 증거 — 셸이 *이미지에 없다*(정책 이전에 "no such file"):
kubectl exec db-distroless -- sh -c echo          # -> exec: "sh": no such file  (Git Bash: bare `sh`, not `/bin/sh` — MSYS가 경로를 변조함)
# 런타임 층 증거 — 셸이 있는 alpine db에선 exec가 137로 죽는다 (db는 shop 네임스페이스):
kubectl exec db -n shop -- id                     # -> rc=137 (정책 kill)
```

**라이브 검증됨(kind+Tetragon 1.7.0):** distroless 파드는 zero-exec 정책이 t=0부터 켜진 상태로도 Ready로
기동했고, `/bin/sh`·busybox는 이미지에 부재했다.

**정직한 범위:** (1) **restart-tolerance는 distroless가 아니라 Tetragon 부착-창** 덕분이다 — alpine·distroless
둘 다 정책 활성 상태로 올라왔다(PID1 entrypoint execve가 창을 빠져나감; fragile·이미지 무관). (2) 이건 채점
스택의 *drop-in 교체가 아니다* — verify.sh 21/21과 api→db L7 홉은 alpine db(8080) 기준이고 chainguard/nginx의
포트·root-FS는 다를 수 있다(`app-db-distroless.yaml` 주석 참조). (3) allowlist(일부 exec 허용)가 필요하면 arg0
문자열이 아니라 **BPF-LSM**(`security_bprm_creds_for_exec`)의 바이너리 신원이 필요하다.

---

## 함정 — 실제로 부딪히는 것 (틀린 출력 → 원인 → 고침)

- **`exec: "sh": no such file`인데 정책이 죽인 줄 안다.** distroless 검증(`kubectl exec db-distroless -- sh -c echo`)
  에서 이 메시지가 뜨면 **rc=137이 아니라** "이미지에 셸이 없다"는 *이미지층* 증거다(정책이 부착되기도 전). 두 신호를
  구분하라: `137`=런타임 kill, `no such file`/`exit 127`=바이너리 부재. 같은 명령을 alpine `db`(`kubectl exec db -n shop -- id`)
  로 돌려 `137`을 보면 런타임층이 분리 증명된다. ("정책이 막았다"고 둘을 뭉뚱그리면 ED1 과장.)
- **Git Bash에서 `kubectl exec ... /bin/sh`가 이상한 경로로 변함.** MSYS가 `/bin/sh`를 Windows 경로로 변조한다.
  README가 `db-distroless`엔 *bare* `sh`(slash 없이)를 쓰는 이유다. 변조가 의심되면 `MSYS_NO_PATHCONV=1 kubectl exec ...`
  로 끄거나, slash 없는 토큰을 쓰라. (이건 정책 동작이 아니라 셸 변환 버그라 결과 해석을 오염시킨다.)
- **`verify-runtime-scope`를 `verify.sh`와 같이 돌렸다.** 스크립트가 런닝 db의 TracingPolicy를 *교체*했다가
  복원하므로, 21/21 채점과 동시에 돌리면 채점이 selective 룰 적용 순간을 보고 `id` 단언이 흔들린다. 두 스크립트 헤더가
  "Run standalone"이라 명시한다 — **순차로 돌려라.**
- **정책 apply 직후 곧장 probe → 기대와 다른 rc.** eBPF 프로그램이 커널에 attach되는 데 시간이 든다.
  `verify-runtime-scope`의 `only()`가 두 룰을 다 지우고 apply한 뒤 **`sleep 6`** 을 넣는 이유다. 수동으로 룰을 바꿔
  검증할 땐 곧장 `exec`하지 말고 attach를 기다려라(안 그러면 "닫혔어야 할 갭이 안 닫혔다"는 *허위* 결론).
- **selective Phase에서 `cat /etc/passwd`가 살아남는 걸 "버그"로 본다.** 그건 **설계대로**다 — selective는 셸-이름
  execve만 죽인다(D 스테이션의 커버리지 갭). `cat`은 비셸 바이너리라 Phase1에서 `rc=0`이 *정답*. 우회/갭은 결함이
  아니라 측정 대상이다.

## 변이 실험 — predict → break → confirm

룰을 깨 보면 어느 줄이 무엇을 지탱하는지 보인다. (런닝 db에 직접 적용하면 *복원*을 잊지 마라 — `verify-runtime-scope`
처럼 마지막엔 shipped zero-exec로 되돌린다.)

1. **zero-exec에서 `sys_execveat` 블록을 지운다(ⓓ 삭제).**
   - *예측:* `sh`·`id`는 여전히 죽지만 `execveat` 경로(fd-exec)는 빠져나간다.
   - *기전:* `sys_execve` kprobe는 다른 syscall 번호인 `sys_execveat`를 보지 못한다 → selective의 ① 갭이 부활.
   - *교훈:* zero-exec의 "robust"는 selector가 아니라 **두 진입점을 모두 후킹**한 데서 온다. 한쪽만 막으면
     이름 무관이어도 *문 하나가 열려* 있다.
2. **zero-exec ⓒ에 selective의 `args`+`matchArgs`(Postfix 셸-이름)를 다시 붙인다.**
   - *예측:* `verify-runtime-scope` Phase2의 `id (non-shell) -> 137` 단언이 **FAIL**(id가 살아남음)로 바뀐다.
   - *기전:* matchArgs를 다는 순간 "전부"가 다시 "고른 것만"이 된다 — 매칭 표면이 0에서 셸-이름으로 복귀.
   - *교훈:* Phase2 단언 `id=137`은 *바로 그 8줄(matchArgs 부재)* 을 지키는 회귀 테스트다.
3. **write-window 룰(`tracingpolicy-write-window.yaml`)의 라벨을 `m8-write-window`에서 `tier: data`로 바꾼다.**
   - *예측:* db(nginx)가 첫 `write()`에서 SIGKILL → CrashLoop. 파드가 Ready로 못 올라온다.
   - *기전:* `sys_write`+Sigkill은 *쓰는 모든 프로세스*를 죽인다 — nginx도 정상 운영 중 write한다.
   - *교훈:* write-window 룰이 **전용 throwaway 라벨**만 노리는 건 안전장치다(헤더 §"WHY A DEDICATED SELECTOR").
     I/O 룰은 execve 룰처럼 "데이터 티어 전부"로 켤 수 없다 — 정상 I/O와 악성 I/O가 같은 syscall이라서.

## 졸업 기준
- [ ] **A (델타):** Phase1 선택적 `sh=137 / id=0` → Phase2 zero-exec `id=137`(갭 닫힘) 직접 확인 + "execve는 왜 pre-image-load인가" 설명
- [ ] **심화(2중 방어):** distroless db + zero-exec를 적용해 *이미지층*(셸 부재)과 *런타임층*(exec kill)을 구분 설명 + restart-tolerance가 부착-창임을 안다
- [ ] **B:** 실제 결과 보고(예상: marker 없음/쓰기 불가) + readOnlyRootFS 이중차단 이해
- [ ] **C:** write-window를 측정(`bytes>0`) **또는** 정직한 SKIP + "synchronous-process-kill ≠ pre-operation"과 Sigkill vs +Override 설명
- [ ] **D:** 비셸 exec + 파일 읽기 생존 확인 + io_uring/BPF-LSM(KRSI)을 robust 훅으로 지목
- [ ] 헤드라인이 **왜 안 변하나**(77.5%) 설명 — M8은 통제 가감이 아니라 가장자리 측정

## 구두 문답
1. <details><summary>execve+Sigkill은 prevention-grade인데 write+Sigkill은 왜 detection-grade?</summary>execve는 새 이미지 load *이전*에 죽어 셸 코드가 실행되지 않음(pre-image-load). write()는 프로세스를 동기적으로 죽여도 커널이 이미 바이트를 기록했을 수 있음. prevention-grade로 만들려면 Sigkill+Override.</details>
2. <details><summary>여기서 커버리지 %를 내리는 게 왜 틀린 선택인가?</summary>아무것도 반증되지 않았다(ED1의 셸-kill은 여전히 참). M8은 통제를 더/덜 만들지 않고 *경계를 측정*한다. 내리면 false-underclaim, 올리면 inflation. 안 변하는 게 정직.</details>
3. <details><summary>io_uring 클래스를 닫는 훅은? 왜?</summary>BPF-LSM/KRSI — syscall 표면이 아니라 커널 *연산*을 관측하므로 호출 방식(syscall vs io_uring)과 무관. Tetragon은 LSM 훅도 지원하므로 io_uring을 "볼 수 있다"; blind한 건 *기본 syscall 정책*일 뿐.</details>
4. <details><summary>Tetragon은 io_uring에 "blind"한가? 정확히.</summary>아니다(전부는). ARMO는 "기본 syscall 후킹 기반 탐지가 blind"라 했고, Tetragon은 kprobe+LSM 훅도 지원해 io_uring을 잡을 수 있다. "기본 정책 blind / LSM이 해법"이 정확.</details>
5. <details><summary>matchBinaries로 "nginx만 허용"하는 allowlist를 왜 못 쓰나? 그럼 무엇으로?</summary>`sys_execve`에서 matchBinaries는 적재될 *새 이미지*가 아니라 execve를 *호출한 부모*를 매칭한다. `NotIn [/usr/sbin/nginx]`는 `nginx -v`(호출자=exec shim)를 죽이고 nginx-RCE 셸(호출자=nginx)은 통과시켜 정확히 거꾸로 동작한다. execve 진입 시점엔 caller 정보뿐이라 이름 기반 allowlist가 원리적으로 불가. 진짜 신원이 필요하면 BPF-LSM `security_bprm_creds_for_exec`(적재될 바이너리의 creds를 본다).</details>
6. <details><summary>zero-exec가 selective보다 "더 강한 통제"라서 커버리지가 올라가야 하지 않나?</summary>아니다 — selector를 *추가*한 게 아니라 *줄여* 매칭 표면을 없앤 것이다. ED1의 주장("데이터 티어 셸 exec를 죽인다")은 selective에서도 zero-exec에서도 참이라 개수가 불변(77.5%). (#2가 하향을, 이건 상향을 막는 같은 정직성의 두 방향.)</details>
7. <details><summary>execve 룰을 web/api 티어엔 왜 안 거나? (ED3 NOT_COVERED)</summary>데이터 티어는 정당한 exec가 0(프로브=httpGet, 본체=PID1)이라 "전부 금지"가 가용성을 안 깬다. web/api는 정상 운영 중 exec할 수 있어(예: 진입스크립트·sidecar) 전면 금지가 곧 가용성 사고. 그래서 zero-exec는 `tier: data`(ⓐ)에 한정되고, 다른 티어는 NOT_COVERED로 정직히 남긴다 — 과잉차단도 결함이라는 M4 교훈의 연장.</details>

## 더 깊이 (1차 출처)
- **Tetragon TracingPolicy / kprobe selectors** — selector·matchActions(Sigkill/Override) 문법: <https://tetragon.io/docs/concepts/tracing-policy/>
- **Tetragon enforcement & the write() caveat** — "SIGKILL during write() does not guarantee bytes were not written" + Sigkill vs Override: <https://tetragon.io/docs/concepts/enforcement/>
- **kind/LinuxKit kprobe 미부착 이슈(Station C SKIP 근거)** — cilium/tetragon#4883: <https://github.com/cilium/tetragon/issues/4883>
- **io_uring 회피 클래스("Curing", ARMO 2025)** — 기본 syscall 정책 blind / LSM이 해법: <https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/>
- **execveat(2) ABI** — execve와 별개 syscall, `AT_EMPTY_PATH`/fd-exec: <https://man7.org/linux/man-pages/man2/execveat.2.html>
- **LSM `bprm_creds_for_exec` 훅(allowlist의 올바른 표면)** — 적재될 바이너리의 creds 시점: <https://www.kernel.org/doc/html/latest/security/lsm.html>
- **이 레포 결정 기록** — [ADR 0001 selective→zero-exec](../../docs/decisions/0001-data-tier-zero-exec.md) · [THREAT_MODEL](../../THREAT_MODEL.md)

> 정직 메모: **라이브 측정은 rc뿐** — Phase1 선택적(id=0/sh=137/cat=0)·Phase2 zero-exec(id=137/sh=137)(`verify-runtime-scope.ps1`). Phase1의 *pre-image-load
> 타이밍*은 문서화 의미론(여기서 미측정). B는 execve가 pre-image-load라 윈도우 없음(쓰기가능 emptyDir는 있으니
> "쓸 곳이 없어서"가 아니다). C(write-window)는 Tetragon 문서화 caveat이며 kind에선 SKIP일 수 있다(미측정).
> M8은 ED1을 바꾸지 않고 그 의미를 *날카롭게* 한다. 배경: [04-runtime](../../docs/04-runtime.md) · [THREAT_MODEL](../../THREAT_MODEL.md).
