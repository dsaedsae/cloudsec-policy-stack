# M11 — exec 허용목록은 LSM이 필요하다: syscall 표면 vs 커널 연산

<div class="lab-pills">
<span class="lab-progress">심화 / 측정·LSM</span> · <span class="lab-badge">스택 Tetragon BPF-LSM</span> · <span class="lab-badge">소요 ~30–50m</span> · <span class="lab-badge cluster">클러스터 필요 · BPF-LSM 커널</span> · <span class="lab-badge">비용 $0 로컬</span>
</div>

> **선행:** M4(선택적 셸-kill을 *직접* 만든다) · M8(그 룰의 한계를 *라이브로 측정*). M11은 M4·M8이 *이름만 대고 못 막은* 잔여를 **실제로 구현**한다.
> **준비:** BPF-LSM이 켜진 커널(`CONFIG_BPF_LSM=y` + `lsm=...,bpf`) + Tetragon. **대부분의 kind/Docker Desktop 커널엔 BPF-LSM이 `lsm=` 목록에 없다 → grade.sh가 정직하게 SKIP**(FAIL 아님). 이 랩은 그게 *왜* 그런지까지 가르친다.

**미션 — exec를 전면금지(zero-exec)할 수 없는 티어에서, "이 바이너리만 허용"을 *정직하게* 거는 법.**
[ADR 0001](../../docs/decisions/0001-data-tier-zero-exec.md)은 데이터 티어를 **zero-exec**(모든 exec SIGKILL)로 정했다 — 정상 exec가 0이라 가능했다. 하지만 **web/api 티어는 정상 exec가 있다**(entrypoint 스크립트·sidecar·디버그). 거기서 zero-exec는 가용성 사고다. 그럼 **허용목록**(nginx는 OK, 주입된 셸은 kill)이 필요한데 — M4·M8이 보였듯 **syscall 표면으론 허용목록을 정직하게 못 건다.** M11은 그 이유를 보이고, **BPF-LSM `bprm_check_security`** 훅으로 — *적재되는 이미지*의 신원을 봐서 — 허용목록을 건다(BPF-LSM이 있는 커널에서).

## 1. 왜 syscall 표면으론 허용목록이 안 되나 (M4·M8의 현금화)

| | 무엇을 보나 | 허용목록에서 깨지는 지점 |
|---|---|---|
| **M4 `matchArgs` arg0** (`sys_execve`) | 새 프로세스의 `argv[0]` 문자열 | `cp busybox /tmp/x; /tmp/x sh` → arg0=`/tmp/x` 로 **rename 우회**. 이름은 신원이 아니다. |
| **`matchBinaries`** (kprobe/LSM 공통) | exec를 *호출한* 바이너리(**caller**) | **거꾸로 작동한다**: `NotIn [nginx]`는 `nginx -v`(caller=exec shim)를 죽이고, nginx-RCE 셸(caller=nginx)은 *통과*시킨다. ADR 0001의 핵심 발견. |
| **LSM `bprm_check_security`** | **적재될 바이너리**(`linux_binprm->file`)의 path/inode | 호출자도 arg0도 아닌 *실제 적재 이미지*. rename·execveat·fd-exec와 무관 — 그래서 정직한 허용목록의 유일한 훅. |

핵심 senior 구분: **syscall 표면은 "어떤 호출이 일어났나"를, LSM은 "어떤 커널 *연산*이 일어나는가"를 본다.** exec 허용목록은 *적재되는 바이너리가 무엇인가*를 알아야 하고, 그건 `bprm_check_security` LSM 훅에만 신뢰성 있게 있다(M8이 io_uring 잔여에서 가리킨 바로 그 LSM 레이어).

## 2. 측정 — 호출자 vs 적재-이미지 (BPF-LSM 있는 커널에서)

테스트 파드(nginx)에 `tracingpolicy-lsm-exec-allowlist.yaml`(적재-이미지 `nginx`만 허용, 나머지 exec는 Sigkill)을 적용하고 `grade.sh`가 단언:

| 시도 | 적재 이미지 | 기대 | 왜 |
|---|---|---|---|
| `nginx -v` | `/usr/sbin/nginx` | **생존** | 허용목록의 *적재 이미지* — M4 arg0 룰은 이걸 못 구분 |
| 주입 셸 `/bin/sh` | `/bin/sh` | **kill (137)** | 적재 이미지가 허용목록 밖 |
| **renamed** `cp busybox /tmp/x; /tmp/x sh` | `/tmp/x`(busybox) | **kill (137)** | LSM은 inode/path를 보므로 **rename 우회가 안 통한다**(M4 arg0는 여기서 뚫렸다) |

이게 측정되면 M4·M8이 *못 막던* 두 우회(rename·caller-혼동)가 LSM 레이어에서 닫힘을 *직접* 본다.

## 정직한 한계 (과장 금지)

- **kind/Docker Desktop/GitHub Actions 러너 모두 BPF-LSM이 없다 (라이브 확정).** `cat /sys/kernel/security/lsm`에 `bpf`가 없으면 grade.sh는 **SKIP**한다 — 그 환경에선 이 통제를 *증명할 수 없다*. CI integration 잡이 grade.sh를 돌려 **라이브로 SKIP**함을 확인했다(러너 `lsm = lockdown,capability,landlock,yama,apparmor,ima,evm` — bpf 없음 → disallowed 셸이 rc=0로 생존). (kind 이슈 #4883류; M8의 SKIP 선례.)
- **그래서 ED3는 여전히 NOT_COVERED다.** M11은 LSM *메커니즘*을 제공·설명하지만, kind에서 라이브로 안정 증명이 안 되므로 **헤드라인 82.5%는 안 바뀐다** — 단발 행운의 PASS로 ED3를 VERIFIED로 올리지 않는다(정직성 철칙).
- **"io_uring-proof / 우회 불가" 주장 금지.** 이 랩의 주장은 딱 *"LSM 훅이 syscall-arg0/caller가 못 보던 적재-이미지 연산을 본다"* 뿐이다. LSM도 전능하지 않다(정책 미적용 경로·다른 LSM 충돌 등).
- **Sigkill은 탐지-후-kill.** prevention-grade는 LSM `bprm`에서 **`Override`(-EPERM 반환)**로 exec 자체를 거부하는 것 — 룰에 옵션으로 표기. (Tetragon의 정확한 LSM arg-resolve/Sigkill 문법은 버전 의존 — 정책 헤더 주석 참고.)

## 왜 헤드라인이 안 변하나

> M11은 M8이 가리킨 LSM 잔여를 *랩으로* 만든 **깊이 모듈**이다. kind에서 BPF-LSM이 없어 라이브 증명이 SKIP-prone이라, **ED3는 NOT_COVERED 그대로, 82.5%(33/40) 불변.** 통제를 가감한 게 아니라 *메커니즘과 그 한계를 가르친다*. (BPF-LSM 가능 클러스터에서 cross-tier 적재-이미지 kill이 *실제로* 발화하면 그때 ED3 승격을 오너가 판단 — 단발 PASS로는 안 됨.)

## 구두 문답

1. <details><summary>데이터 티어는 zero-exec인데 왜 web/api는 허용목록이 필요한가?</summary>데이터 티어는 정상 exec가 0(프로브=httpGet, 본체=PID1)이라 전면금지가 가용성을 안 깬다. web/api는 entrypoint·sidecar·디버그로 정상 exec가 있어 전면금지가 곧 사고 → "이것만 허용"이 필요하고, 그건 *적재 이미지 신원*을 요구한다.</details>
2. <details><summary>matchBinaries로 "nginx만 허용"하면 왜 거꾸로 되나?</summary>matchBinaries는 exec를 *호출한* 바이너리(caller)를 매칭한다. `nginx -v`의 caller는 exec shim이라 죽고, nginx-RCE 셸의 caller는 nginx라 통과한다 — 정확히 반대(ADR 0001).</details>
3. <details><summary>M4 arg0 룰은 renamed 셸을 왜 못 막나? LSM은 왜 막나?</summary>arg0는 `argv[0]` 문자열이라 `cp busybox /tmp/x; /tmp/x sh`로 바꾸면 안 걸린다. LSM `bprm_check_security`는 `linux_binprm->file`(실제 적재 inode/path)을 보므로 이름을 바꿔도 동일 바이너리를 잡는다.</details>
4. <details><summary>이 랩이 kind에서 SKIP하면 실패인가?</summary>아니다. kind 커널 `lsm=`에 bpf가 없으면 *증명 불가*가 정직한 결과다. 그래서 ED3는 NOT_COVERED로 남고 헤드라인도 안 변한다. SKIP을 PASS인 척하지 않는 게 핵심.</details>
5. <details><summary>"이제 모든 런타임 우회를 막았다"고 말해도 되나?</summary>안 된다. LSM은 syscall-arg0/caller가 못 보던 *적재-이미지* 연산을 볼 뿐, 전능하지 않다(정책 커버리지·다른 LSM·비-exec 경로). 주장은 정확히 그 범위로 한정.</details>
6. <details><summary>탐지가 아니라 진짜 *방지*하려면?</summary>Sigkill은 적재 직전 프로세스를 죽이는 detection-then-kill에 가깝다. LSM `bprm`에서 `Override`로 -EPERM을 반환하면 exec 자체가 거부되는 prevention-grade다(룰에 옵션 표기).</details>

## 실행 (opt-in · SKIP-prone)

```bash
bash labs/m11/grade.sh        # BPF-LSM 없으면 SKIP(정직). 있으면 nginx-self 생존 / 셸·renamed kill 측정
python labs/m11/grade.py      # 무클러스터: 정책 구조 + 'caller 아닌 적재-이미지' 검증
```
