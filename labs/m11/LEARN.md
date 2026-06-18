# M11 배우기 모드 — 왜 LSM `bprm` 훅인가

> [M11 README](README.md)를 먼저. 핵심 한 줄: **exec 허용목록은 *적재되는 이미지*의 신원을 봐야 하는데,
> 그건 syscall 표면(arg0·caller)엔 없고 LSM `bprm_creds_for_exec`에만 있다.**

## 1단계 — 세 후보를 손에 익힌다 (무엇을 보나)

| 훅 | 보는 것 | exec 허용목록에서 |
|---|---|---|
| `sys_execve` + `matchArgs` arg0 (M4) | `argv[0]` 문자열 | rename으로 우회(`/tmp/x sh`) — 이름은 신원이 아님 |
| `matchBinaries` (어느 훅이든) | exec를 *호출한* 바이너리(caller) | 거꾸로 — `nginx -v`는 죽고 nginx-RCE 셸은 통과(ADR 0001) |
| **LSM `bprm_creds_for_exec`** | **적재될 `linux_binprm->file`** | 실제 inode/path — 정직한 허용목록의 유일한 훅 |

## 2단계 — 한 칸 채우기 (정책에서 무엇이 load-bearing인가)

`tracingpolicy-lsm-exec-allowlist.yaml`에서:
```yaml
lsmhooks:
  - hook: "bprm_creds_for_exec"
    args: [{ index: 0, type: "linux_binprm" }]   # 적재 이미지
    selectors:
      - matchArgs: [{ index: 0, operator: "NotPrefix", values: ["/usr/sbin/nginx", ...] }]
        matchActions: [{ action: Sigkill }]
```

<details><summary>왜 matchBinaries가 아니라 matchArgs인가?</summary>matchBinaries는 <b>caller</b>(exec를 호출한 바이너리)를 매칭한다 — exec 허용목록엔 거꾸로다. 우리가 알아야 할 건 <b>적재될 바이너리</b>이고, 그건 bprm 훅의 <code>linux_binprm->file</code> = 이 정책에선 <code>matchArgs</code> index 0이다. matchArgs(적재-이미지) ✓ / matchBinaries(caller) ✗.</details>

<details><summary>왜 Sigkill이고, 진짜 방지는?</summary>Sigkill은 적재 직전 프로세스를 죽인다(detection-then-kill). prevention-grade는 <code>action: Override</code>로 exec syscall에 -EPERM을 반환해 exec 자체를 거부하는 것. 룰 헤더 주석 참고.</details>

## 3단계 — 예측 후 측정 (BPF-LSM 커널에서)

`bash labs/m11/grade.sh` 전에 예측하라:
1. `nginx -v` → ? (적재 이미지 = nginx, 허용목록 안 → **생존**)
2. `/bin/sh` → ? (적재 이미지 = sh, 허용목록 밖 → **137**)
3. `cp busybox /tmp/x; /tmp/x sh` → ? (적재 이미지 = busybox, **137** — LSM은 path/inode를 보므로 rename이 안 통함. M4 arg0는 여기서 뚫렸다.)

**kind에서 SKIP이 떠도 실패가 아니다** — `lsm=`에 bpf가 없으면 이 통제는 *증명 불가*이고, 그래서 ED3는 NOT_COVERED·헤드라인 불변이다. 그 *정직한 경계*를 설명할 수 있으면 졸업이다.
