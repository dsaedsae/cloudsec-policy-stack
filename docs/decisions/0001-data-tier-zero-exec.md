# ADR 0001 — 데이터 티어 런타임: 선택적 셸-kill → zero-exec

**상태:** 채택 (2026-06-16) · **대체:** 선택적 arg0-Postfix 룰 `block-shell-in-data-tier` (이제 M4 랩 프리미티브 `labs/m4/tracingpolicy.solution.yaml`)

## 맥락
런타임 계층(Tetragon/eBPF)은 침해 *후* 데이터 티어의 exec를 막는다. 첫 통제는 **선택적 셸-kill**이었다:
`sys_execve`의 arg0가 셸 이름(`/sh`·`/bash`·`/dash`·`/ash`·`/busybox`)으로 끝나면 SIGKILL, 정상 바이너리(`id`)는
살린다. `verify.sh`는 이를 *선택성*으로 검증했다 — "id는 살고(rc=0) 셸만 죽는다(137)"; **과잉차단도 결함**(정상
운영을 깨면 가용성 사고)이라는 M4의 교훈을 담은 테스트였다.

## 왜 바꾸나 (M8에서 *라이브로* 발견한 한계)
선택적·이름 기반 룰은 **우회된다**:
- `matchBinaries`는 *호출자* 바이너리를 매칭한다 — `sys_execve`로 새로 실행될 이미지가 아니라. 그래서
  `matchBinaries NotIn [nginx]`는 `nginx -v`(호출자=런타임 exec shim)를 죽이면서, nginx-RCE로 띄운
  셸(호출자=nginx)은 *놓친다*. "어떤 바이너리가 실행되나"엔 틀린 도구다.
- arg0-Postfix는 **renamed copy**(`cp busybox /tmp/x && /tmp/x sh`, arg0=`/tmp/x`)·**execveat**(별도의 미후킹
  syscall)·**fd-exec**로 우회된다.

## 결정
데이터 티어의 *유일한 정상 프로세스는 DB 본체(PID1)*이고 — db 프로브는 **httpGet**이라 exec가 전혀 필요 없다.
따라서 이름으로 whack-a-mole 하지 말고 **데이터 티어의 *모든* exec를 금지(zero-exec)** 한다:
`sys_execve` **와** `sys_execveat`를 후킹해 `tier: data`에서 발생하는 모든 exec를 SIGKILL.

## 결과
- shipped default를 `block-shell-in-data-tier`(선택적) → **`data-tier-no-exec`(zero-exec)** 로 교체.
  M8에서 라이브 검증됨: `id`/`sh`/renamed-copy/busybox **전부 rc=137**(arg0·이름·rename 무관), PID1 nginx는 유지.
- `verify.sh`/`verify.ps1` 런타임 단언이 *선택성*에서 *zero-exec*로 바뀐다: 이제 `id`도 137(데이터 티어 exec
  전면 차단, 파드 Ready 동시 확인으로 false-pass 차단).
- 선택적 룰과 "과잉차단도 결함" 교훈은 **M4 랩에 학습용 프리미티브로 남고**(selector 문법을 익힌다), 그 룰의
  *우회를 라이브로 측정*하고 zero-exec를 검증하는 건 **M8**이다 — **shipped 스택은 그 결론(zero-exec)을 기본으로 쓴다.**

## 트레이드오프 · 정직한 caveat
- zero-exec는 `kubectl exec`·exec 기반 프로브도 죽인다 — db는 httpGet이라 무관(의도된 "datastore엔 인터랙티브 exec 0").
- restart-tolerance는 *이미지가 아니라 Tetragon 부착-창* 덕분(이미지 무관·fragile; 더 빠른 attach는 entrypoint를
  죽여 CrashLoop 가능). **distroless의 이점은 *이미지층*(셸 부재) = 2중 방어**이지 restart-safety가 아니다.
- 일부 exec 허용(allowlist)이 필요하면 arg0 문자열이 아니라 **BPF-LSM**(`security_bprm_creds_for_exec`)의
  바이너리 신원이 필요하다.

**근거(라이브):** [`labs/m8/tracingpolicy-data-tier-no-exec.yaml`](../../labs/m8/tracingpolicy-data-tier-no-exec.yaml) 헤더의
검증 기록 · [`labs/m8/README.md`](../../labs/m8/README.md) · [`THREAT_MODEL.md`](../../THREAT_MODEL.md).
