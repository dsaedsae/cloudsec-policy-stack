# M4 배우기 — Tetragon TracingPolicy: 셸 차단의 작동 원리

## 개요

`labs/m4/tracingpolicy.yaml`의 skeleton은 podSelector와 kprobe 기본 구조를 이미 제공합니다. 
당신이 채워야 할 부분은 **selectors** — data tier 파드에서 execve된 인자가 셸 경로로 끝나면 
즉시 SIGKILL하는 조건과 액션입니다.

이 페이지는:
1. **완성 예시** — 셸 경로 매칭의 한 가지 대표 사례를 보고 이해
2. **빈칸 채우기** — 핵심 개념(operator)을 직접 기입하며 배우기
3. **이제 혼자** — skeleton에서 나머지 셸들을 추가하고 정책 완성

---

## 1) 완성 예시 (읽고 이해)

다음은 **두 셸만** 매칭하는 kprobe의 전체 모습입니다. 어떻게 작동하는지 주석과 함께 읽으세요.

```yaml
kprobes:
  - call: "sys_execve"          # syscall: execve(경로, 인자...) 를 후킹
    syscall: true
    args:
      - index: 0                # execve의 첫 인자 = 실행 파일 경로 (string 타입)
        type: "string"
    selectors:
      - matchArgs:              # "언제" 액션을 실행할지 조건 정의
          - index: 0            # 위에서 정의한 arg[0](경로)를 검사하겠다
            operator: "Postfix"  # 경로가 이 값으로 끝나면 매칭
            values: ["/sh", "/bash"]  # "/bin/sh", "/usr/bin/bash" 등 모두 잡음 (경로 접두 무시)
        matchActions:           # 위 조건이 참이면 "무엇"을 할지
          - action: Sigkill     # 커널에서 즉시 SIGKILL (exit code 137)
```

**왜 이 방식인가:**
- **Postfix (접미사 매칭)**  
  `/bin/sh`, `/usr/bin/bash` 등 경로의 앞부분은 다를 수 있습니다(distro/설치 방식에 따라).
  Postfix는 "경로가 이것으로 끝나면"이라는 뜻이므로, 앞부분을 무시하고 셸 이름만 잡습니다.

- **values 목록 (화이트리스트)**  
  `["/sh", "/bash"]`는 "이 이름들로 끝나는 경로만 매칭"이라는 뜻입니다.  
  `/usr/bin/id`는 이 목록에 없으니 **건드리지 않습니다** ← 이것이 **선택성(selectivity)**.

- **Sigkill (커널 신호)**  
  eBPF가 syscall 시점(커널)에서 즉시 프로세스를 죽입니다.  
  사용자공간 에이전트처럼 폴링 지연이 없어 타이밍 레이스에 강합니다.

---

## 2) 빈칸 채우기 (핵심 이해: Operator)

다음 selector에서 `__?__` 부분을 채워라.  
**핵심 질문: 경로 앞부분이 달라도 셸을 모두 잡으려면 operator는 뭐여야 하나?**

```yaml
selectors:
  - matchArgs:
      - index: 0
        operator: __?__        # "Postfix" 아니면 "Equal"?
        values: ["/sh", "/bash", "/dash", "/ash", "/busybox"]
    matchActions:
      - action: Sigkill
```

**힌트 1:** README의 Step 2를 보면, `operator: "Equal"`로 바꾸면 뭐가 달라지나 하는 실험이 있습니다.  
Equal은 "인자가 정확히 이 문자열이면"이라는 뜻입니다.

**힌트 2:** 실제 pods에서 셸은 어떻게 실행되나요?  
- `/bin/sh` (Postfix match O, Equal match X — "Equal: /sh"는 "/bin/sh"와 다름)
- `/usr/bin/bash` (Postfix match O, Equal match X)

**정답:** `Postfix`  
(이것이 이 룰의 핵심 idiom: 경로 접두를 모를 때 **이름으로 끝나는지만** 본다)

---

## 3) 이제 혼자 — Skeleton에서 완성하기

`labs/m4/tracingpolicy.yaml`를 열고 **selectors** 섹션(line 24-31)을 작성하세요.

```yaml
selectors:
  - matchArgs:
      - index: 0
        operator: ??           # 위에서 배운 operator를 쓰세요
        values: [??]           # README Step 1에 나온 5개 셸 이름 중 2개를 넣었으니, 
                               # 나머지 3개를 추가하세요
    matchActions:
      - action: ??            # 커널에서 프로세스를 즉시 SIG로 종료하는 액션은?
```

**필요한 것:**
1. **operator** — "Postfix" 를 기입
2. **values** — `["/sh", "/bash"]` 에 3개를 더 추가해 총 5개 (`"/dash", "/ash", "/busybox"` 를 추가할 것)
3. **action** — "Sigkill" 를 기입 (대소문자 정확히: `Sigkill`만 유효, `sigkill`이나 `SIGKILL`은 안 됨)

**검증:**
```bash
bash labs/m4/grade.sh
```
두 가지 모두 PASS여야 합니다:
- `비셸 exec(id) 는 살아있다` — rc=0 (id 명령어는 실행 허용)
- `셸 exec(sh) 는 SIGKILL` — rc=137 (sh는 SIGKILL로 종료)

**"둘 다" 가 필요한 이유:**  
셸만 죽이는 게 아니라 셸**만** 골라 죽인다는 걸 증명해야 합니다.  
전체를 다 죽이는 정책도 "셸 죽음"을 만족하지만, 정상 운영(id 헬스체크)을 깨므로 결함입니다.

---

## 다음 배우기

- **Step 2 (break-and-fix):** operator를 Equal로 바꾸면?  
  → `/bin/sh` 는 "/sh"와 정확히 다르므로 매칭 안 됨. 셸이 살아남음.

- **이 룰의 한계(THREAT_MODEL):**  
  이 규칙은 **셸 이름의 직접 execve**만 죽입니다.  
  쉘을 다른 이름으로 띄우면 우회됩니다:
  - 쓰기가능 /tmp에 복사: `/tmp/x sh` (renamed binary)
  - execveat syscall (별도 후킹 필요)
  - fd-exec: `/proc/self/fd/N` (arg0 매칭 아님)
  
  강건한 답은 zero-exec(execve + execveat 전부 Sigkill) + distroless 이미지 — [M8](../m8/README.md)에서 라이브로 측정합니다.

---

정리:  
skeleton을 완성한 후 `grade.sh` 로 검증하고, 왜 "operator: Postfix"를 썼는지,  
그리고 이 룰이 못 막는 것(renamed/execveat)이 뭔지 설명할 수 있으면 M4 통과입니다.
