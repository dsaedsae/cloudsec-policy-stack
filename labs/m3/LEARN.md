# M3 — Cilium 제로트러스트: 배우기 모드

이 모듈에서 web→api→db 최소권한 홉을 CiliumNetworkPolicy로 구성한다. 정책 문법과 L3/L4 vs L7의 차이를 **한 예시**를 통해 완전히 이해한 후, 나머지 규칙 5개를 직접 써서 검증한다.

---

## 1) 완성 예시 읽고 이해: allow-web-to-api 규칙

**왜 이 규칙인가:** 가장 복잡하다. L3/L4/L7이 모두 들어 있고, Cilium 정책의 구조를 완전히 보여준다.

```yaml
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: allow-web-to-api, namespace: shop }
spec:
  endpointSelector: { matchLabels: { app: api } }  # 이 규칙이 적용되는 대상: app=api 레이블 파드
  ingress:
    - fromEndpoints: [{ matchLabels: { app: web } }]  # 누가 접근 가능한가: app=web 파드만
      toPorts:
        - ports: [{ port: "8080", protocol: TCP }]    # 어느 포트인가: TCP 8080만 (다른 포트는 차단)
          rules:                                        # L7 제한: HTTP 메서드·경로 검사
            http:
              # L7: 공개 진입점이므로 경로 제한.
              # web이 /auditlogs 로 가려면: (1) Cilium이 L7 매칭 → "no match" → DROP
              # (2) 앱(Cedar)에 닿기 전에, 네트워크 엣지에서 403. 매칭된 경로만 진입.
              - method: "GET"
                path: "/accounts/[^/]+$"              # 정규식: /accounts/(아무거나) 끝. 정규식 매칭 성공해야만 통과
              - method: "POST"
                path: "/accounts/[^/]+/transfer$"     # /accounts/(아무거나)/transfer 끝만 POST 허용
```

**문법 분해:**

| 섹션 | 의미 |
|---|---|
| `apiVersion: cilium.io/v2` | Cilium 네트워크 정책 API 버전 |
| `kind: CiliumNetworkPolicy` | Kubernetes 리소스 타입 (일반 NetworkPolicy도 있으나, Cilium은 L7 규칙 지원) |
| `metadata.name` | 정책 이름 (클러스터 내 유일) |
| `spec.endpointSelector` | **누가 이 규칙의 대상인가**: matchLabels로 파드 선택. 여기선 app=api |
| `spec.ingress[]` | 이 파드들이 **받을(inbound)** 수 있는 규칙 리스트 |
| `fromEndpoints` | 발신자(source) 필터. 이 선택자와 매칭된 파드들만 여기 도달 가능. 여기선 app=web |
| `toPorts` | 포트·프로토콜·L7 규칙 |
| `.ports[].port` | L3/L4: TCP/UDP 포트 번호 |
| `.rules.http[]` | L7: HTTP 메서드 + 경로 정규식. **경로 정규식 매칭 실패 → Cilium이 즉시 DROP, HTTP 403 응답** |

**보안 의도:**

- **web 파드만 api 8080에 도달 가능.** 다른 파드(db, 외부 등)가 시도? → Cilium이 L3/L4에서 **DROP** (연결 거부, 타임아웃, HTTP 응답 없음).
- **web이 와도, 경로가 맞아야.** GET /accounts/acct-alice (정규식 매칭 O) → 통과 → 앱(Cedar)으로 전달 (Cedar가 추가 인가).
- **web이 와도, 경로가 틀리면.** GET /accounts/acct-alice/auditlogs (정규식 "^/accounts/[^/]+$" 매칭 X) → Cilium이 L7 엣지에서 **DROP** → HTTP **403** 응답 (앱 코드 실행 전).

**핵심 구분:**
- **L3/L4 DROP (e.g. db 파드가 api 8080 시도):** 연결 거부 / 타임아웃. HTTP 응답 없음. Cilium이 근본적으로 차단.
- **L7 403 (e.g. web 파드가 /auditlogs 시도):** HTTP 연결은 허용되나, Cilium의 L7 Envoy 필터가 경로 정규식 매칭 실패 → 403 응답. 경로만 틀린 것.

---

## 2) 빈칸 채우기: allow-api-to-db 규칙

이제 두 번째 규칙을 직접 채워라. **fromEndpoints의 선택자를 비워뒀다.**

```yaml
---
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata: { name: allow-api-to-db, namespace: shop }
spec:
  endpointSelector: { matchLabels: { app: db } }
  ingress:
    - fromEndpoints: [{ matchLabels: { app: __?__ } }]  # ← 여기 채워라: 누가 db에 접근?
      toPorts: [{ ports: [{ port: "8080", protocol: TCP }] }]
```

**힌트:**
- 아키텍처는 외부 → web → api → **db**. 여기서 누가 db로 가는가?
- L7 `rules.http` 섹션이 없다. 왜? api↔db는 *내부 마이크로서비스 통신*. 경로 제한이 필요 없으니 L3/L4만 충분.
- 1)의 worked example과 구조는 같다. **선택자만** 다르다.

**학습 단계:**
1. 아키텍처를 보고 선택자를 직접 입력하자.
2. 정답을 보기 전에 `bash labs/m3/grade.sh` 를 돌려서 검증하자.
3. 검증 후 아래 정답과 비교해서 확인.

<details><summary>정답 (클릭 전에 직접 써 볼 것)</summary>

```yaml
    - fromEndpoints: [{ matchLabels: { app: api } }]
      toPorts: [{ ports: [{ port: "8080", protocol: TCP }] }]
```

구조는 1)과 동일. app=api 파드들만 db에 접근 가능. 경로 제한 없음 (내부 통신).

</details>

---

## 3) 이제 혼자: 나머지 3개 규칙

skeleton(`labs/m3/netpol.yaml`)에 남은 TODO 3개를 채워라:

1. **allow-ingress-to-web** — 클러스터 외부 진입
   - `fromEntities: ["cluster"]` (외부 클라이언트)에서 web의 8080/TCP
   - L7 규칙 없음 (외부 진입이므로 포트만)
   
2. **egress-web-to-api** — web이 api로 나가기
   - `toEndpoints` (egress 방향): app=api
   - 8080/TCP
   - 구조는 1)의 `fromEndpoints` 대신 `toEndpoints`만 바뀜
   
3. **egress-api-to-db** — api가 db로 나가기
   - `toEndpoints`: app=db
   - 8080/TCP

**주의:**
- egress는 `spec.egress`를 쓴다 (ingress 대신).
- egress의 대상은 `toEndpoints` (ingress의 `fromEndpoints` 반대).
- db에 egress 규칙을 *주지 않는다* → DNS 베이스라인만 적용 → db는 DNS 외 못 나감 (가장 잠긴 tier). "규칙 없음"도 정책이다.

`labs/m3/netpol.yaml`의 형식을 따르고, 위 worked example(allow-web-to-api)의 구조를 참고해서 작성하자.

```bash
bash labs/m3/grade.sh        # 7/7 PASS 확인
```

다음: 정답과 비교 → 불일치면 README.md의 Step 2(break-and-fix) 실행.
