# 검증가능성 커버리지 — 코드북 (분류 규칙)

> 헤드라인 **82.5% (33/40)** 은 [`docs/mls-coverage.csv`](mls-coverage.csv) 를 [`scripts/coverage.py`](https://github.com/dsaedsae/cloudsec-policy-stack/blob/master/scripts/coverage.py) 가 계산한 값이다. 이 문서는 그 **분류 규칙(codebook)** 을 명문화한다 — 어떤 행을 왜 VERIFIED/CONFIGURED/GOVERNANCE/NOT_COVERED 로 놓았는지, 분모를 어떻게 잡는지. **정직 고지: 이 분류는 단일 저자(n=1)의 판단이다.** 재현은 가능하지만(같은 CSV→같은 숫자) 객관적 합의는 아니다 — 복수 평가자 inter-rater 합의가 다음 단계다([`evaluation-coverage.md`](evaluation-coverage.md) 참조).

## 1. 산식은 코드에 박혀 있다 (해석 여지 없음)

`scripts/coverage.py:36` 이 분모를 결정한다 — **임의 규칙이 아니라 결정론적 코드**:

```python
workload_applicable = total - by_cat["GOVERNANCE"]      # 42 - 2 = 40
headline           = VERIFIED / workload_applicable      # 33 / 40
```

- **분모에서 빠지는 것 = GOVERNANCE 행만**(아래 §3). NOT_COVERED 는 분모에 **남아 감점**된다.
- 반올림 금지: `coverage.py:46` 이 `.1f` 후 후행 `.0` 만 떼므로 33/40 은 정확히 `82.5`, 32/40 이라면 `80` 으로 찍힌다 — **올림으로 부풀리지 않는다**.
- 두 분모를 함께 보고한다: **82.5% (33/40, 워크로드-적용)** · **79% (33/42, governance 포함)**.

## 2. 카테고리 정의 (행별 판정 기준)

| 카테고리 | 의미 | 들어가는 증거 기준 |
|---|---|---|
| **VERIFIED** | 통제가 **실행 가능한 테스트로 라이브 증명**됨 | 재실행 가능한 스크립트/단위테스트가 통제의 작동(또는 위반 거부)을 보인다. *대부분 always-on CI(policy+integration job), 일부는 opt-in 재실행(§4).* |
| **CONFIGURED** | 통제가 **설정·존재하나 스위트가 단언하지 않음**(clean PASS/DENY 없음) | 매니페스트/런북엔 있으나 라이브 거부를 깨끗이 못 보이거나(예: ID4 SVID), 자동·테스트화 안 됨(ER2 키회전). |
| **GOVERNANCE** | **조직/프로세스 통제 — 단일 워크로드가 구현·테스트할 수 없음** | 데이터분류 거버넌스·이사회 보고처럼 *워크로드의 통제 표면 밖*. → **분모 제외**(워크로드-적용 아님). |
| **NOT_COVERED** | **워크로드-적용 가능한 기술 통제인데 이 repo엔 부재** | DLP·SIEM·KMS처럼 워크로드가 *통합할 수 있으나* 안 한 것. → **분모에 남아 감점(gap)**. |

핵심 구분(**GOVERNANCE vs NOT_COVERED**): "이 워크로드가 코드로 구현·검증할 수 있는 종류인가?" — 아니오(조직 프로세스)면 GOVERNANCE(제외), 예-인데-안 했으면 NOT_COVERED(감점). 이 규칙이 분모를 정한다.

## 3. governance 가족 4행 — 왜 2개는 제외, 2개는 감점인가

| 행 | 분류 | 판정 근거 |
|---|---|---|
| **GV1** C/S/O 데이터분류 거버넌스 | GOVERNANCE(제외) | 등급 분류는 **조직 프로세스**(NIS MLS) — 한 워크로드가 수행/테스트할 수 없다. |
| **GV2** CEO·이사회 보고 + 시정요구 대응 | GOVERNANCE(제외) | 순수 **조직** 책임 — 워크로드 통제 표면 밖. |
| **GV3** DLP(데이터 유출 방지) | **NOT_COVERED(감점)** | 워크로드 데이터에 *적용 가능한 기술 통제*이나 이 repo엔 없음 → gap. |
| **GV4** SIEM/중앙 감사 통합 | **NOT_COVERED(감점)** | 신호 export 지점은 있으나 *통합 안 함* → 기술적으로 가능했는데 부재 → gap. |

→ GV1/GV2 를 제외하는 것은 "워크로드가 못 하는 일로 워크로드를 벌하지 않기" 위함이고, GV3/GV4 를 감점하는 것은 "할 수 있었는데 안 한 것은 정직히 갭으로 센다" 위함이다. **이 비대칭은 의도적이며 위 규칙에서 도출된다.**

## 4. 정직한 추가 고지

- **always-on vs opt-in.** 33개 VERIFIED 중 약 **28개는 always-on CI**(매 push: policy job + kind 통합 job)에서 재실행된다. 나머지 ~5개는 **opt-in 이지만 재실행 가능한** 증거다 — ER1(M5 etcd 암호화), ID7(capstone Kyverno), SL6(cosign 서명), ID8 enforce-라이브, ET2(WG 패킷 캡처). 이들은 CSV `evidence` 열에 `opt-in`/`capstone`/`M5` 로 표시된다. 즉 *상시-게이트된* 비율은 ~28/40 으로, 헤드라인(재실행-가능 테스트 기준 33/40)보다 낮다.
- **n=1.** 분해·분류·VERIFIED/CONFIGURED 라벨 부여 모두 저자 1인이 했다. 객관 측정이 아니라 **저자 판단의 재현**이다.
- **자기-평가지 아님.** 이 코드북은 분류 규칙을 *명시*해 자의성을 줄일 뿐, 외부 검증(복수 평가자·국내 워크숍 심사)을 대체하지 않는다 — 그게 신뢰성 다음 단계다.
