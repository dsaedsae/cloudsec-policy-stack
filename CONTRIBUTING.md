# Contributing

이 저장소의 가치는 **정직한 검증가능성**이다. 기여도 그 원칙을 따른다.

## 절대 규칙

1. **모든 통제는 실행 가능한 검증을 갖거나, 정직하게 라벨된다.** "있다고 주장"만 하고 테스트가 없는
   통제는 `CONFIGURED`로, 미구현은 `NOT_COVERED`로 [`docs/mls-coverage.csv`](docs/mls-coverage.csv)에
   기록한다. 헤드라인 숫자를 올리려고 미검증 통제를 VERIFIED로 칠하지 마라.
2. **과대주장 금지.** 통제가 *막지 못하는 것*(잔여위험)을 함께 명시한다([THREAT_MODEL.md](THREAT_MODEL.md)).
3. **규제 조항번호를 날조하지 마라.** 확인 안 된 고시 번호·조문·시행일은 "1차 출처 대조 필요"로 표기.
4. **시크릿 커밋 금지.** 키/토큰은 절대 커밋하지 않는다(공개키만 허용).

## 게이트 (PR 전 통과)

```bash
make test     # CI 정책 게이트: 5개 스위트 (Cedar 8/8 · agent 17/17 · JWT 18/18 · cross-layer · SA-drift)
make docs     # mkdocs build --strict (링크/구조 검증)
```

클러스터 변경은 `make up && make verify`(라이브 21/21)까지 통과해야 한다.

## 새 랩 모듈 추가

1. **스켈레톤** — `labs/<m>/`에 학습자가 채울 작업 파일(strip된 통제).
2. **그레이더** — `labs/<m>/grade.{py,sh}`. canonical을 임시 디렉터리에 묶어 채점하고 **건드리지 않는다**
   (드리프트 0). 종료코드 0 = 졸업.
3. **canonical(정답지)** — `cedar/`·`k8s/` 등 실제 통제 파일. 졸업 후 `diff`로 비교하는 답안지.
4. **개념 문서** — `docs/`에 짝 페이지. `labs/README.md`의 표·리스트·체크리스트에 등록.
5. 무클러스터면 `scripts/progress.py`의 `NOCLUSTER`에 추가.

## 문서 렌더링 규칙 (중요)

문서는 **GitHub-raw와 mkdocs 사이트 양쪽에서 깨끗이** 렌더돼야 한다(저장소는 private + Pages 미배포라
GitHub-raw가 공유 표면):

- **배지/펄은 raw HTML로** — `<span class="lab-badge">`. `[텍스트]{ .lab-badge }`(attr_list)는 **둘 다에서
  리터럴로 깨진다**(`attr_list`는 맨 대괄호에 클래스를 못 붙임). 검증: 빌드된 `site/.../index.html`에서
  `class="lab-badge"`가 보이는지 grep.
- **Material 전용 구문 금지** — admonition(`!!!`/`???`), 콘텐츠 탭(`===`), 그리드 카드, `:material-*:`/
  `:octicons-*:` 아이콘 단축코드는 GitHub에서 리터럴. 블록쿼트/리스트/이모지/일반 링크로 쓴다.
  **mermaid는 OK**(양쪽 렌더).

## 커밋

`feat(m1): ...`, `fix(score): ...`, `docs: ...` 형식. 한 커밋 = 한 가지 일.
