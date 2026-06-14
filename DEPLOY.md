# 배포 — 의사결정자가 *방문하는* 라이브 URL 만들기

목표: 사람을 raw `.md`로 보내지 않는다. 두 표면을 호스팅한다.

| 표면 | 파일 | 대상 |
|---|---|---|
| **의사결정자 랜딩** (rich, 단일 파일) | `presentation/cloudsec-onepager.html` | CISO/구매 — 멋진 한 화면 + 인쇄 PDF |
| 참조 문서 (plain) | `mkdocs build` → `site/` | 개발자/도입팀 — 트랙·매핑·평가 |

> 호스팅 *계정*은 필요 없다(여기 준비물엔). 무료 호스트에 **연결만** 하면 라이브 URL이 생긴다.

## 가장 빠른 길 — 랜딩 한 파일만 (계정 없이 30초)

`presentation/cloudsec-onepager.html`은 외부 의존성이 없는 **단일 파일**이다.

1. <https://app.netlify.com/drop> 에 그 파일을 **드래그** → 즉시 `https://<random>.netlify.app` URL.
2. (또는) 이메일에 그대로 첨부하거나, [PDF](presentation/cloudsec-onepager.pdf)를 보낸다.

## 전체 사이트 (문서까지) — 빌드 후 호스팅

```bash
make site          # = mkdocs build + 랜딩을 site/ 에 복사 → 배포 번들 'site/' 생성
```

그다음 셋 중 하나(전부 무료):

- **Netlify Drop** — `site/` 폴더를 <https://app.netlify.com/drop> 에 드래그. 가장 간단.
- **Cloudflare Pages** — 대시보드 ▸ Pages ▸ "Direct Upload" 로 `site/` 업로드 (private repo도 OK),
  또는 GitHub 연동(build command `mkdocs build`, output `site`).
- **GitHub Pages** — *repo를 public으로* 전환해야 무료(현재 private). 전환 시: Settings ▸ Pages ▸
  Source=GitHub Actions, 그리고 `.github/workflows/docs.yml`에 deploy 잡을 추가(현재는 build-only).

배포 후 공유 URL:
- 의사결정자: `https://<host>/cloudsec-onepager.html`
- 문서 홈: `https://<host>/`

## 공개 전 체크 (private → public 시)

- `gitleaks`로 히스토리 재스캔(시크릿 0 — 이미 CI에 있음).
- README의 repo URL/배지 경로 확인.
- 문서는 *의도적으로 평문 마크다운*이다(GitHub-raw 이식성). 배포 사이트의 *시각적 화려함*은
  `cloudsec-onepager.html` 랜딩이 담당한다 — 문서 본문까지 Material 카드/탭으로 화려하게 하려면
  별도 작업이 필요하고 GitHub-raw 가독성과 트레이드오프가 있다(요청 시 진행).
