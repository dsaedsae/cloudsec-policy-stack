// M6 Part A 작업 파일 — AI 에이전트 위임 인가 (Cedar). 여기에만 작성한다.
//
// 스키마(열람 OK): cedar/agent/schema.json — Agent{allowed_tools, max_classification,
//   on_behalf_of, delegation_depth}, User{clearance}, Tool{name}, DataRecord{classification, owner};
//   액션 InvokeTool(Agent→Tool), ReadData(Agent→DataRecord). 등급 0=공개·1=민감·2=기밀.
// 채점: .venv\Scripts\python.exe labs\m6\grade.py agent   (목표 14/14)
// 정답지 cedar/agent/policies.cedar 는 졸업 전 열람 금지.
//
// 핵심 개념: 에이전트는 사용자를 *대행*하는 NHI다. confused-deputy를 막으려면 인가가
// (에이전트 자신의 천장) ∧ (대행 사용자의 등급)의 *교집합*이어야 한다.

// P1) 도구 허용목록: 에이전트는 자기 allowed_tools 안의 도구만 호출할 수 있다.
//     힌트: 문자열 Set 멤버십은 `.contains(...)` (Cedar `in`은 엔티티 계층용 — 쓰지 말 것).
// TODO

// P2) 위임 교집합(confused-deputy 방지): 데이터 읽기는 등급이
//     (에이전트 max_classification 이하) AND (대행 사용자 on_behalf_of.clearance 이하)일 때만.
// TODO

// P3) owner override: 대행 사용자가 *소유한* 레코드는 등급 사다리와 무관하게 읽되,
//     여전히 에이전트 천장으로는 제한한다(에이전트에 넘긴 권한 이상은 못 줌).
// TODO

// P4) 하드 가드레일(forbid): 천장이 '기밀(2)' 미만인 에이전트는 기밀 데이터를 절대 못 읽는다.
//     forbid는 어떤 permit보다 우선. (지금 permit 집합에선 중복이지만, 미래 permit 대비 백스톱.)
// TODO

// P5) 위임 깊이 cap (OWASP Agentic Top 10 ASI08 — cascading/runaway delegation):
//     에이전트가 서브에이전트를 스폰하면 human->agent->sub->... 체인이 생긴다. delegation_depth
//     (휴먼 위의 agent->agent 홉 수: 0=직접조작, 1=허용된 한 홉, 2+=금지)가 1을 넘는 에이전트는
//     *모든 action*에서 거부하라. 힌트: action 제약 없는 forbid + `principal.delegation_depth > 1`.
// TODO
