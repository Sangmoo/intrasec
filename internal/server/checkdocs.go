package server

// checkItem 은 UI 에 보여 줄 세부 점검 항목이다 (docs/checks.md 와 같은 내용).
type checkItem struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
}

type checkDoc struct {
	items []checkItem
	note  string
}

// checkDocs 는 점검 플러그인 ID 별 세부 항목이다. 새 점검을 추가하면 여기와 docs/checks.md 를 함께 갱신한다.
var checkDocs = map[string]checkDoc{
	"COMMON-HDR": {items: []checkItem{
		{"COMMON-HDR-001", "Content-Security-Policy 누락", "medium"},
		{"COMMON-HDR-002", "Strict-Transport-Security 누락", "medium"},
		{"COMMON-HDR-003", "X-Frame-Options / frame-ancestors 누락", "medium"},
		{"COMMON-HDR-004", "X-Content-Type-Options 누락", "low"},
		{"COMMON-HDR-005", "Server / X-Powered-By 버전 노출", "low"},
	}, note: "기본 페이지 1회 요청"},
	"COMMON-TLS": {items: []checkItem{
		{"COMMON-TLS-001", "TLS 1.0/1.1 허용", "high"},
		{"COMMON-TLS-002", "취약 암호화 스위트 허용", "medium"},
		{"COMMON-TLS-003", "인증서 만료·자체 서명·호스트명 불일치", "medium"},
	}, note: "https 대상만, TLS 연결만 약 6회"},
	"COMMON-CKE": {items: []checkItem{
		{"COMMON-CKE-001", "세션 쿠키 Secure 누락", "medium"},
		{"COMMON-CKE-002", "세션 쿠키 HttpOnly 누락", "medium"},
		{"COMMON-CKE-003", "세션 쿠키 SameSite 미설정", "low"},
	}, note: "기본 페이지 1회 요청"},
	"COMMON-HTTP": {items: []checkItem{
		{"COMMON-HTTP-001", "로그인 페이지 HTTP 평문 제공", "high"},
	}},
	"COMMON-EXP": {items: []checkItem{
		{"COMMON-EXP-001", ".git / .svn 노출", "high"},
		{"COMMON-EXP-002", ".env·백업·설정 파일 노출", "high"},
		{"COMMON-EXP-003", "디렉터리 리스팅", "medium"},
	}, note: "경로 약 40개 확인 (운영 안전 모드는 3개)"},
	"COMMON-ERR": {items: []checkItem{
		{"COMMON-ERR-001", "상세 에러·스택트레이스 노출", "medium"},
	}},
	"PHP": {items: []checkItem{
		{"PHP-001~004", "PHP 버전 취약점 (EOL, PHP2Shell, CVE-2024-4577 등)", "critical"},
		{"PHP-010~017", "phpinfo·관리 도구·디버그·PHPUnit 노출", "high"},
	}, note: "PHP 흔적이 있거나 유형에 PHP 를 선택한 대상만"},
	"WLS": {items: []checkItem{
		{"WLS-001", "WebLogic 관리 콘솔 접근 가능", "high"},
		{"WLS-002", "WebLogic 버전 노출", "low"},
		{"WLS-003", "T3/IIOP 프로토콜 노출", "high"},
		{"WLS-004", "취약 컴포넌트(wls-wsat, _async 등) 노출", "high"},
	}, note: "WebLogic 흔적이 있거나 유형에 WebLogic 을 선택한 대상만"},
	"XP": {items: []checkItem{
		{"XP-001", "서비스 URL 세션 없이 응답", "critical"},
		{"XP-002", "서비스 통신 평문 전송", "high"},
	}, note: "서비스 URL 을 등록한 대상만"},
}
