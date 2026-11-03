# 점검 항목 목록

상태: ✅ 구현 · 🚧 예정

| ID | 항목 | 심각도 | 레벨 | 플러그인 | 매핑 | 상태 |
|---|---|---|---|---|---|---|
| COMMON-HDR-001 | Content-Security-Policy 누락 | Medium | passive | `COMMON-HDR` | CWE-693, A05:2021 | ✅ |
| COMMON-HDR-002 | Strict-Transport-Security 누락 (HTTPS 대상만) | Medium | passive | `COMMON-HDR` | CWE-319, A05:2021 | ✅ |
| COMMON-HDR-003 | X-Frame-Options / frame-ancestors 누락 | Medium | passive | `COMMON-HDR` | CWE-1021, A05:2021 | ✅ |
| COMMON-HDR-004 | X-Content-Type-Options 누락 | Low | passive | `COMMON-HDR` | CWE-693, A05:2021 | ✅ |
| COMMON-HDR-005 | Server / X-Powered-By 버전 노출 | Low | passive | `COMMON-HDR` | CWE-200, A05:2021 | ✅ |
| COMMON-TLS-001 | TLS 1.0/1.1 허용 | High | passive | | | 🚧 |
| COMMON-TLS-002 | 취약 암호화 스위트 허용 | Medium | passive | | | 🚧 |
| COMMON-TLS-003 | 인증서 만료 / 만료 임박 / 자체 서명 | Medium | passive | | | 🚧 |
| COMMON-HTTP-001 | 로그인 페이지 HTTP 평문 제공 | High | passive | | | 🚧 |
| COMMON-CKE-001 | 세션 쿠키 Secure 누락 (HTTPS 대상만) | Medium | passive | `COMMON-CKE` | CWE-614, A05:2021 | ✅ |
| COMMON-CKE-002 | 세션 쿠키 HttpOnly 누락 | Medium | passive | `COMMON-CKE` | CWE-1004, A05:2021 | ✅ |
| COMMON-CKE-003 | 세션 쿠키 SameSite 미설정 | Low | passive | `COMMON-CKE` | CWE-1275, A05:2021 | ✅ |
| COMMON-EXP-001 | `.git/`, `.svn/` 노출 | High | passive | | | 🚧 |
| COMMON-EXP-002 | 백업·설정 파일 노출 (`.bak`, `.old`, `web.xml` 등) | High | passive | | | 🚧 |
| COMMON-EXP-003 | 디렉터리 리스팅 활성화 | Medium | passive | | | 🚧 |
| COMMON-ERR-001 | 상세 에러/스택트레이스 노출 | Medium | passive | | | 🚧 |
| WLS-001 | WebLogic 관리 콘솔 접근 가능 | High | passive | | | 🚧 |
| WLS-002 | WebLogic 버전 노출 | Low | passive | | | 🚧 |
| WLS-003 | T3/IIOP 프로토콜 노출 | High | passive | | | 🚧 |
| XP-001 | 서비스 URL 세션 없이 응답 | Critical | passive | | | 🚧 |
| XP-002 | 서비스 통신 평문 전송 | High | passive | | | 🚧 |

## 판단 기준 메모

- **세션 쿠키 판별**: 이름에 `session`, `sessid`, `jsessionid`, `sid`, `token`, `auth` 등이 포함된 쿠키만 대상으로 한다.
- **버전 노출**: `Server` 헤더에 `숫자.숫자` 형태가 있거나 `X-Powered-By`, `X-AspNet-Version` 헤더가 있으면 보고한다.
- 리다이렉트를 따라간 **최종 응답**을 기준으로 판단하며, 최종 URL 이 `Target` 으로 기록된다.
