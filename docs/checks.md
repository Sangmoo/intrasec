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
| COMMON-EXP-001 | `.git/`, `.svn/` 노출 | High | passive | `COMMON-EXP` | CWE-527, KISA IL | ✅ |
| COMMON-EXP-002 | `.env` 노출 (Critical) / 백업·설정 파일 노출 (`.bak`, `~`, `.sql`, `.zip`, `web.xml`, `.DS_Store`) | High | passive | `COMMON-EXP` | CWE-538/530, KISA IL | ✅ |
| COMMON-EXP-003 | 디렉터리 리스팅 활성화 | Medium | passive | `COMMON-EXP` | CWE-548, KISA DI | ✅ |
| COMMON-ERR-001 | 상세 에러/스택트레이스 노출 | Medium | passive | | | 🚧 |
| WLS-001 | WebLogic 관리 콘솔 접근 가능 | High | passive | | | 🚧 |
| WLS-002 | WebLogic 버전 노출 | Low | passive | | | 🚧 |
| WLS-003 | T3/IIOP 프로토콜 노출 | High | passive | | | 🚧 |
| XP-001 | 서비스 URL 세션 없이 응답 | Critical | passive | | | 🚧 |
| XP-002 | 서비스 통신 평문 전송 | High | passive | | | 🚧 |
| PHP-001 | 지원 종료(EOL) PHP 버전 / 종료 90일 이내 | High / Low | passive | `PHP` | CWE-1104, A06:2021 | ✅ |
| PHP-002 | PHP2Shell RCE 취약 버전 (CVE-2026-109618/109619, CISA KEV) | Critical | passive | `PHP` | A06:2021 | ✅ |
| PHP-003 | Windows PHP-CGI 인자 주입 취약 버전 (CVE-2024-4577, KEV) | Critical / High | passive | `PHP` | CWE-78, A06:2021 | ✅ |
| PHP-004 | nginx + PHP-FPM RCE 취약 버전 (CVE-2019-11043, KEV) | High | passive | `PHP` | CWE-787, A06:2021 | ✅ |
| PHP-010 | `phpinfo()` 페이지 노출 (위험 설정 함께 표시) | Medium | passive | `PHP` | CWE-200, KISA IL | ✅ |
| PHP-011 | PHP 에러 메시지·서버 경로 노출 (display_errors) | Medium | passive | `PHP` | CWE-209, KISA IL | ✅ |
| PHP-012 | DB 관리 도구 노출 (phpMyAdmin, Adminer) | High | passive | `PHP` | CWE-306, KISA AE | ✅ |
| PHP-013 | 프레임워크 디버그 노출 (Laravel Ignition, Symfony Profiler, Telescope/Horizon) | Critical / High | passive | `PHP` | CWE-489 | ✅ |
| PHP-014 | PHPUnit `eval-stdin.php` 노출 (CVE-2017-9841, KEV) | Critical | passive | `PHP` | CWE-94 | ✅ |
| PHP-015 | PHP-FPM 상태 페이지 노출 | Medium | passive | `PHP` | CWE-200, KISA IL | ✅ |
| PHP-016 | Composer 의존성 파일 노출 | Low | passive | `PHP` | CWE-200, KISA IL | ✅ |
| PHP-017 | `.user.ini` / `php.ini` 노출 | Medium | passive | `PHP` | CWE-538, KISA IL | ✅ |

## 판단 기준 메모

- **soft 404 방지**: 대상마다 존재하지 않는 경로를 한 번 요청해 기준선으로 삼고, 기준선과 같은 응답은 "없음"으로 본다. 모든 노출 점검은 상태 코드가 아닌 **내용 표식**(예: `.git/HEAD` 의 `ref: refs/`)으로 판단한다.
- **비밀값 비기록**: `.env`, 백업 파일 등은 근거에 본문을 넣지 않고, `.env` 는 키 **이름**만 기록한다.
- **PHP 점검 대상 판별**: 기본 페이지에 PHP 흔적(`X-Powered-By: PHP`, `PHPSESSID`, `.php` 링크)이 있거나 `targets.tags` 에 `php` 가 있을 때만 경로 탐색을 한다. 버전을 숨긴 PHP 서버는 `tags: [php]` 를 지정하십시오.
- **PHP 버전 판단** (기준일 2026-11-03, 출처 [php.net supported-versions](https://www.php.net/supported-versions), [2026 보안 권고](https://www.php.net/archive/2026.php)):
  - 버전 출처 우선순위: `phpinfo()` > `X-Powered-By` > `Server` 헤더.
  - `8.1.2-1ubuntu2.14` 처럼 배포판 빌드 표시가 있으면 백포트 가능성을 비고에 명시한다 (버전만으로 확정 불가).
  - PHP2Shell 은 8.1 이하에 공식 수정 릴리스가 없으므로 해당 브랜치는 취약으로 본다.
  - CVE-2024-4577 은 Windows 흔적(Server 헤더 Win32/Win64/IIS, phpinfo System)이 있을 때만, CVE-2019-11043 은 nginx 일 때만 보고한다.
  - 새 PHP 보안 릴리스가 나오면 `internal/checks/php/version.go` 의 표와 이 기준일을 갱신한다.
- **active 레벨로 남겨둔 것**: 파라미터 변조로 에러를 유도하는 점검, 업로드 웹셸 실행 여부 확인 등은 데이터 변경·공격 요청이 필요하므로 M2 이후 `active` 점검으로 별도 구현한다.
- **세션 쿠키 판별**: 이름에 `session`, `sessid`, `jsessionid`, `sid`, `token`, `auth` 등이 포함된 쿠키만 대상으로 한다.
- **버전 노출**: `Server` 헤더에 `숫자.숫자` 형태가 있거나 `X-Powered-By`, `X-AspNet-Version` 헤더가 있으면 보고한다.
- 리다이렉트를 따라간 **최종 응답**을 기준으로 판단하며, 최종 URL 이 `Target` 으로 기록된다.
