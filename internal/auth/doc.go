// Package auth 는 폼 로그인, 세션 쿠키 유지, 세션 만료 감지 후 재로그인을 담당한다 (M2).
//
// 비밀번호는 scope.yaml 의 password_env 로 지정한 환경변수 또는 OS 키체인에서만 읽으며
// DB·로그·리포트에 평문으로 남기지 않는다. 로그아웃 URL 은 scope 의 제외 경로로 회피한다.
package auth
