package common

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/transport"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func init() {
	checks.Register(tlsCheck{now: time.Now})
}

// tlsCheck 는 COMMON-TLS-001~003 을 판단한다. https 대상에만 TLS 핸드셰이크를 수행한다 (HTTP 요청 없음).
type tlsCheck struct {
	now func() time.Time
}

func (tlsCheck) ID() string          { return "COMMON-TLS" }
func (tlsCheck) Name() string        { return "TLS 설정·인증서 점검" }
func (tlsCheck) Level() checks.Level { return checks.Passive }
func (tlsCheck) Tags() []string      { return []string{checks.TagCommon, "tls"} }

// allSuites 는 Go 가 구현한 모든 스위트다. 구버전 프로토콜 협상 성공률을 높이기 위해 사용한다.
func allSuites() []uint16 {
	var ids []uint16
	for _, s := range tls.CipherSuites() {
		ids = append(ids, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		ids = append(ids, s.ID)
	}
	return ids
}

// weakSuiteGroups 는 TLS 1.2 이하에서 허용 여부를 확인할 취약 스위트 묶음이다.
var weakSuiteGroups = []struct {
	name string
	sev  finding.Severity
	ids  []uint16
}{
	{"RC4", finding.SevMedium, []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
	}},
	{"3DES (SWEET32)", finding.SevMedium, []uint16{
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	}},
	{"RSA 키 교환 (전방향 안전성 없음)", finding.SevLow, []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	}},
}

func (c tlsCheck) Run(ctx context.Context, t checks.Target, s *checks.Session) ([]finding.Finding, error) {
	if t.BaseURL.Scheme != "https" {
		return nil, nil
	}
	target := t.BaseURL.Scheme + "://" + t.BaseURL.Host
	base, err := s.HTTP.TLSHandshake(ctx, target, &tls.Config{MinVersion: tls.VersionTLS10, CipherSuites: allSuites()}) //nolint:gosec // 점검용
	if err != nil {
		return nil, fmt.Errorf("TLS 핸드셰이크 실패: %w", err)
	}
	var out []finding.Finding
	ev := finding.Evidence{Request: "TLS ClientHello → " + target}

	// COMMON-TLS-001 구버전 프로토콜
	var old []string
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11} {
		cfg := &tls.Config{MinVersion: v, MaxVersion: v, CipherSuites: allSuites()} //nolint:gosec // 점검용
		if cs, err := s.HTTP.TLSHandshake(ctx, target, cfg); err == nil && cs.Version == v {
			old = append(old, transport.TLSVersionName(v))
		} else if checks.Abort(err) {
			return out, err
		}
	}
	if len(old) > 0 {
		e := ev
		e.Note = "협상 성공: " + strings.Join(old, ", ")
		out = append(out, finding.Finding{
			CheckID: "COMMON-TLS-001", Title: "TLS 1.0/1.1 허용", Severity: finding.SevHigh, Target: target, Evidence: e,
			CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, KISA: []string{"SN"},
			Description: "취약한 구버전 TLS 프로토콜(" + strings.Join(old, ", ") + ")을 허용합니다. BEAST 등 알려진 공격에 노출되며 주요 브라우저와 보안 기준에서 사용이 금지되었습니다.",
			Remediation: "TLS 1.2 이상만 허용하십시오 (Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3, nginx: ssl_protocols TLSv1.2 TLSv1.3, WebLogic: weblogic.security.SSL.minimumProtocolVersion=TLSv1.2).",
		})
	}

	// COMMON-TLS-002 취약 암호화 스위트
	var weak []string
	sev := finding.SevInfo
	for _, g := range weakSuiteGroups {
		cfg := &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12, CipherSuites: g.ids} //nolint:gosec // 점검용
		cs, err := s.HTTP.TLSHandshake(ctx, target, cfg)
		if err != nil {
			if checks.Abort(err) {
				return out, err
			}
			continue
		}
		weak = append(weak, g.name+": "+tls.CipherSuiteName(cs.CipherSuite))
		if g.sev.Rank() > sev.Rank() {
			sev = g.sev
		}
	}
	if len(weak) > 0 {
		e := ev
		e.Note = "협상 성공: " + strings.Join(weak, "; ")
		out = append(out, finding.Finding{
			CheckID: "COMMON-TLS-002", Title: "취약 암호화 스위트 허용", Severity: sev, Target: target, Evidence: e,
			CWE: []string{"CWE-327"}, OWASP: []string{"A02:2021"}, KISA: []string{"SN"},
			Description: "취약하거나 전방향 안전성(PFS)이 없는 암호화 스위트를 허용합니다: " + strings.Join(weak, "; "),
			Remediation: "ECDHE 키 교환과 AES-GCM / CHACHA20-POLY1305 스위트만 허용하고 RC4, 3DES, RSA 키 교환 스위트를 비활성화하십시오. " +
				"설정 예시는 Mozilla SSL Configuration Generator(Intermediate) 를 참고하십시오.",
		})
	}

	// COMMON-TLS-003 인증서
	if f, ok := analyzeCert(target, t.BaseURL.Hostname(), base.PeerCertificates, c.now()); ok {
		f.Evidence.Request = ev.Request
		out = append(out, f)
	}
	return out, nil
}

const certExpireWarnDays = 30

// analyzeCert 는 인증서 체인 문제를 하나의 발견 항목으로 모은다. 심각도는 가장 심각한 문제 기준.
func analyzeCert(target, host string, chain []*x509.Certificate, now time.Time) (finding.Finding, bool) {
	if len(chain) == 0 {
		return finding.Finding{}, false
	}
	leaf := chain[0]
	var issues []string
	sev := finding.SevInfo
	add := func(s finding.Severity, msg string) {
		issues = append(issues, msg)
		if s.Rank() > sev.Rank() {
			sev = s
		}
	}

	switch {
	case now.After(leaf.NotAfter):
		add(finding.SevHigh, "만료됨 ("+leaf.NotAfter.Format("2006-01-02")+")")
	case now.Before(leaf.NotBefore):
		add(finding.SevMedium, "아직 유효하지 않음 (시작 "+leaf.NotBefore.Format("2006-01-02")+")")
	case leaf.NotAfter.Sub(now) < certExpireWarnDays*24*time.Hour:
		add(finding.SevLow, fmt.Sprintf("만료 임박 (%s, %d일 남음)", leaf.NotAfter.Format("2006-01-02"), int(leaf.NotAfter.Sub(now).Hours()/24)))
	}

	// CheckSignatureFrom 은 부모에 CA 플래그를 요구하므로, CA 플래그 없는 자체 서명 서버 인증서도 잡도록 서명을 직접 검증한다.
	selfSigned := bytes.Equal(leaf.RawSubject, leaf.RawIssuer) &&
		leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	if selfSigned {
		add(finding.SevMedium, "자체 서명 인증서")
	} else {
		inter := x509.NewCertPool()
		for _, c := range chain[1:] {
			inter.AddCert(c)
		}
		// 만료 판단은 위에서 했으므로 체인 검증은 유효기간 안의 시각으로 한다.
		at := now
		if at.After(leaf.NotAfter) || at.Before(leaf.NotBefore) {
			at = leaf.NotBefore.Add(time.Minute)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Intermediates: inter, CurrentTime: at}); err != nil {
			add(finding.SevLow, "공인 루트로 검증되지 않는 체인 (사내 CA 사용 시 정상일 수 있음)")
		}
	}

	if err := leaf.VerifyHostname(host); err != nil {
		add(finding.SevMedium, "호스트명 불일치 ("+host+")")
	}

	switch k := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			add(finding.SevMedium, fmt.Sprintf("RSA 키 길이 부족 (%d비트)", k.N.BitLen()))
		}
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			add(finding.SevMedium, fmt.Sprintf("ECDSA 키 길이 부족 (%d비트)", k.Curve.Params().BitSize))
		}
	}
	switch leaf.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		add(finding.SevMedium, "취약한 서명 알고리즘 ("+leaf.SignatureAlgorithm.String()+")")
	}

	if len(issues) == 0 {
		return finding.Finding{}, false
	}
	return finding.Finding{
		CheckID: "COMMON-TLS-003", Title: "서버 인증서 문제", Severity: sev, Target: target,
		Evidence: finding.Evidence{Note: fmt.Sprintf("주체: %s / 발급자: %s / 유효기간: %s ~ %s",
			leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotBefore.Format("2006-01-02"), leaf.NotAfter.Format("2006-01-02"))},
		CWE:         []string{"CWE-295"},
		OWASP:       []string{"A02:2021", "A07:2021"},
		Description: "서버 인증서에 문제가 있습니다: " + strings.Join(issues, "; ") + ". 사용자가 인증서 경고를 무시하는 습관이 생겨 중간자 공격에 취약해집니다.",
		Remediation: "신뢰할 수 있는 CA(또는 전사 배포된 사내 CA)에서 발급한 2048비트 이상 RSA/ECDSA P-256 인증서로 교체하고, 호스트명(SAN)을 일치시키며 만료 전 갱신 절차를 마련하십시오.",
	}, true
}
