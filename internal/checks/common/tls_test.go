package common

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Sangmoo/intrasec/internal/checks/checkstest"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

func selfSigned(t *testing.T, cn string, notBefore, notAfter time.Time, ips ...net.IP) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnalyzeCert(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		cert     *x509.Certificate
		host     string
		sev      finding.Severity
		contains []string
	}{
		{"만료+자체서명", selfSigned(t, "erp.example.local", now.AddDate(-2, 0, 0), now.AddDate(0, 0, -1)), "erp.example.local",
			finding.SevHigh, []string{"만료됨", "자체 서명"}},
		{"만료 임박", selfSigned(t, "erp.example.local", now.AddDate(-1, 0, 0), now.AddDate(0, 0, 10)), "erp.example.local",
			finding.SevMedium, []string{"만료 임박", "자체 서명"}},
		{"호스트명 불일치", selfSigned(t, "other.example.local", now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0)), "erp.example.local",
			finding.SevMedium, []string{"호스트명 불일치"}},
	}
	for _, c := range cases {
		f, ok := analyzeCert("https://x", c.host, []*x509.Certificate{c.cert}, now)
		if !ok {
			t.Errorf("%s: 미검출", c.name)
			continue
		}
		if f.Severity != c.sev {
			t.Errorf("%s: 심각도 want %s got %s", c.name, c.sev, f.Severity)
		}
		for _, s := range c.contains {
			if !strings.Contains(f.Description, s) {
				t.Errorf("%s: %q 없음: %s", c.name, s, f.Description)
			}
		}
	}
}

func runTLS(t *testing.T, cfg *tls.Config) map[string]finding.Finding {
	t.Helper()
	tgt, s := checkstest.ServeTLS(t, http.NotFoundHandler(), cfg)
	fs, err := tlsCheck{now: time.Now}.Run(context.Background(), tgt, s)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]finding.Finding{}
	for _, f := range fs {
		m[f.CheckID] = f
	}
	return m
}

func TestTLSLegacyServer(t *testing.T) {
	got := runTLS(t, &tls.Config{
		MinVersion: tls.VersionTLS10,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
	})
	if f, ok := got["COMMON-TLS-001"]; !ok || !strings.Contains(f.Evidence.Note, "TLS 1.0") {
		t.Errorf("TLS 1.0 허용 미검출: %+v", f)
	}
	if f, ok := got["COMMON-TLS-002"]; !ok || !strings.Contains(f.Evidence.Note, "3DES") {
		t.Errorf("3DES 허용 미검출: %+v", f)
	}
	if _, ok := got["COMMON-TLS-003"]; !ok {
		t.Error("httptest 자체 서명 인증서 미검출")
	}
}

func TestTLSModernServer(t *testing.T) {
	got := runTLS(t, &tls.Config{MinVersion: tls.VersionTLS12})
	for _, id := range []string{"COMMON-TLS-001", "COMMON-TLS-002"} {
		if f, ok := got[id]; ok {
			t.Errorf("%s 오탐: %s", id, f.Evidence.Note)
		}
	}
}
