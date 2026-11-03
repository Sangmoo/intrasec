// Package scope 는 scope.yaml 을 파싱·검증하고, 모든 요청의 허용 여부를 판단한다.
package scope

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Engagement   Engagement `yaml:"engagement"`
	Targets      []Target   `yaml:"targets"`
	Allow        Allow      `yaml:"allow"`
	ExcludePaths []string   `yaml:"exclude_paths"`
	Auth         []Auth     `yaml:"auth"`
	Options      Options    `yaml:"options"`
}

type Engagement struct {
	Name        string `yaml:"name"`
	ApprovedBy  string `yaml:"approved_by"`
	ApprovalRef string `yaml:"approval_ref"`
	Window      Window `yaml:"window"`
}

type Window struct {
	Start time.Time `yaml:"start"`
	End   time.Time `yaml:"end"`
}

type Target struct {
	Name    string   `yaml:"name"`
	BaseURL string   `yaml:"base_url"`
	Ports   []int    `yaml:"ports"`
	Tags    []string `yaml:"tags"`
}

type Allow struct {
	CIDRs []string `yaml:"cidrs"`
}

// Auth 는 대상별 인증 설정이다. 비밀번호는 평문으로 두지 않고 환경변수 이름만 받는다.
type Auth struct {
	Target        string `yaml:"target"`
	Type          string `yaml:"type"`
	LoginURL      string `yaml:"login_url"`
	UsernameField string `yaml:"username_field"`
	PasswordField string `yaml:"password_field"`
	Username      string `yaml:"username"`
	PasswordEnv   string `yaml:"password_env"`
}

type Options struct {
	RateLimit    float64 `yaml:"rate_limit"`
	Concurrency  int     `yaml:"concurrency"`
	ActiveChecks bool    `yaml:"active_checks"`
	TimeoutSec   int     `yaml:"timeout_sec"`
}

const (
	DefaultRateLimit   = 5
	DefaultConcurrency = 4
	DefaultTimeoutSec  = 15
	MaxRateLimit       = 50
	MaxConcurrency     = 32
)

// Load 는 파일을 읽어 파싱·기본값 적용·검증까지 수행한다.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse 는 YAML을 엄격 모드(알 수 없는 필드 거부)로 파싱한다.
// `password:` 처럼 평문 비밀번호 필드를 넣으면 여기서 거부된다.
func Parse(b []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("scope 파싱 실패: %w", err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Options.RateLimit == 0 {
		c.Options.RateLimit = DefaultRateLimit
	}
	if c.Options.Concurrency == 0 {
		c.Options.Concurrency = DefaultConcurrency
	}
	if c.Options.TimeoutSec == 0 {
		c.Options.TimeoutSec = DefaultTimeoutSec
	}
}

// Validate 는 설정의 모든 오류를 모아서 반환한다.
func (c *Config) Validate() error {
	var errs []error
	add := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	e := c.Engagement
	if strings.TrimSpace(e.Name) == "" {
		add("engagement.name 필수")
	}
	if strings.TrimSpace(e.ApprovedBy) == "" {
		add("engagement.approved_by 필수 (승인자 없이 점검 불가)")
	}
	if strings.TrimSpace(e.ApprovalRef) == "" {
		add("engagement.approval_ref 필수 (결재문서번호 등)")
	}
	if e.Window.Start.IsZero() || e.Window.End.IsZero() {
		add("engagement.window.start/end 필수")
	} else if !e.Window.End.After(e.Window.Start) {
		add("engagement.window.end 는 start 이후여야 함")
	}

	if len(c.Targets) == 0 {
		add("targets 가 비어 있음")
	}
	names := map[string]bool{}
	for i, t := range c.Targets {
		if t.Name == "" {
			add("targets[%d].name 필수", i)
		} else if names[t.Name] {
			add("targets[%d].name 중복: %s", i, t.Name)
		}
		names[t.Name] = true
		u, err := url.Parse(t.BaseURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			add("targets[%d].base_url 이 올바른 http(s) URL이 아님: %q", i, t.BaseURL)
		}
		for _, p := range t.Ports {
			if p < 1 || p > 65535 {
				add("targets[%d].ports 범위 오류: %d", i, p)
			}
		}
	}

	if len(c.Allow.CIDRs) == 0 {
		add("allow.cidrs 가 비어 있음 (허용 IP 대역 필수)")
	}
	for _, s := range c.Allow.CIDRs {
		if _, err := netip.ParsePrefix(s); err != nil {
			add("allow.cidrs 형식 오류: %q", s)
		}
	}

	for i, a := range c.Auth {
		if !names[a.Target] {
			add("auth[%d].target 이 targets 에 없음: %q", i, a.Target)
		}
		if a.Type != "form" {
			add("auth[%d].type 지원하지 않음: %q (form 만 지원)", i, a.Type)
		}
		if a.PasswordEnv == "" {
			add("auth[%d].password_env 필수 (비밀번호는 환경변수로 전달)", i)
		}
	}

	o := c.Options
	if o.RateLimit < 0 || o.RateLimit > MaxRateLimit {
		add("options.rate_limit 은 0~%d 범위", MaxRateLimit)
	}
	if o.Concurrency < 1 || o.Concurrency > MaxConcurrency {
		add("options.concurrency 는 1~%d 범위", MaxConcurrency)
	}
	if o.TimeoutSec < 1 {
		add("options.timeout_sec 는 1 이상")
	}

	return errors.Join(errs...)
}
