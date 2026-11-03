package main

import (
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/Sangmoo/intrasec/internal/audit"
	"github.com/Sangmoo/intrasec/internal/auth"
	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
)

// passwordFromEnvOrPrompt 는 환경변수를 먼저 보고, 없으면 터미널에서 화면에 표시하지 않고 입력받는다.
func passwordFromEnvOrPrompt(env, prompt string) (string, error) {
	if v, ok := os.LookupEnv(env); ok {
		return v, nil
	}
	fd := int(os.Stdin.Fd()) //nolint:gosec // 표준 입력 fd 는 int 범위
	if !term.IsTerminal(fd) {
		return "", nil
	}
	fmt.Fprintf(os.Stderr, "%s (%s 환경변수 없음): ", prompt, env)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

func buildAuth(cfg *scope.Config, c *transport.Client, al *audit.Logger) ([]engine.Authenticator, error) {
	var out []engine.Authenticator
	for _, a := range cfg.Auth {
		f, err := auth.New(a, c, al, passwordFromEnvOrPrompt)
		if err != nil {
			return nil, fmt.Errorf("auth (%s): %w", a.Target, err)
		}
		out = append(out, f)
	}
	return out, nil
}
