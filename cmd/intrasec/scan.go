package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Sangmoo/intrasec/internal/audit"
	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/engine"
	"github.com/Sangmoo/intrasec/internal/report"
	"github.com/Sangmoo/intrasec/internal/scope"
	"github.com/Sangmoo/intrasec/internal/transport"
)

const resultsDir = "results"

func newScanCmd() *cobra.Command {
	var (
		scopePath string
		only      []string
		out       string
		format    string
		auditPath string
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "scope.yaml 기준으로 점검 실행",
		Example: `  intrasec scan -c scope.yaml
  intrasec scan -c scope.yaml --only weblogic,headers -o report.html`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := scope.Load(scopePath)
			if err != nil {
				return err
			}
			sc, err := scope.New(cfg)
			if err != nil {
				return err
			}
			al, err := audit.Open(auditPath)
			if err != nil {
				return fmt.Errorf("감사 로그 열기 실패: %w", err)
			}
			defer func() { _ = al.Close() }()

			selected := checks.Select(only)
			if len(selected) == 0 {
				return fmt.Errorf("--only %v 에 해당하는 점검 항목이 없음", only)
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()

			w := cmd.ErrOrStderr()
			fmt.Fprintf(w, "점검: %s (승인: %s, %s)\n", cfg.Engagement.Name, cfg.Engagement.ApprovedBy, cfg.Engagement.ApprovalRef)
			res, err := engine.Run(ctx, engine.Options{
				Scope: sc,
				HTTP: transport.New(sc, transport.Options{
					RateLimit: cfg.Options.RateLimit,
					Timeout:   time.Duration(cfg.Options.TimeoutSec) * time.Second,
				}),
				Checks: selected,
				Audit:  al,
				Progress: func(p engine.Progress) {
					status := fmt.Sprintf("%d건", p.Findings)
					if p.Err != nil {
						status = "오류: " + p.Err.Error()
					}
					fmt.Fprintf(w, "[%d/%d] %s @ %s — %s\n", p.Done, p.Total, p.CheckID, p.Target, status)
				},
			})
			if err != nil {
				return err
			}

			saved, err := saveResult(res)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "결과 저장: %s (발견 %d건, 오류 %d건)\n", saved, len(res.Findings), len(res.Errors))

			if out != "" {
				f := report.FormatFromPath(out)
				if format != "" {
					if f, err = report.ParseFormat(format); err != nil {
						return err
					}
				}
				if err := report.WriteFile(out, f, res); err != nil {
					return err
				}
				fmt.Fprintf(w, "리포트: %s\n", out)
			}
			if res.Canceled {
				return errors.New("사용자에 의해 중단됨")
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&scopePath, "config", "c", "scope.yaml", "scope 설정 파일")
	cmd.Flags().StringSliceVar(&only, "only", nil, "실행할 점검 (태그 또는 ID 접두사, 쉼표 구분)")
	cmd.Flags().StringVarP(&out, "output", "o", "", "리포트 출력 파일 (확장자로 형식 추정)")
	cmd.Flags().StringVar(&format, "format", "", "리포트 형식 강제 (html|json|md|sarif)")
	cmd.Flags().StringVar(&auditPath, "audit-log", filepath.Join(resultsDir, "audit.log"), "감사 로그 파일")
	return cmd
}

func saveResult(r *engine.Result) (string, error) {
	if err := os.MkdirAll(resultsDir, 0o700); err != nil {
		return "", err
	}
	p := filepath.Join(resultsDir, r.ScanID+".json")
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return p, os.WriteFile(p, b, 0o600)
}
