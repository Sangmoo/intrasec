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
		safe      bool
		dryRun    bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "scope.yaml 기준으로 점검 실행",
		Example: `  intrasec scan -c scope.yaml
  intrasec scan -c scope.yaml --only weblogic,headers -o report.html
  intrasec scan -c scope.yaml --safe --dry-run     # 운영 시스템: 실행 계획만 확인
  intrasec scan -c scope.yaml --safe -o report.html`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := scope.Load(scopePath)
			if err != nil {
				return err
			}
			if safe {
				if cfg.Options.ActiveChecks {
					fmt.Fprintln(cmd.ErrOrStderr(), "--safe: active_checks 를 비활성화합니다")
				}
				cfg.Options.SafeMode, cfg.Options.ActiveChecks = true, false
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

			w := cmd.ErrOrStderr()
			if dryRun {
				plan, err := engine.NewPlan(sc, selected, time.Now())
				if err != nil {
					return err
				}
				printPlan(cmd.OutOrStdout(), cfg, plan)
				return nil
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()

			fmt.Fprintf(w, "점검: %s (승인: %s, %s)\n", cfg.Engagement.Name, cfg.Engagement.ApprovedBy, cfg.Engagement.ApprovalRef)
			if cfg.Options.SafeMode {
				e := cfg.Options.Effective()
				fmt.Fprintf(w, "운영 안전 모드: 초당 %v요청, 동시 %d, 호스트당 최대 %d요청, 연속 5xx %d회 시 일시정지, passive 전용\n",
					e.RateLimit, e.Concurrency, e.MaxRequestsPerTarget, e.PauseOn5xx)
			}
			client := transport.NewFromScope(sc, nil)
			auths, err := buildAuth(cfg, client, al)
			if err != nil {
				return err
			}
			res, err := engine.Run(ctx, engine.Options{
				Scope:  sc,
				HTTP:   client,
				Auth:   auths,
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
	cmd.Flags().BoolVar(&safe, "safe", false, "운영 안전 모드 (scope.yaml 의 options.safe_mode: true 와 동일)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "요청을 보내지 않고 실행 계획만 출력")
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
