package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/Sangmoo/intrasec/internal/checks"
	"github.com/Sangmoo/intrasec/internal/scope"
)

func newChecksCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "checks", Short: "점검 항목 관리"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "등록된 점검 항목 목록",
		Run: func(cmd *cobra.Command, _ []string) {
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tLEVEL\tTAGS\tNAME")
			for _, c := range checks.All() {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID(), c.Level(), strings.Join(c.Tags(), ","), c.Name())
			}
			_ = tw.Flush()
		},
	})
	return cmd
}

func newScopeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scope", Short: "scope 설정 관리"}
	var path string
	validate := &cobra.Command{
		Use:   "validate",
		Short: "scope.yaml 검증",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := scope.Load(path)
			if err != nil {
				return err
			}
			w := cmd.OutOrStdout()
			fmt.Fprintf(w, "OK: %s\n", cfg.Engagement.Name)
			fmt.Fprintf(w, "  승인: %s (%s)\n", cfg.Engagement.ApprovedBy, cfg.Engagement.ApprovalRef)
			fmt.Fprintf(w, "  시간대: %s ~ %s\n", cfg.Engagement.Window.Start, cfg.Engagement.Window.End)
			for _, t := range cfg.Targets {
				fmt.Fprintf(w, "  대상: %s %s %v\n", t.Name, t.BaseURL, t.Tags)
			}
			fmt.Fprintf(w, "  허용 대역: %v\n", cfg.Allow.CIDRs)
			fmt.Fprintf(w, "  active_checks: %v, rate_limit: %v/s, concurrency: %d\n",
				cfg.Options.ActiveChecks, cfg.Options.RateLimit, cfg.Options.Concurrency)
			return nil
		},
	}
	validate.Flags().StringVarP(&path, "config", "c", "scope.yaml", "scope 설정 파일")
	cmd.AddCommand(validate)
	return cmd
}
