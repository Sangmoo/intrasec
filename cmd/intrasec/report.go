package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Sangmoo/intrasec/internal/report"
)

func newReportCmd() *cobra.Command {
	var scanID, format, out string
	cmd := &cobra.Command{
		Use:     "report",
		Short:   "저장된 점검 결과로 리포트 재생성",
		Example: "  intrasec report --scan-id 20261110-190000-a1b2c3 --format html -o out.html",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if scanID == "" || filepath.Base(scanID) != scanID {
				return errors.New("--scan-id 가 올바르지 않음")
			}
			f, err := report.ParseFormat(format)
			if err != nil {
				return err
			}
			res, err := report.LoadResult(filepath.Join(resultsDir, scanID+".json"))
			if err != nil {
				return err
			}
			if out == "" {
				out = filepath.Join(resultsDir, scanID+"."+string(f))
			}
			if err := report.WriteFile(out, f, res); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "리포트: %s\n", out)
			return nil
		},
	}
	cmd.Flags().StringVar(&scanID, "scan-id", "", "점검 ID (results/<id>.json)")
	cmd.Flags().StringVar(&format, "format", "html", "html|json|md|sarif")
	cmd.Flags().StringVarP(&out, "output", "o", "", "출력 파일")
	_ = cmd.MarkFlagRequired("scan-id")
	return cmd
}
