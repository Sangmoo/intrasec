// Command intrasec 은 승인된 사내 웹 시스템을 점검하는 로컬 실행형 보안 점검 도구다.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"

	// 점검 플러그인 등록
	_ "github.com/Sangmoo/intrasec/internal/checks/common"
	_ "github.com/Sangmoo/intrasec/internal/checks/php"
)

// 빌드 시 -ldflags 로 주입된다.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "오류:", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "intrasec",
		Short:         "승인된 사내 웹 시스템 보안 점검 도구",
		Long:          "intrasec 은 본인이 관리 권한을 가졌거나 서면 승인을 받은 사내 시스템만 점검해야 합니다.\n모든 점검은 scope.yaml 에 명시된 대상·시간대 안에서만 실행되며 감사 로그가 남습니다.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newServeCmd(),
		newScanCmd(),
		newReportCmd(),
		newChecksCmd(),
		newScopeCmd(),
		newVersionCmd(),
	)
	return root
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "버전 정보 출력",
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "intrasec %s (commit %s, built %s, %s/%s)\n",
				version, commit, date, runtime.GOOS, runtime.GOARCH)
		},
	}
}
