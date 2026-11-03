package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/Sangmoo/intrasec/internal/audit"
	"github.com/Sangmoo/intrasec/internal/server"
	"github.com/Sangmoo/intrasec/internal/store"
	"github.com/Sangmoo/intrasec/web"
)

func newServeCmd() *cobra.Command {
	var (
		port      int
		noBrowser bool
		dbPath    string
		auditPath string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "로컬 웹 UI 실행 (127.0.0.1 전용)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := store.Open(dbPath)
			if err != nil {
				return fmt.Errorf("DB 열기 실패: %w", err)
			}
			defer func() { _ = st.Close() }()
			al, err := audit.Open(auditPath)
			if err != nil {
				return fmt.Errorf("감사 로그 열기 실패: %w", err)
			}
			defer func() { _ = al.Close() }()
			cfg := server.Config{Version: version, Store: st, Audit: al}
			if ui, ok := web.Dist(); ok {
				cfg.UI = ui
			} else {
				fmt.Fprintln(cmd.ErrOrStderr(), "주의: 웹 UI 가 포함되지 않은 실행 파일입니다 (go build 로 직접 빌드한 경우). 릴리스 zip 을 쓰거나 .\\build.ps1 (macOS/Linux: make build) 로 빌드하십시오.")
			}
			s, err := server.New(cfg)
			if err != nil {
				return err
			}
			hs := s.HTTPServer(port)
			// 포트를 먼저 확보한 뒤 브라우저를 연다. 포트가 사용 중이면 다른 프로그램 화면이 열리지 않도록 여기서 멈춘다.
			ln, err := net.Listen("tcp", hs.Addr)
			if err != nil {
				return fmt.Errorf("%s 를 사용할 수 없습니다 (다른 프로그램이 사용 중일 수 있음). --port 로 다른 포트를 지정하십시오: %w", hs.Addr, err)
			}
			// 토큰은 URL 프래그먼트로 전달해 서버 로그·Referer 에 남지 않게 한다.
			uiURL := fmt.Sprintf("http://127.0.0.1:%d/#token=%s", port, s.Token)
			fmt.Fprintf(cmd.ErrOrStderr(), "intrasec UI: %s\n(Ctrl+C 로 종료)\n", uiURL)
			if !noBrowser {
				openBrowser(uiURL)
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			errc := make(chan error, 1)
			go func() { errc <- hs.Serve(ln) }()
			select {
			case err := <-errc:
				if !errors.Is(err, http.ErrServerClosed) {
					return err
				}
			case <-ctx.Done():
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return hs.Shutdown(shutdownCtx)
		},
	}
	cmd.Flags().IntVar(&port, "port", server.DefaultPort, "로컬 포트 (127.0.0.1 에만 바인딩)")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "브라우저 자동 실행 안 함")
	cmd.Flags().StringVar(&dbPath, "db", filepath.Join(resultsDir, "intrasec.db"), "SQLite DB 파일")
	cmd.Flags().StringVar(&auditPath, "audit-log", filepath.Join(resultsDir, "audit.log"), "감사 로그 파일")
	return cmd
}

func openBrowser(u string) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		c = exec.Command("open", u)
	default:
		c = exec.Command("xdg-open", u)
	}
	_ = c.Start()
}
