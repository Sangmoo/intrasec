package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/Sangmoo/intrasec/internal/server"
)

func newServeCmd() *cobra.Command {
	var (
		port      int
		noBrowser bool
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "로컬 웹 UI 실행 (127.0.0.1 전용)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := server.New(version)
			if err != nil {
				return err
			}
			hs := s.HTTPServer(port)
			// 토큰은 URL 프래그먼트로 전달해 서버 로그·Referer 에 남지 않게 한다.
			uiURL := fmt.Sprintf("http://127.0.0.1:%d/#token=%s", port, s.Token)
			fmt.Fprintf(cmd.ErrOrStderr(), "intrasec UI: %s\n(Ctrl+C 로 종료)\n", uiURL)
			if !noBrowser {
				openBrowser(uiURL)
			}

			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
			defer stop()
			errc := make(chan error, 1)
			go func() { errc <- hs.ListenAndServe() }()
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
	cmd.Flags().IntVar(&port, "port", 8080, "로컬 포트")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "브라우저 자동 실행 안 함")
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
