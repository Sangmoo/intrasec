package weblogic

import (
	"bytes"
	"context"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/Sangmoo/intrasec/internal/checks/checkstest"
	"github.com/Sangmoo/intrasec/pkg/finding"
)

// fakeT3 는 T3 인사·GIOP 요청에 WebLogic 처럼 응답하는 TCP 서버다.
func fakeT3(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				buf := make([]byte, 256)
				n, _ := c.Read(buf)
				switch {
				case bytes.HasPrefix(buf[:n], []byte("t3 ")):
					_, _ = c.Write([]byte("HELO:12.2.1.3.0.false\nAS:2048\nHL:19\nMS:10000000\n\n"))
				case bytes.HasPrefix(buf[:n], []byte("GIOP")):
					_, _ = c.Write([]byte("GIOP\x01\x02\x00\x04\x00\x00\x00\x08\x00\x00\x00\x01\x00\x00\x00\x01"))
				default: // WebLogic 은 같은 포트에서 HTTP 도 처리한다
					_, _ = c.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				}
			}(c)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

func ids(fs []finding.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.CheckID)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestWebLogicExposed(t *testing.T) {
	port := fakeT3(t)
	tgt, s := checkstest.ServeOpts(t, checkstest.Files{
		Headers: map[string]string{"Server": "WebLogic Server 12.2.1.3.0 Thu Aug 17 13:39:49 PDT 2017"},
		Paths: map[string]checkstest.File{
			"/": {ContentType: "text/html", Body: "<html>ERP</html>"},
			"/console/login/LoginForm.jsp": {ContentType: "text/html",
				Body: `<title>Oracle WebLogic Server Administration Console</title><input name="j_username"><p>WebLogic Server Version: 12.2.1.3.0</p>`},
			"/wls-wsat/CoordinatorPortType": {ContentType: "text/html", Body: "<h2>Web Services</h2> CoordinatorPortType"},
		},
	}, checkstest.Opts{Ports: []int{port}})
	fs, err := wlsCheck{}.Run(context.Background(), tgt, s)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(fs); got != "WLS-001,WLS-002,WLS-003,WLS-004" {
		t.Fatalf("got %s", got)
	}
	for _, f := range fs {
		if f.CheckID == "WLS-003" && !strings.Contains(f.Evidence.Note, "IIOP") {
			t.Errorf("IIOP 미검출: %s", f.Evidence.Note)
		}
		if f.CheckID == "WLS-002" && !strings.Contains(f.Evidence.Note, "12.2.1.3.0 (T3 HELO 응답)") {
			t.Errorf("T3 버전 미기록: %s", f.Evidence.Note)
		}
	}
}

func TestNotWebLogicSkipped(t *testing.T) {
	tgt, s := checkstest.Serve(t, checkstest.Files{
		Headers: map[string]string{"Server": "nginx"},
		Paths:   map[string]checkstest.File{"/": {ContentType: "text/html", Body: "<html>hi</html>"}},
	})
	fs, err := wlsCheck{}.Run(context.Background(), tgt, s)
	if err != nil || len(fs) != 0 {
		t.Fatalf("WebLogic 아님: %v %v", ids(fs), err)
	}
}

func TestGIOPRequestShape(t *testing.T) {
	b := giopLocateRequest()
	if !bytes.HasPrefix(b, []byte("GIOP\x01\x02\x00\x03")) || len(b) != 12+23 {
		t.Fatalf("GIOP LocateRequest 형식 오류: % x", b)
	}
}
