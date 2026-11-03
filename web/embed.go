// Package web 은 Svelte UI 빌드 결과(web/dist)를 바이너리에 내장한다.
// `make web` 으로 빌드하지 않으면 dist 에는 .gitkeep 만 있으며, 서버는 안내 페이지를 보여준다.
package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist 는 UI 파일 시스템과, 빌드된 UI(index.html)가 있는지 여부를 돌려준다.
func Dist() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		return nil, false
	}
	_, err = fs.Stat(sub, "index.html")
	return sub, err == nil
}
