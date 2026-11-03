import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

// 빌드 결과(web/dist)는 Go 바이너리에 go:embed 로 내장된다.
// 개발 시: `intrasec serve --no-browser` 실행 후 `npm run dev` (API 는 7777 로 프록시)
export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: 'dist',
    emptyOutDir: false, // dist/.gitkeep 보존
    assetsInlineLimit: 0, // CSP(default-src 'self') 를 위해 data: 인라인 대신 파일로
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:7777' },
  },
})
