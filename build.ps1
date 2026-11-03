# Windows 용 빌드 스크립트 (make 없이 사용)
#   .\build.ps1          웹 UI 빌드 → bin\intrasec.exe 생성
#   .\build.ps1 -Run     빌드 후 바로 웹 UI 실행 (http://127.0.0.1:7777)
#
# 필요: Go 1.27+ (https://go.dev/dl/), Node.js 22+ (https://nodejs.org/)
param(
    [switch]$Run,
    [int]$Port = 7777
)
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

foreach ($tool in 'go', 'npm') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool 이(가) 설치되어 있지 않습니다. README 의 '개발 환경 준비'를 참고하십시오."
    }
}

Write-Host '[1/2] 웹 UI 빌드 (web\dist)' -ForegroundColor Cyan
Push-Location web
try {
    npm ci --no-fund --no-audit
    if ($LASTEXITCODE -ne 0) { throw 'npm ci 실패' }
    npm run build
    if ($LASTEXITCODE -ne 0) { throw 'npm run build 실패' }
} finally {
    Pop-Location
}

Write-Host '[2/2] Go 빌드 (bin\intrasec.exe)' -ForegroundColor Cyan
$version = (git describe --tags --always --dirty 2>$null)
if (-not $version) { $version = 'dev' }
$commit = (git rev-parse --short HEAD 2>$null)
if (-not $commit) { $commit = 'none' }
$date = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$env:CGO_ENABLED = '0'
go build -trimpath -ldflags "-s -w -X main.version=$version -X main.commit=$commit -X main.date=$date" -o bin\intrasec.exe .\cmd\intrasec
if ($LASTEXITCODE -ne 0) { throw 'go build 실패' }

Write-Host "완료: bin\intrasec.exe ($version)" -ForegroundColor Green
if ($Run) {
    .\bin\intrasec.exe serve --port $Port
}
