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

# 설치 직후에는 이미 열려 있던 콘솔의 PATH 에 Go/Node 가 없다. 레지스트리의 최신 PATH 를 다시 읽고,
# 그래도 없으면 기본 설치 경로를 찾아 이 세션에만 추가한다.
if (-not (Get-Command go -ErrorAction SilentlyContinue) -or -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}
$fallback = @{
    go  = @("$env:ProgramFiles\Go\bin", "$env:USERPROFILE\sdk\go\bin")
    npm = @("$env:ProgramFiles\nodejs")
}
foreach ($tool in 'go', 'npm') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        $dir = $fallback[$tool] | Where-Object { Test-Path (Join-Path $_ "$tool*") } | Select-Object -First 1
        if ($dir) { $env:Path = "$dir;$env:Path" }
    }
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        $hint = @{ go = 'https://go.dev/dl/'; npm = 'https://nodejs.org/ (LTS)' }[$tool]
        throw "$tool 을(를) 찾을 수 없습니다. 설치($hint) 후 PowerShell 창을 새로 열고 다시 실행하십시오."
    }
}
Write-Host ("go: " + (go version)) -ForegroundColor DarkGray

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
