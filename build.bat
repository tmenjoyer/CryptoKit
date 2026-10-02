@echo off
setlocal
where go >nul 2>nul
if errorlevel 1 (
    echo [!] Go is not installed. Download it from https://go.dev/dl/
    exit /b 1
)
echo Running tests...
go test ./... || exit /b 1
echo Building cryptokit.exe ...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64
go build -trimpath -ldflags "-s -w" -o cryptokit.exe . || exit /b 1
echo Done: cryptokit.exe
endlocal
