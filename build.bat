@echo off
rem 一键编译全平台版本，产物在 dist\ 目录
cd /d "%~dp0"

if not exist dist\windows-amd64 mkdir dist\windows-amd64
if not exist dist\linux-amd64 mkdir dist\linux-amd64
if not exist dist\linux-arm64 mkdir dist\linux-arm64

echo [1/3] Windows amd64  -^> dist\windows-amd64\dig.exe
set GOOS=windows
set GOARCH=amd64
go build -trimpath -ldflags "-s -w" -o dist\windows-amd64\dig.exe .

echo [2/3] Linux amd64    -^> dist\linux-amd64\dig
set GOOS=linux
go build -trimpath -ldflags "-s -w" -o dist\linux-amd64\dig .

echo [3/3] Linux arm64    -^> dist\linux-arm64\dig
set GOARCH=arm64
go build -trimpath -ldflags "-s -w" -o dist\linux-arm64\dig .

echo Done.
