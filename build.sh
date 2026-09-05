#!/usr/bin/env bash
# 一键编译全平台版本，产物在 dist/ 目录
set -e
cd "$(dirname "$0")"

mkdir -p dist/windows-amd64 dist/linux-amd64 dist/linux-arm64

echo "[1/3] Windows amd64  -> dist/windows-amd64/dig.exe"
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/windows-amd64/dig.exe .

echo "[2/3] Linux amd64    -> dist/linux-amd64/dig"
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/linux-amd64/dig .

echo "[3/3] Linux arm64    -> dist/linux-arm64/dig"
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/linux-arm64/dig .

echo "Done."
