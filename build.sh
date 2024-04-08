#!/bin/sh

BASE="$(pwd)"

cd "$BASE/server/ui-src" && npm install
cd "$BASE/server/ui-src" && npm run build

cd "$BASE" && go build -ldflags "-s -w"
