#!/usr/bin/env bash

ZIG_TARGET=""

SYSROOT=""
MACOS_SDK=${MACOS_SDK:-"./MacOS.sdk"}

ZIG_CMD="zig cc"

# Check the name of the command used to invoke this script
if [ "$(basename "$0")" = "zcxx.sh" ]; then
    ZIG_CMD="zig c++"
fi

# Map Go's OS and Arch to Zig's targets
case "$GOOS-$GOARCH" in
    "linux-amd64")   ZIG_TARGET="x86_64-linux-gnu" ;;
    "linux-arm64")   ZIG_TARGET="aarch64-linux-gnu" ;;
    "windows-amd64") ZIG_TARGET="x86_64-windows-gnu" ;;
    "darwin-amd64")  
        ZIG_TARGET="x86_64-macos-gnu"
        SYSROOT="-isysroot $MACOS_SDK" 
        ;;
    "darwin-arm64")  
        ZIG_TARGET="aarch64-macos-gnu"
        SYSROOT="-isysroot $MACOS_SDK" 
        ;;
    *)
        echo "Unsupported target: $GOOS-$GOARCH"
        exit 1
        ;;
esac

# Execute the correct compiler dynamically
exec $ZIG_CMD -target $ZIG_TARGET $SYSROOT "$@"
