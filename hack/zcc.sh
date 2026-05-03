#!/usr/bin/env bash

ZIG_TARGET=""
ZIG_SYSROOT=""

ZIG_MACOS_SDK=${ZIG_MACOS_SDK:-"./MacOS.sdk"}

ZIG_CMD="zig cc"
ZIG_BUILD_FLAGS="-D_FORTIFY_SOURCE=3 -O3 -fstack-protector-strong -fcf-protection=full -fPIC"
ZIG_BUILD_LDFLAGS="-Wl,-s -Wl,-z,relro,-z,now"

# Check the name of the command used to invoke this script
if [ "$(basename "$0")" = "zcxx.sh" ]; then
    ZIG_CMD="zig c++"
fi

# Map Go's OS and Arch to Zig's targets
case "$GOOS-$GOARCH" in
    "linux-386")     ZIG_TARGET="x86-linux-gnu" ;;
    "linux-amd64")   ZIG_TARGET="x86_64-linux-gnu" ;;
    "linux-arm64")   ZIG_TARGET="aarch64-linux-gnu" ;;
    "windows-386")   ZIG_TARGET="x86-windows-gnu" ;;
    "windows-amd64") ZIG_TARGET="x86_64-windows-gnu" ;;
    "windows-arm64") ZIG_TARGET="aarch64-windows-gnu" ;;
    "darwin-amd64")  
        ZIG_TARGET="x86_64-macos-gnu"
        ZIG_SYSROOT="-isysroot $ZIG_MACOS_SDK" 
        ;;
    "darwin-arm64")  
        ZIG_TARGET="aarch64-macos-gnu"
        ZIG_SYSROOT="-isysroot $ZIG_MACOS_SDK" 
        ;;
    *)
        echo "Unsupported target: $GOOS-$GOARCH"
        exit 1
        ;;
esac

# Execute the correct compiler dynamically
exec $ZIG_CMD $ZIG_BUILD_FLAGS $ZIG_BUILD_LDFLAGS -target $ZIG_TARGET $ZIG_SYSROOT "$@"
