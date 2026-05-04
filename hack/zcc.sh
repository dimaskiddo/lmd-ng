#!/usr/bin/env bash

ZIG_TARGET=""
ZIG_SYSROOT=""

ZIG_CMD="`which zig`"
if [[ $ZIG_CMD == "" ]]; then
  echo "`date` - ERROR! Zig command not found, please set install Zig and don't forget to expose it on your PATH environment variable!"
  exit 1
fi

ZIG_BUILD_FLAGS="-D_FORTIFY_SOURCE=3 -O3 -fPIC -fstack-protector-strong -fcf-protection=full"
ZIG_BUILD_LDFLAGS="-Wl,-s -Wl,-z,relro,-z,now"

ZIG_MACOS_SDK_VERSION=${ZIG_MACOS_SDK_VERSION:-"12.3"}
ZIG_MACOS_SDK_FILE_PATH=${ZIG_MACOS_SDK_FILE_PATH:-"/tmp/MacOS.sdk"}

# Check the name of the command used to invoke this script
ZIG_CMD_ALIAS="$ZIG_CMD cc"
if [[ "$(basename "$0")" == "zcxx.sh" ]]; then
  ZIG_CMD_ALIAS="$ZIG_CMD c++"
fi

# Check for MacOS SDK files if already exist
if [[ ! -d $ZIG_MACOS_SDK_FILE_PATH ]]; then
  echo "`date` - MacOS SDK file not found..."
  if [[ $GOOS == "darwin" ]]; then
    echo "`date` - Downloading MacOS $ZIG_MACOS_SDK_VERSION SDK file..."

    curl -sS -o /tmp/MacOS.sdk.tar.xz -L \
      https://github.com/joseluisq/macosx-sdks/releases/download/$ZIG_MACOS_SDK_VERSION/MacOSX${ZIG_MACOS_SDK_VERSION}.sdk.tar.xz
    tar -xf /tmp/MacOS.sdk.tar.xz -C /tmp/
    rm -f /tmp/MacOS.sdk.tar.xz

    mv /tmp/MacOSX${ZIG_MACOS_SDK_VERSION}.sdk $ZIG_MACOS_SDK_FILE_PATH
  fi
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
        ZIG_SYSROOT="-isysroot $ZIG_MACOS_SDK_FILE_PATH"
        ;;
    "darwin-arm64")  
        ZIG_TARGET="aarch64-macos-gnu"
        ZIG_SYSROOT="-isysroot $ZIG_MACOS_SDK_FILE_PATH"
        ;;
    *)
        echo "Unsupported target: $GOOS-$GOARCH"
        exit 1
        ;;
esac

# Execute the correct compiler dynamically
exec $ZIG_CMD_ALIAS $ZIG_BUILD_FLAGS $ZIG_BUILD_LDFLAGS -target $ZIG_TARGET $ZIG_SYSROOT "$@"
