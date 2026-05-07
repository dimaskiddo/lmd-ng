#!/usr/bin/env bash

ZIG_TARGET=""
ZIG_SYSROOT=""

ZIG_CMD="`which zig`"
if [[ $ZIG_CMD == "" ]]; then
  echo "`date` - ERROR! Zig command not found, please set install Zig and don't forget to expose it on your PATH environment variable!"
  exit 1
fi

ZIG_TARGET_LIBC=${ZIG_TARGET_LIBC:-"gnu"}

ZIG_BUILD_FLAGS="-D_FORTIFY_SOURCE=3 -O3 -fPIC -fstack-protector-strong -Wformat -Werror=format-security -Wno-missing-noreturn -Wno-unreachable-code-break -Wno-nullability-completeness -Wno-expansion-to-defined -Wno-macro-redefined"
ZIG_BUILD_LDFLAGS="-Wl,-s -Wl,-z,relro,-z,now"

ZIG_MACOS_SDK_VERSION=${ZIG_MACOS_SDK_VERSION:-"12.3"}
ZIG_MACOS_SDK_FILE_URL=${ZIG_MACOS_SDK_FILE_URL:-"https://oss.dimaskiddo.my.id/public.dimaskiddo.my.id/macos/sdk/MacOSX-${ZIG_MACOS_SDK_VERSION}.sdk.tar.xz"}
ZIG_MACOS_SDK_FILE_PATH=${ZIG_MACOS_SDK_FILE_PATH:-"/tmp/MacOSX.sdk"}

# Check the name of the command used to invoke this script
ZIG_CMD_ALIAS="$ZIG_CMD cc"
if [[ "$(basename "$0")" == "zcxx.sh" ]]; then
  ZIG_CMD_ALIAS="$ZIG_CMD c++"
fi

# Check architecture for CET / BTI build flags
if [[ "$GOARCH" == "amd64" ]] || [[ "$GOARCH" == "386" ]]; then
  # Intel/AMD protection (Control-Flow Enforcement)
  ZIG_BUILD_FLAGS="$ZIG_BUILD_FLAGS -fcf-protection=full"
elif [[ "$GOARCH" == "arm64" ]]; then
  # ARM protection (Pointer Authentication & Branch Target Identification)
  ZIG_BUILD_FLAGS="$ZIG_BUILD_FLAGS -mbranch-protection=standard"
fi

# Check of build for MacOS, since it need it's own SDK
if [[ $GOOS == "darwin" ]]; then
  # Check for MacOS SDK files if already exist
  if [[ ! -d $ZIG_MACOS_SDK_FILE_PATH ]]; then
    echo "`date` - Downloading MacOS $ZIG_MACOS_SDK_VERSION SDK file..."

    curl -sS -o /tmp/MacOSX.sdk.tar.xz -L $ZIG_MACOS_SDK_FILE_URL
    tar -xf /tmp/MacOSX.sdk.tar.xz -C /tmp/
    rm -f /tmp/MacOSX.sdk.tar.xz

    mv /tmp/MacOSX${ZIG_MACOS_SDK_VERSION}.sdk $ZIG_MACOS_SDK_FILE_PATH
  fi
fi

# Map Go's OS and Arch to Zig's targets
case "$GOOS-$GOARCH" in
  "linux-386")     ZIG_TARGET="x86-linux-$ZIG_TARGET_LIBC" ;;
  "linux-amd64")   ZIG_TARGET="x86_64-linux-$ZIG_TARGET_LIBC" ;;
  "linux-arm64")   ZIG_TARGET="aarch64-linux-$ZIG_TARGET_LIBC" ;;
  "windows-386")   ZIG_TARGET="x86-windows-gnu" ;;
  "windows-amd64") ZIG_TARGET="x86_64-windows-gnu" ;;
  "windows-arm64") ZIG_TARGET="aarch64-windows-gnu" ;;
  "darwin-amd64")  
    ZIG_TARGET="x86_64-macos"
    ZIG_SYSROOT="-isysroot $ZIG_MACOS_SDK_FILE_PATH -iframework $ZIG_MACOS_SDK_FILE_PATH/System/Library/Frameworks -F $ZIG_MACOS_SDK_FILE_PATH/System/Library/Frameworks -I $ZIG_MACOS_SDK_FILE_PATH/usr/include -L $ZIG_MACOS_SDK_FILE_PATH/usr/lib"
    ;;
  "darwin-arm64")  
    ZIG_TARGET="aarch64-macos"
    ZIG_SYSROOT="-isysroot $ZIG_MACOS_SDK_FILE_PATH -iframework $ZIG_MACOS_SDK_FILE_PATH/System/Library/Frameworks -F $ZIG_MACOS_SDK_FILE_PATH/System/Library/Frameworks -I $ZIG_MACOS_SDK_FILE_PATH/usr/include -L $ZIG_MACOS_SDK_FILE_PATH/usr/lib"
    ;;
  *)
    echo "Unsupported target: $GOOS-$GOARCH"
    exit 1
    ;;
esac

# Execute the correct compiler dynamically
exec $ZIG_CMD_ALIAS $ZIG_BUILD_FLAGS $ZIG_BUILD_LDFLAGS -target $ZIG_TARGET $ZIG_SYSROOT "$@"
