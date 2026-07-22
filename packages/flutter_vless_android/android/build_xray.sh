#!/bin/bash
set -euo pipefail

# Configuration
XRAY_REPO="https://github.com/XTLS/Xray-core"
XRAY_VERSION="${XRAY_VERSION:-v26.7.11}"
TARGET_DIR="${TARGET_DIR:-../../../android_runtime/xray_android/src/main/jniLibs}"
NDK_PATH="${ANDROID_NDK_HOME:-$HOME/Library/Android/sdk/ndk/28.2.13676358}"

# Check NDK
if [ ! -d "$NDK_PATH" ]; then
    echo "Error: NDK not found at $NDK_PATH"
    echo "Please export ANDROID_NDK_HOME pointing to your NDK installation."
    exit 1
fi

echo "Using NDK at: $NDK_PATH"

# MacOS NDK Toolchain path
case "$(uname -s)" in
    Darwin) TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/darwin-x86_64" ;;
    Linux) TOOLCHAIN="${NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64" ;;
    *) echo "Error: unsupported host OS $(uname -s)"; exit 1 ;;
esac
if [ ! -d "$TOOLCHAIN" ]; then
    echo "Error: NDK toolchain not found at $TOOLCHAIN"
    echo "Are you on macOS? If not, please edit the script to match your OS."
    exit 1
fi

# Clone Xray if not exists
if [ ! -d "Xray-core" ]; then
    echo "Cloning Xray-core..."
    git clone "$XRAY_REPO"
else
    echo "Xray-core directory exists, pulling latest..."
    cd Xray-core && git fetch --tags && cd ..
fi

cd Xray-core
git fetch --tags
git checkout "$XRAY_VERSION"
cd ..

# Build Function
build_xray() {
    local ARCH_NAME=$1
    local GO_ARCH=$2
    local GO_ARM=$3
    local ANDROID_TARGET=$4
    local OUTPUT_DIR="${TARGET_DIR}/${ARCH_NAME}"

    echo "Building for ${ARCH_NAME}..."
    
    mkdir -p "$OUTPUT_DIR"

    export CGO_ENABLED=1
    export GOOS=android
    export GOARCH=$GO_ARCH
    export GOARM=$GO_ARM
    
    export CC="${TOOLCHAIN}/bin/${ANDROID_TARGET}-clang"
    export CXX="${TOOLCHAIN}/bin/${ANDROID_TARGET}-clang++"
    
    # 16KB page size support for Android 15+
    export LDFLAGS="-Wl,-z,max-page-size=16384"
    
    # Verify compiler exists
    if [ ! -f "$CC" ]; then
        echo "Error: Compiler not found at $CC"
        # Try older NDK naming convention if new one fails (API 21 is standard)
        # Some NDKs use specific API levels in clang name
        return 1
    fi

    cd Xray-core
    
    # Build with 16KB page alignment
    if go build -v -trimpath -buildvcs=false \
        -gcflags "all=-l=4" \
        -ldflags "-X github.com/xtls/xray-core/core.build=${XRAY_VERSION} -s -w -buildid= -checklinkname=0 -linkmode=external -extldflags=${LDFLAGS}" \
        -buildmode=pie \
        -o "../${OUTPUT_DIR}/libxray.so" ./main; then
        echo "Success: ${OUTPUT_DIR}/libxray.so created."
    else
        echo "Failed to build for ${ARCH_NAME}"
        return 1
    fi
    
    cd ..
}

# Build for Architectures
# API Level 21 is generally safe for modern Flutter apps (Android 5.0+)

# ARM64
if [ "${XRAY_BUILD_ARM64:-1}" = "1" ]; then
    build_xray "arm64-v8a" "arm64" "" "aarch64-linux-android21"
fi

# ARMv7
if [ "${XRAY_BUILD_ARMV7:-1}" = "1" ]; then
    build_xray "armeabi-v7a" "arm" "7" "armv7a-linux-androideabi21"
fi

# x86 is included in the main runtime AAR.
if [ "${XRAY_BUILD_X86:-1}" = "1" ]; then
    build_xray "x86" "386" "" "i686-linux-android21"
fi

# x86_64 is included in the main runtime AAR.
if [ "${XRAY_BUILD_X86_64:-1}" = "1" ]; then
    build_xray "x86_64" "amd64" "" "x86_64-linux-android21"
fi

echo "Build process finished."
