#!/bin/sh
set -eu
cd "$(dirname "$0")"
mkdir -p build
SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
if ! find "$SDKROOT/System/Library/Frameworks/EndpointSecurity.framework" -name '*.tbd' -print -quit 2>/dev/null | grep -q .; then
  if [ "${PLATFORM_MACOS_ALLOW_COMPILE_ONLY:-false}" != "true" ]; then
    echo "EndpointSecurity.framework is not linkable in SDK: $SDKROOT" >&2
    exit 4
  fi
  xcrun --sdk macosx clang -isysroot "$SDKROOT" \
    -F "$SDKROOT/System/Library/Frameworks" \
    -fobjc-arc -fblocks -Wall -Wextra -Werror -mmacosx-version-min=13.0 \
    -fsyntax-only main.m
  echo "Endpoint Security source validation passed; hosted SDK has no linkable framework stub."
  exit 0
fi
xcrun --sdk macosx clang -isysroot "$SDKROOT" \
  -F "$SDKROOT/System/Library/Frameworks" \
  -fobjc-arc -fblocks -Wall -Wextra -Werror -mmacosx-version-min=13.0 \
  -framework Foundation -framework EndpointSecurity main.m -o build/platform-es-collector
codesign --force --options runtime --entitlements platform-es-collector.entitlements \
  --sign "${PLATFORM_MACOS_SIGNING_IDENTITY:--}" build/platform-es-collector
codesign --verify --strict --verbose=2 build/platform-es-collector
