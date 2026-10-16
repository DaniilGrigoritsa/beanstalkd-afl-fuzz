#!/bin/bash
# Builds the fuzzing binaries of beanstalkd from one source tree (beanstalkd-afl/)
# usage: ./build_targets.sh
set -eu
CC=$PWD/AFLplusplus/afl-clang-fast
FLAGS="-DFUZZ_EXIT_ON_CLOSE -DFUZZ_DETERMINISTIC"

build() {
  local variant=$1 extra=$2; shift 2
  echo "[*] building $variant"
  make -C beanstalkd-afl clean >/dev/null
  env "$@" make -C beanstalkd-afl CC="$CC" CFLAGS="$FLAGS $extra" LDFLAGS="$extra" USE_SYSTEMD=no -j4 >/dev/null
  if [ "$variant" != plain ]; then
    mkdir -p "targets/$variant"
    cp beanstalkd-afl/beanstalkd "targets/$variant/beanstalkd"
  fi
}

# UBSan without the nonnull-attribute check: ms.c grow() calls memcpy(dst, NULL, 0) for every empty
# array (at start-up and for every connection).
UBSAN="-fsanitize=undefined -fno-sanitize=nonnull-attribute -fno-sanitize-recover=undefined -fno-omit-frame-pointer"
build asan-ubsan "$UBSAN" AFL_USE_ASAN=1
build msan "" AFL_USE_MSAN=1
build plain "" AFL_QUIET=1
