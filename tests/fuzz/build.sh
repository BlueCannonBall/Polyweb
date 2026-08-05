#!/bin/sh
# Builds one libFuzzer binary per target, with the address and undefined sanitizers on.
# Needs clang 20 or newer; set CXX to choose one. Polybuild does not reach in here,
# since Polybuild.toml names the source directories it compiles rather than walking them.
#
# Builds every target, or just the ones named:
#   ./build.sh                # all five
#   ./build.sh http_request   # only this one, which is what CI wants per job
#
# Run one target with:
#   ./build.sh http_request && ./http_request corpus/http_request seeds/http_request \
#       -max_total_time=60
#
# The first directory is where libFuzzer keeps what it finds, the second is read only, so
# the seeds stay as they were written. All five at once, which is how they were last run:
#   for t in http_request http_response websocket url decoders; do
#       ./$t corpus/$t seeds/$t -max_total_time=60 & done; wait
set -e
cd "$(dirname "$0")"

# CI points this at a newer clang than the distribution ships
: "${CXX:=clang++}"

LIB="../../polyweb.cpp ../../server.cpp ../../client.cpp ../../websocket.cpp ../../string.cpp \
     ../../error.cpp ../../Polynet/polynet.cpp ../../Polynet/tls.cpp ../../Polynet/error.cpp"

# Clang 18 as Ubuntu ships it cannot reach std::expected in the libstdc++ beside it, even
# though that libstdc++ has it and GCC compiles it happily, and its libc++ has no
# std::move_only_function. Neither standard library is enough, so there is nothing to fall
# back to. Clang 20 with the system libstdc++ handles both. Say so here rather than let it
# fail later as a wall of template errors
if ! printf '#include <expected>\n#include <functional>\nint main() {
        std::expected<int, int> e {1};
        std::move_only_function<int() const> f = [] { return 2; };
        return *e + f();
    }\n' | "$CXX" -std=c++23 -x c++ - -o /dev/null 2>/dev/null; then
    printf '%s cannot compile std::expected and std::move_only_function together.\n' "$CXX" >&2
    printf 'Clang 20 with the system libstdc++ can; Clang 18 cannot, with either library.\n' >&2
    printf 'Set CXX to a newer clang, as CI does.\n' >&2
    exit 1
fi

for target in ${@:-http_request http_response websocket url decoders}; do
    printf 'Building %s...\n' "$target"
    "$CXX" -std=c++23 -g -O1 \
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
        -I. -I.. -I../.. -I../../Polynet \
        "$target.cpp" $LIB -lssl -lcrypto -o "$target"
    mkdir -p "corpus/$target"
done
