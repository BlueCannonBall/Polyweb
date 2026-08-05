#!/bin/sh
# Builds one libFuzzer binary per target, with the address and undefined sanitizers on.
# Needs clang. Polybuild does not reach in here, since Polybuild.toml names the source
# directories it compiles rather than walking them.
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

LIB="../../polyweb.cpp ../../server.cpp ../../client.cpp ../../websocket.cpp ../../string.cpp \
     ../../error.cpp ../../Polynet/polynet.cpp ../../Polynet/tls.cpp ../../Polynet/error.cpp"

for target in ${@:-http_request http_response websocket url decoders}; do
    printf 'Building %s...\n' "$target"
    clang++ -std=c++23 -g -O1 \
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
        -I. -I.. -I../.. -I../../Polynet \
        "$target.cpp" $LIB -lssl -lcrypto -o "$target"
    mkdir -p "corpus/$target"
done
