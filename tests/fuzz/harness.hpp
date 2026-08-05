#ifndef POLYWEB_FUZZ_HARNESS_HPP_
#define POLYWEB_FUZZ_HARNESS_HPP_

#include "polyweb.hpp"
#include <stdint.h>
#include <vector>

// The parsers resume across reads, so how the input arrives is as much a part of the
// input as the bytes are. The first byte steers the delivery and the rest is the message,
// which lets the fuzzer explore a message arriving whole and the same message arriving a
// byte at a time without needing two corpora
namespace fuzz {
    inline std::vector<char> body(const uint8_t* data, size_t size) {
        return std::vector<char>(data + 1, data + size);
    }

    inline size_t chunk_size(uint8_t control) noexcept {
        return (control & 0x3F) + 1;
    }

    inline size_t buf_capacity(uint8_t control) noexcept {
        return ((control >> 6) & 0x3) * 64 + 16;
    }

    // Small enough that the fuzzer spends its time parsing rather than allocating, while
    // still leaving room above the sizes the corpus actually reaches
    inline pw::MessageConfig message_config() {
        pw::MessageConfig config;
        config.header_value_rlimit = 4'000;
        config.body_chunk_rlimit = 16'000;
        config.body_rlimit = 32'000;
        return config;
    }

    inline pw::WSConfig ws_config() {
        pw::WSConfig config;
        config.frame_rlimit = 16'000;
        config.message_rlimit = 32'000;
        return config;
    }
} // namespace fuzz

#endif
