#ifndef POLYWEB_TESTS_SUPPORT_HPP_
#define POLYWEB_TESTS_SUPPORT_HPP_

#include "Polynet/polynet.hpp"
#include <algorithm>
#include <cstring>
#include <vector>

class ScriptedConnection : public pn::tcp::Connection {
public:
    std::vector<char> input;
    std::vector<char> output;
    size_t input_cursor = 0;
    size_t chunk_size = 1;

    ScriptedConnection(std::vector<char> input = {}, size_t chunk_size = 1):
        input(std::move(input)),
        chunk_size(chunk_size) {}

    pn::Result<size_t> send(const void* buf, size_t len) override {
        const char* first = (const char*) buf;
        output.insert(output.end(), first, first + len);
        return len;
    }

    pn::Result<size_t> recv(void* buf, size_t len) override {
        size_t available = input.size() - input_cursor;
        size_t received = std::min({len, available, chunk_size});
        memcpy(buf, input.data() + input_cursor, received);
        input_cursor += received;
        return received;
    }

    pn::Result<size_t> peek(void* buf, size_t len) override {
        size_t available = input.size() - input_cursor;
        size_t received = std::min({len, available, chunk_size});
        memcpy(buf, input.data() + input_cursor, received);
        return received;
    }
};

inline std::vector<char> to_bytes(pn::StringView string) {
    return {string.begin(), string.end()};
}

inline std::string to_string(const std::vector<char>& bytes) {
    return {bytes.begin(), bytes.end()};
}

#endif
