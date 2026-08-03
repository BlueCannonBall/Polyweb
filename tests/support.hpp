#ifndef POLYWEB_TESTS_SUPPORT_HPP_
#define POLYWEB_TESTS_SUPPORT_HPP_

#include "Polynet/polynet.hpp"
#include <algorithm>
#include <cstring>
#include <limits>
#include <system_error>
#include <vector>

class ScriptedConnection : public pn::tcp::Connection {
public:
    std::vector<char> input;
    std::vector<char> output;
    size_t input_cursor = 0;
    size_t chunk_size = 1;
    size_t send_count = 0;
    size_t recv_count = 0;
    size_t send_error_after = std::numeric_limits<size_t>::max();
    size_t recv_error_after = std::numeric_limits<size_t>::max();

    ScriptedConnection(std::vector<char> input = {}, size_t chunk_size = 1):
        input(std::move(input)),
        chunk_size(chunk_size) {}

    pn::Result<size_t> send(const void* buf, size_t len) override {
        if (send_count++ >= send_error_after) {
            return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "scripted send"});
        }
        const char* first = (const char*) buf;
        size_t sent = std::min(len, chunk_size);
        output.insert(output.end(), first, first + sent);
        return sent;
    }

    pn::Result<size_t> recv(void* buf, size_t len) override {
        if (recv_count++ >= recv_error_after) {
            return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "scripted receive"});
        }
        size_t available = input.size() - input_cursor;
        size_t received = std::min({len, available, chunk_size});
        memcpy(buf, input.data() + input_cursor, received);
        input_cursor += received;
        return received;
    }

    pn::Result<size_t> peek(void* buf, size_t len) override {
        if (recv_count++ >= recv_error_after) {
            return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "scripted peek"});
        }
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
