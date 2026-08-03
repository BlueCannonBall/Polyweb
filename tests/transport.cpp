#include "support.hpp"
#include "test.hpp"
#include <array>

TEST(sendall_handles_partial_writes) {
    ScriptedConnection conn({}, 2);
    static constexpr char input[] = "abcdef";

    if (pn::Result<size_t> result = conn.sendall(input, sizeof input - 1); !result) {
        test::fail(result.error().message().c_str(), __FILE__, __LINE__);
    } else {
        CHECK(*result == sizeof input - 1);
    }
    CHECK(to_string(conn.output) == input);
    CHECK(conn.send_count == 3);
}

TEST(sendall_reports_immediate_errors_and_preserves_partial_progress) {
    static constexpr char input[] = "abcdef";

    ScriptedConnection immediate_error({}, 2);
    immediate_error.send_error_after = 0;
    CHECK(!immediate_error.sendall(input, sizeof input - 1));

    ScriptedConnection partial_error({}, 2);
    partial_error.send_error_after = 1;
    if (pn::Result<size_t> result = partial_error.sendall(input, sizeof input - 1); !result) {
        test::fail(result.error().message().c_str(), __FILE__, __LINE__);
    } else {
        CHECK(*result == 2);
    }
    CHECK(to_string(partial_error.output) == "ab");
}

TEST(recvall_handles_partial_reads_eof_and_errors) {
    std::array<char, 6> output;
    ScriptedConnection partial(to_bytes("abcdef"), 2);
    if (pn::Result<size_t> result = partial.recvall(output.data(), output.size()); !result) {
        test::fail(result.error().message().c_str(), __FILE__, __LINE__);
    } else {
        CHECK(*result == output.size());
    }
    CHECK(std::string(output.begin(), output.end()) == "abcdef");

    ScriptedConnection eof(to_bytes("abc"), 2);
    if (pn::Result<size_t> result = eof.recvall(output.data(), output.size()); !result) {
        test::fail(result.error().message().c_str(), __FILE__, __LINE__);
    } else {
        CHECK(*result == 3);
    }

    ScriptedConnection immediate_error({}, 2);
    immediate_error.recv_error_after = 0;
    CHECK(!immediate_error.recvall(output.data(), output.size()));
}

TEST(buf_receiver_peek_rewind_and_buffer_boundaries) {
    ScriptedConnection conn(to_bytes("abcdef"), 4);
    pn::tcp::BufReceiver receiver(4);
    std::array<char, 3> output;

    CHECK(receiver.peek(conn, output.data(), 2));
    CHECK(std::string(output.data(), 2) == "ab");
    CHECK(receiver.recv(conn, output.data(), 2));
    CHECK(std::string(output.data(), 2) == "ab");

    receiver.rewind("Z", 1);
    CHECK(receiver.recvall(conn, output.data(), output.size()));
    CHECK(std::string(output.data(), output.size()) == "Zcd");

    CHECK(receiver.recv(conn, output.data(), 2));
    CHECK(std::string(output.data(), 2) == "ef");
}
