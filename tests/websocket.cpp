#include "polyweb.hpp"
#include "support.hpp"
#include "test.hpp"
#include <string>
#include <vector>

TEST(websocket_masked_frame_round_trip) {
    static constexpr char masking_key[] = {1, 2, 3, 4};
    pw::WSMessage sent("Hello, WebSocket!");
    std::vector<char> frame = sent.build(masking_key);
    ScriptedConnection conn(std::move(frame), 2);
    pn::tcp::BufReceiver receiver(3);
    pw::WSMessage received;

    CHECK(received.parse(conn, receiver));
    CHECK(received.opcode == pw::WS_OPCODE_TEXT);
    CHECK(received.to_string() == "Hello, WebSocket!");
}

TEST(websocket_streamed_message_is_fragmented_and_reassembled) {
    unsigned int call_count = 0;
    pw::WSMessage sent([&call_count]() -> std::vector<char> {
        switch (call_count++) {
        case 0: return {'a', 'b'};
        case 1: return {'c', 'd'};
        default: return {};
        }
    }, pw::WS_OPCODE_BINARY);
    ScriptedConnection conn(sent.build(), 1);
    pn::tcp::BufReceiver receiver(2);
    pw::WSMessage received;

    CHECK(received.parse(conn, receiver));
    CHECK(received.opcode == pw::WS_OPCODE_BINARY);
    CHECK(received.to_string() == "abcd");
}

TEST(websocket_message_limit_is_enforced) {
    pw::WSMessage sent("exceeds");
    ScriptedConnection conn(sent.build());
    pn::tcp::BufReceiver receiver;
    pw::WSMessage received;
    pw::WSConfig config;
    config.message_rlimit = 6;

    CHECK(!received.parse(conn, receiver, config));
}

TEST(websocket_close_message_round_trip) {
    pw::WSMessage sent = pw::WSMessage::make_close(1001, "going away");
    ScriptedConnection conn(sent.build());
    pn::tcp::BufReceiver receiver;
    pw::WSMessage received;

    CHECK(received.parse(conn, receiver));
    CHECK(received.opcode == pw::WS_OPCODE_CLOSE);
    CHECK(received.close_status_code() == 1001);
    CHECK(received.close_reason() == "going away");
}
