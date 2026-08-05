#include "polyweb.hpp"
#include "support.hpp"
#include "test.hpp"
#include <limits>
#include <string>
#include <thread>
#include <vector>

namespace {
    uint16_t listening_port(const pn::tcp::Server& server) {
        struct sockaddr_in address = {};
        socklen_t address_length = sizeof address;
        CHECK(::getsockname(server.fd, (struct sockaddr*) &address, &address_length) == PN_OK);
        return ntohs(address.sin_port);
    }

    pn::Status set_socket_timeout(pn::Socket& socket) {
#ifdef _WIN32
        DWORD timeout = 10'000;
#else
        struct timeval timeout = {10, 0};
#endif
        if (pn::Status result = socket.setsockopt(SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout); !result) {
            return result;
        }
        return socket.setsockopt(SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);
    }
} // namespace

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
    },
        pw::WS_OPCODE_BINARY);
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

TEST(websocket_extended_payload_lengths_round_trip) {
    for (size_t size : {125u, 126u, 65'535u, 65'536u}) {
        std::vector<char> payload(size);
        for (size_t i = 0; i < payload.size(); ++i) {
            payload[i] = i;
        }

        pw::WSMessage sent(payload);
        ScriptedConnection conn(sent.build(), 17);
        pn::tcp::BufReceiver receiver(31);
        pw::WSMessage received;

        CHECK(received.parse(conn, receiver));
        CHECK(received.opcode == pw::WS_OPCODE_BINARY);
        CHECK(received.data == payload);
    }
}

TEST(websocket_rejects_truncated_and_oversized_frames) {
    {
        std::vector<char> frame = {(char) 0x82, 126, 0, 10, 'a', 'b', 'c'};
        ScriptedConnection conn(std::move(frame));
        pn::tcp::BufReceiver receiver;
        pw::WSMessage message;
        CHECK(!message.parse(conn, receiver));
    }
    {
        std::vector<char> frame = {(char) 0x82, 127, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF, (char) 0xFF};
        ScriptedConnection conn(std::move(frame));
        pn::tcp::BufReceiver receiver;
        pw::WSMessage message;
        pw::WSConfig config;
        config.message_rlimit = std::numeric_limits<size_t>::max();
        CHECK(!message.parse(conn, receiver, config));
    }
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

TEST(websocket_connection_automatically_replies_to_control_messages) {
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    std::string server_error;
    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        if (pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length); fd == PN_INVALID_SOCKFD) {
            server_error = pn::make_last_socket_error("accept test connection").message();
            return;
        } else {
            pn::tcp::Connection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
                return;
            }

            pw::WSMessage ping("still there?", pw::WS_OPCODE_PING);
            if (pn::Status result = ping.build(connection); !result) {
                server_error = result.error().message();
                return;
            }

            pn::tcp::BufReceiver receiver;
            pw::WSMessage pong;
            if (pn::Status result = pong.parse(connection, receiver); !result) {
                server_error = result.error().message();
                return;
            } else if (pong.opcode != pw::WS_OPCODE_PONG || pong.to_string() != "still there?") {
                server_error = "invalid WebSocket pong";
                return;
            }

            pw::WSMessage close = pw::WSMessage::make_close(1000, "bye");
            if (pn::Status result = close.build(connection); !result) {
                server_error = result.error().message();
                return;
            }

            pw::WSMessage echoed_close;
            if (pn::Status result = echoed_close.parse(connection, receiver); !result) {
                server_error = result.error().message();
            } else if (echoed_close.opcode != pw::WS_OPCODE_CLOSE || echoed_close.data != close.data) {
                server_error = "invalid WebSocket close reply";
            }
        }
    });

    pw::WSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    pw::WSMessage ping;
    CHECK(client.recv(ping));
    CHECK(ping.opcode == pw::WS_OPCODE_PING);
    pw::WSMessage close;
    CHECK(client.recv(close));
    CHECK(close.opcode == pw::WS_OPCODE_CLOSE);
    CHECK(client.ws_closed);

    server_thread.join();
    CHECK(server_error.empty());
}
