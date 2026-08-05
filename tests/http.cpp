#include "polyweb.hpp"
#include "support.hpp"
#include "test.hpp"
#include <chrono>
#ifndef _WIN32
    #include <netinet/tcp.h>
#endif
#include <openssl/ssl.h>
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

TEST(query_parameters_round_trip) {
    pw::QueryParameters parameters("one=hello+world&empty&encoded=%2Fpath%3F");

    CHECK(parameters->at("one") == "hello world");
    CHECK(parameters->at("empty").empty());
    CHECK(parameters->at("encoded") == "/path?");

    pw::QueryParameters rebuilt(parameters.build());
    CHECK(rebuilt->at("one") == "hello world");
    CHECK(rebuilt->at("empty").empty());
    CHECK(rebuilt->at("encoded") == "/path?");
}

TEST(url_parse_and_build) {
    pw::URLInfo url;
    CHECK(url.parse("https://user:pass@example.com:8443/a/b?x=one+two&y=%2F"));
    CHECK(url.scheme == "https");
    CHECK(url.username() == "user");
    CHECK(url.password() == "pass");
    CHECK(url.hostname() == "example.com");
    CHECK(url.port() == 8443);
    CHECK(url.path == "/a/b");
    CHECK(url.query_parameters->at("x") == "one two");
    CHECK(url.query_parameters->at("y") == "/");
    pw::URLInfo rebuilt;
    CHECK(rebuilt.parse(url.build()));
    CHECK(rebuilt.query_parameters->at("x") == "one two");
    CHECK(rebuilt.query_parameters->at("y") == "/");
}

TEST(http_request_parse_handles_fragmented_input) {
    ScriptedConnection conn(to_bytes("POST /submit?name=codex HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello"));
    pn::tcp::BufReceiver receiver(3);
    pw::Request request;

    CHECK(request.parse(conn, receiver));
    CHECK(request.method == "POST");
    CHECK(request.target == "/submit");
    CHECK(request.query_parameters->at("name") == "codex");
    CHECK(request.headers.at("host") == "example.test");
    CHECK(request.body_to_string() == "hello");
}

TEST(http_request_parse_handles_empty_headers_and_pipelining) {
    ScriptedConnection conn(to_bytes("GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\nHost: example.test\r\n\r\n"), 2);
    pn::tcp::BufReceiver receiver(5);
    pw::Request first;
    pw::Request second;

    CHECK(first.parse(conn, receiver));
    CHECK(first.target == "/one");
    CHECK(first.headers.empty());
    CHECK(second.parse(conn, receiver));
    CHECK(second.target == "/two");
    CHECK(second.headers.at("host") == "example.test");
}

TEST(http_response_parse_handles_fragmentation_and_empty_headers) {
    for (size_t chunk_size = 1; chunk_size <= 8; ++chunk_size) {
        ScriptedConnection conn(to_bytes("HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nhello"), chunk_size);
        pn::tcp::BufReceiver receiver(3);
        pw::Response response;

        CHECK(response.parse(conn, receiver));
        CHECK(response.status_code == 201);
        CHECK(response.reason_phrase == "Created");
        CHECK(response.body_string() == "hello");
    }

    ScriptedConnection conn(to_bytes("HTTP/1.1 204 No Content\r\n\r\n"));
    pn::tcp::BufReceiver receiver;
    pw::Response response;
    CHECK(response.parse(conn, receiver));
    CHECK(response.headers.empty());
}

TEST(http_chunked_receiver_streams_chunks) {
    ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n"), 2);
    pn::tcp::BufReceiver receiver(4);
    pw::RequestReceiver request;
    std::vector<char> body;
    request.recv_cb = [&body](std::vector<char> chunk) {
        body.insert(body.end(), chunk.begin(), chunk.end());
        return true;
    };

    CHECK(request.parse(conn, receiver));
    CHECK(to_string(body) == "onetwo");
}

TEST(http_parsers_reject_malformed_and_limited_messages) {
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nContent-Length: no\r\n\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::Request request;
        CHECK(!request.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabc"));
        pn::tcp::BufReceiver receiver;
        pw::Request request;
        CHECK(!request.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nnope\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::Request request;
        CHECK(!request.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::Request request;
        pw::MessageConfig config;
        config.header_climit = 0;
        CHECK(!request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_ALL, config));
    }
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"));
        pn::tcp::BufReceiver receiver;
        pw::Request request;
        pw::MessageConfig config;
        config.body_rlimit = 4;
        CHECK(!request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_ALL, config));
    }
    {
        ScriptedConnection conn(to_bytes("HTTP/1.1 200x OK\r\n\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::Response response;
        CHECK(!response.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nFFFFFFFFFFFFFFFF\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::Request request;
        CHECK(!request.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nFFFFFFFFFFFFFFFF\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::Response response;
        CHECK(!response.parse(conn, receiver));
    }
}

TEST(http_receiver_stops_when_its_callback_rejects_a_chunk) {
    ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"), 2);
    pn::tcp::BufReceiver receiver(3);
    pw::RequestReceiver request;
    request.recv_cb = [](std::vector<char>) {
        return false;
    };

    CHECK(!request.parse(conn, receiver));
}

TEST(http_chunked_sender_streams_chunks) {
    unsigned int call_count = 0;
    pw::Request request("POST", "/", [&call_count]() -> std::vector<char> {
        switch (call_count++) {
        case 0: return {'o', 'n', 'e'};
        case 1: return {'t', 'w', 'o'};
        default: return {};
        }
    });

    CHECK(request.build_string() == "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n");
}

TEST(http_response_status_category) {
    pw::Response response(204);
    CHECK(response.status_code_category() == 200);
}

TEST(http_client_and_server_loopback) {
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

            pn::tcp::BufReceiver receiver;
            pw::Request request;
            if (pn::Status result = request.parse(connection, receiver); !result) {
                server_error = result.error().message();
                return;
            } else if (request.method != "POST" || request.target != "/echo" || request.body_to_string() != "hello") {
                server_error = "invalid HTTP request";
                return;
            }

            pw::Response response(201, "created", {{"X-Test", "yes"}});
            if (pn::Status result = response.build(connection); !result) {
                server_error = result.error().message();
            }
        }
    });

    pw::Client client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(client.send(pw::Request("POST", "/echo", "hello")));
    pw::Response response;
    CHECK(client.recv(response));

    server_thread.join();
    CHECK(server_error.empty());
    CHECK(response.status_code == 201);
    CHECK(response.headers.at("x-test") == "yes");
    CHECK(response.body_string() == "created");
}

TEST(closing_a_connection_discards_what_it_had_buffered) {
    // Two pipelined responses arrive together, so the second stays in the receiver
    ScriptedConnection conn(to_bytes("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
                                     "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
        4'000); // Delivered in one read, so the second response lands in the receiver
    pw::BasicConnection<ScriptedConnection> connection(std::move(conn), pn::tcp::BufReceiver());

    pw::Response first;
    CHECK(connection.recv(first));
    CHECK(first.status_code == 200);
    CHECK(connection.buf_receiver.available() != 0);

    size_t buffered = connection.buf_receiver.available();

    // A layer above the byte stream, such as the WebSocket one, leaves it intact
    CHECK(connection.close(PW_PROTOCOL_LAYER_WS));
    CHECK(connection.buf_receiver.available() == buffered);

    // Closing the transport makes it stale, and serving that leftover to whatever this
    // object is used for next would attribute one connection's response to another
    CHECK(connection.close());
    CHECK(connection.buf_receiver.available() == 0);
}

TEST(the_default_tls_context_is_built_once_and_shared) {
    // Every request that does not bring its own context must land on the same one,
    // including when the first several arrive together and race to build it
    std::vector<const pn::TLSContext*> resolved(8);
    std::vector<std::thread> threads;
    for (size_t i = 0; i < resolved.size(); ++i) {
        threads.emplace_back([&resolved, i] {
            pw::ClientConfig config;
            if (pn::Result<const pn::TLSContext*> result = config.resolve_tls_context()) {
                resolved[i] = *result;
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }

    CHECK(resolved.front());
    CHECK(resolved.front()->is_valid());
    for (const pn::TLSContext* context : resolved) {
        CHECK(context == resolved.front());
    }
}

TEST(a_client_config_prefers_the_tls_context_it_is_given) {
    pn::TLSContext context;
    CHECK(context.init_client(SSL_VERIFY_NONE));

    pw::ClientConfig config;
    config.tls_context = &context;

    pn::Result<const pn::TLSContext*> resolved = config.resolve_tls_context();
    CHECK(resolved);
    CHECK(*resolved == &context);
}

TEST(a_connection_config_applies_the_options_it_names) {
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    // Connected, since TCP_NODELAY means nothing on a socket that is not
    pn::tcp::Client client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));

    pw::ConnectionConfig config;
    config.recv_timeout = std::chrono::milliseconds(1'500);
    config.tcp_no_delay = false;
    config.tcp_keep_alive = true;
    CHECK(config.apply(client));

#ifdef _WIN32
    DWORD recv_timeout = 0;
#else
    struct timeval recv_timeout = {};
#endif
    socklen_t length = sizeof recv_timeout;
    CHECK(::getsockopt(client.fd, SOL_SOCKET, SO_RCVTIMEO, (char*) &recv_timeout, &length) == PN_OK);
#ifdef _WIN32
    CHECK(recv_timeout == 1'500);
#else
    // Milliseconds have to survive the trip through timeval's split seconds and microseconds
    CHECK(recv_timeout.tv_sec == 1);
    CHECK(recv_timeout.tv_usec == 500'000);
#endif

    int no_delay = -1;
    length = sizeof no_delay;
    CHECK(::getsockopt(client.fd, IPPROTO_TCP, TCP_NODELAY, (char*) &no_delay, &length) == PN_OK);
    CHECK(no_delay == 0);

    int keep_alive = -1;
    length = sizeof keep_alive;
    CHECK(::getsockopt(client.fd, SOL_SOCKET, SO_KEEPALIVE, (char*) &keep_alive, &length) == PN_OK);
    CHECK(keep_alive != 0);

    // A server's defaults have to leave the socket waiting rather than expiring at once
    CHECK(pw::ServerConfig().tcp.apply(client));
    length = sizeof recv_timeout;
    CHECK(::getsockopt(client.fd, SOL_SOCKET, SO_RCVTIMEO, (char*) &recv_timeout, &length) == PN_OK);
#ifdef _WIN32
    CHECK(recv_timeout == 0);
#else
    CHECK(recv_timeout.tv_sec == 0);
    CHECK(recv_timeout.tv_usec == 0);
#endif
}

TEST(a_server_imposes_no_timeout_of_its_own) {
    // A WebSocket idles between messages by design, and handle_conn cannot tell an idle
    // keep-alive connection from a client that sent nothing, so a server waits instead
    pw::ConnectionConfig config;
    CHECK(config.recv_timeout == std::chrono::milliseconds(0));
    CHECK(config.send_timeout == std::chrono::milliseconds(0));

    // A server takes that as it comes, rather than overriding it the way a client does
    pw::ServerConfig server_config;
    CHECK(server_config.tcp.recv_timeout == std::chrono::milliseconds(0));
    CHECK(server_config.tcp.send_timeout == std::chrono::milliseconds(0));

    // The options that cost a connection nothing are still set for it
    CHECK(server_config.tcp.tcp_no_delay);
    CHECK(server_config.tcp.tcp_keep_alive);

    // A client makes one request and knows what it is waiting for
    pw::ClientConfig client_config;
    CHECK(client_config.tcp.recv_timeout == std::chrono::seconds(30));
    CHECK(client_config.tcp.send_timeout == std::chrono::seconds(30));
}
