#include "polyweb.hpp"
#include "support.hpp"
#include "test.hpp"
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
    pw::HTTPRequest request;

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
    pw::HTTPRequest first;
    pw::HTTPRequest second;

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
        pw::HTTPResponse response;

        CHECK(response.parse(conn, receiver));
        CHECK(response.status_code == 201);
        CHECK(response.reason_phrase == "Created");
        CHECK(response.body_string() == "hello");
    }

    ScriptedConnection conn(to_bytes("HTTP/1.1 204 No Content\r\n\r\n"));
    pn::tcp::BufReceiver receiver;
    pw::HTTPResponse response;
    CHECK(response.parse(conn, receiver));
    CHECK(response.headers.empty());
}

TEST(http_chunked_receiver_streams_chunks) {
    ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n"), 2);
    pn::tcp::BufReceiver receiver(4);
    pw::HTTPRequestReceiver request;
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
        pw::HTTPRequest request;
        CHECK(!request.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabc"));
        pn::tcp::BufReceiver receiver;
        pw::HTTPRequest request;
        CHECK(!request.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nnope\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::HTTPRequest request;
        CHECK(!request.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::HTTPRequest request;
        pw::HTTPMessageConfig config;
        config.header_climit = 0;
        CHECK(!request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_ALL, config));
    }
    {
        ScriptedConnection conn(to_bytes("GET / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello"));
        pn::tcp::BufReceiver receiver;
        pw::HTTPRequest request;
        pw::HTTPMessageConfig config;
        config.body_rlimit = 4;
        CHECK(!request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_ALL, config));
    }
    {
        ScriptedConnection conn(to_bytes("HTTP/1.1 200x OK\r\n\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::HTTPResponse response;
        CHECK(!response.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nFFFFFFFFFFFFFFFF\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::HTTPRequest request;
        CHECK(!request.parse(conn, receiver));
    }
    {
        ScriptedConnection conn(to_bytes("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\nFFFFFFFFFFFFFFFF\r\n"));
        pn::tcp::BufReceiver receiver;
        pw::HTTPResponse response;
        CHECK(!response.parse(conn, receiver));
    }
}

TEST(http_receiver_stops_when_its_callback_rejects_a_chunk) {
    ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc"), 2);
    pn::tcp::BufReceiver receiver(3);
    pw::HTTPRequestReceiver request;
    request.recv_cb = [](std::vector<char>) {
        return false;
    };

    CHECK(!request.parse(conn, receiver));
}

TEST(http_chunked_sender_streams_chunks) {
    unsigned int call_count = 0;
    pw::HTTPRequest request("POST", "/", [&call_count]() -> std::vector<char> {
        switch (call_count++) {
        case 0: return {'o', 'n', 'e'};
        case 1: return {'t', 'w', 'o'};
        default: return {};
        }
    });

    CHECK(request.build_string() == "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n");
}

TEST(http_response_status_category) {
    pw::HTTPResponse response(204);
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
            pw::HTTPRequest request;
            if (pn::Status result = request.parse(connection, receiver); !result) {
                server_error = result.error().message();
                return;
            } else if (request.method != "POST" || request.target != "/echo" || request.body_to_string() != "hello") {
                server_error = "invalid HTTP request";
                return;
            }

            pw::HTTPResponse response(201, "created", {{"X-Test", "yes"}});
            if (pn::Status result = response.build(connection); !result) {
                server_error = result.error().message();
            }
        }
    });

    pw::Client client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(client.send(pw::HTTPRequest("POST", "/echo", "hello")));
    pw::HTTPResponse response;
    CHECK(client.recv(response));

    server_thread.join();
    CHECK(server_error.empty());
    CHECK(response.status_code == 201);
    CHECK(response.headers.at("x-test") == "yes");
    CHECK(response.body_string() == "created");
}
