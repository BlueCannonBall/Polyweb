#include "polyweb.hpp"
#include "support.hpp"
#include "test.hpp"
#include <atomic>
#include <chrono>
#ifndef _WIN32
    #include <netinet/tcp.h>
#endif
#include <openssl/ssl.h>
#include <stdexcept>
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

    // Winsock writes a single byte for a boolean option rather than a whole int, so the
    // value starts at zero: a sentinel would survive in the bytes getsockopt never touches
    bool socket_flag(pn::sockfd_t fd, int level, int option) {
        int value = 0;
        socklen_t length = sizeof value;
        CHECK(::getsockopt(fd, level, option, (char*) &value, &length) == PN_OK);
        return value;
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

TEST(query_parameters_keep_everything_after_the_first_equals) {
    pw::QueryParameters parameters("token=YWJjZA==&next=/a?b=c&=novalue");

    CHECK(parameters->at("token") == "YWJjZA==");
    CHECK(parameters->at("next") == "/a?b=c");
    CHECK(parameters->at("") == "novalue");

    pw::QueryParameters rebuilt(parameters.build());
    CHECK(rebuilt->at("token") == "YWJjZA==");
    CHECK(rebuilt->at("next") == "/a?b=c");
    CHECK(rebuilt->at("") == "novalue");
}

TEST(query_parameters_build_spaces_as_pluses) {
    pw::QueryParameters parameters;
    (*parameters)["q"] = "hello world";
    CHECK(parameters.build() == "q=hello+world");

    parameters.plus_as_space = false;
    CHECK(parameters.build() == "q=hello%20world");

    // A plus of its own is escaped either way, or it would come back as a space
    (*parameters)["q"] = "a+b";
    CHECK(parameters.build() == "q=a%2Bb");
    parameters.plus_as_space = true;
    CHECK(parameters.build() == "q=a%2Bb");
    CHECK(pw::QueryParameters(parameters.build())->at("q") == "a+b");
}

TEST(request_build_carries_plus_as_space_to_the_wire) {
    pw::Request request;
    request.method = "GET";
    request.target = "/search";
    (*request.query_parameters)["q"] = "hello world";

    CHECK(request.build_string(PW_HTTP_MESSAGE_PART_START_LINE) == "GET /search?q=hello+world HTTP/1.1\r\n");

    request.query_parameters.plus_as_space = false;
    CHECK(request.build_string(PW_HTTP_MESSAGE_PART_START_LINE) == "GET /search?q=hello%20world HTTP/1.1\r\n");
}

TEST(url_parse_excludes_fragments) {
    pw::URLInfo url;
    CHECK(url.parse("https://example.com/path?x=1#frag"));
    CHECK(url.path == "/path");
    CHECK(url.query_parameters->at("x") == "1");

    CHECK(url.parse("https://example.com/path#frag"));
    CHECK(url.path == "/path");
    CHECK(url.query_parameters->empty()); // Parsing again must not leave the last URL's parameters behind

    CHECK(url.parse("https://example.com/p#a?b=c")); // The question mark belongs to the fragment
    CHECK(url.path == "/p");
    CHECK(url.query_parameters->empty());
}

TEST(url_parse_handles_missing_path) {
    pw::URLInfo url;
    CHECK(url.parse("https://example.com?x=1"));
    CHECK(url.host == "example.com");
    CHECK(url.path == "/");
    CHECK(url.query_parameters->at("x") == "1");

    CHECK(url.parse("https://example.com#frag"));
    CHECK(url.host == "example.com");
    CHECK(url.path == "/");
    CHECK(url.query_parameters->empty());

    CHECK(!url.parse("https://")); // A URL without a host is not a URL
    CHECK(!url.parse("https:///path"));
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

TEST(url_path_is_decoded_and_survives_a_request) {
    pw::URLInfo url;
    CHECK(url.parse("https://example.com/files/my%20report.pdf"));
    CHECK(url.path == "/files/my report.pdf"); // Decoded, exactly as pw::Request keeps its target
    CHECK(url.build() == "https://example.com/files/my%20report.pdf");
    CHECK(url.path_with_query_parameters() == "/files/my%20report.pdf");

    // Handing the path to a request must not encode it a second time
    pw::Request request;
    request.method = "GET";
    request.target = url.path;
    CHECK(request.build_string(PW_HTTP_MESSAGE_PART_START_LINE) == "GET /files/my%20report.pdf HTTP/1.1\r\n");

    // A plus in a path is a plus, not a space, on the way in and on the way out
    CHECK(url.parse("https://example.com/a+b"));
    CHECK(url.path == "/a+b");
    CHECK(url.build() == "https://example.com/a%2Bb");
}

TEST(http_request_parse_keeps_equals_signs_in_query_values) {
    ScriptedConnection conn(to_bytes("GET /search?token=YWJjZA==&next=/a?b=c HTTP/1.1\r\nHost: example.test\r\n\r\n"));
    pn::tcp::BufReceiver receiver(64);
    pw::Request request;

    CHECK(request.parse(conn, receiver));
    CHECK(request.target == "/search");
    CHECK(request.query_parameters->at("token") == "YWJjZA==");
    CHECK(request.query_parameters->at("next") == "/a?b=c");
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

TEST(http_receiver_discards_only_what_is_left_of_a_body) {
    ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nContent-Length: 6\r\n\r\nabcdefGET /next HTTP/1.1\r\n\r\n"), 4);
    pn::tcp::BufReceiver receiver(4);
    pw::MessageConfig config;
    config.body_chunk_rlimit = 3;

    pw::RequestReceiver request;
    CHECK(request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_HEAD, config));

    // A callback which throws takes its chunk off the wire with it, so a drain which began
    // again from byte zero would eat the message behind this one and wait forever for what
    // it had already been given
    request.recv_cb = [](std::vector<char>) -> bool {
        throw std::runtime_error("route gave up");
    };
    bool threw = false;
    try {
        (void) request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_BODY, config);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    CHECK(threw);
    CHECK(!(request.parts_parsed & PW_HTTP_MESSAGE_PART_BODY));

    CHECK(request.discard_body(conn, receiver, config));
    CHECK(request.parts_parsed & PW_HTTP_MESSAGE_PART_BODY);
    CHECK(request.recv_cb); // Left as its owner set it, and never called, or this would throw

    pw::RequestReceiver next;
    CHECK(next.parse(conn, receiver, PW_HTTP_MESSAGE_PART_HEAD, config));
    CHECK(next.target == "/next");
}

TEST(http_receiver_discards_a_chunked_body_only_before_it_is_started) {
    {
        ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n0\r\n\r\nGET /next HTTP/1.1\r\n\r\n"), 2);
        pn::tcp::BufReceiver receiver(4);

        pw::RequestReceiver request;
        CHECK(request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_HEAD));
        CHECK(request.discard_body(conn, receiver));

        pw::RequestReceiver next;
        CHECK(next.parse(conn, receiver, PW_HTTP_MESSAGE_PART_HEAD));
        CHECK(next.target == "/next");
    }
    {
        ScriptedConnection conn(to_bytes("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\none\r\n3\r\ntwo\r\n0\r\n\r\n"), 2);
        pn::tcp::BufReceiver receiver(4);

        pw::RequestReceiver request;
        CHECK(request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_HEAD));
        request.recv_cb = [](std::vector<char>) {
            return false;
        };
        CHECK(!request.parse(conn, receiver, PW_HTTP_MESSAGE_PART_BODY));

        // How far into its framing a chunked body got is not tracked, so there is no
        // resuming it and the connection can only be closed
        CHECK(!request.discard_body(conn, receiver));
    }
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

    CHECK(!socket_flag(client.fd, IPPROTO_TCP, TCP_NODELAY));
    CHECK(socket_flag(client.fd, SOL_SOCKET, SO_KEEPALIVE));

    // Both flags the other way round, so this shows they are carried rather than that
    // the socket happened to start out matching what was asked for
    config.tcp_no_delay = true;
    config.tcp_keep_alive = false;
    CHECK(config.apply(client));
    CHECK(socket_flag(client.fd, IPPROTO_TCP, TCP_NODELAY));
    CHECK(!socket_flag(client.fd, SOL_SOCKET, SO_KEEPALIVE));

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

TEST(base64_round_trips_including_every_padding_length) {
    // The three residues are where a base64 implementation goes wrong, so all of them
    for (pn::StringView plain : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
        std::string encoded = pw::base64_encode(plain.data(), plain.size());
        std::vector<char> decoded = pw::base64_decode(encoded);
        CHECK(std::string(decoded.begin(), decoded.end()) == std::string(plain));
    }

    // The vectors from RFC 4648, so this checks the alphabet and not just self consistency
    CHECK(pw::base64_encode("f", 1) == "Zg==");
    CHECK(pw::base64_encode("fo", 2) == "Zm8=");
    CHECK(pw::base64_encode("foo", 3) == "Zm9v");
    CHECK(pw::base64_encode("foobar", 6) == "Zm9vYmFy");

    // Bytes that are not text, since a header value may carry anything
    std::vector<char> binary;
    for (int i = 0; i < 256; ++i) {
        binary.push_back((char) i);
    }
    std::vector<char> round_tripped = pw::base64_decode(pw::base64_encode(binary.data(), binary.size()));
    CHECK(round_tripped == binary);

    // Decoding stops at the first byte that is not a symbol, a null byte included
    CHECK(pw::base64_decode("Zm9vYmFy!!!").size() == 6);
    CHECK(pw::base64_decode(std::string("Zm9v\0YmFy", 9)).size() == 3);
}

TEST(percent_encoding_round_trips_and_honours_its_flags) {
    CHECK(pw::percent_decode(pw::percent_encode("hello world")) == "hello world");
    CHECK(pw::percent_decode(pw::percent_encode("a/b?c=d&e#f")) == "a/b?c=d&e#f");

    // A path keeps its separators unless told otherwise, or a URL would stop being one
    CHECK(pw::percent_encode("a/b") == "a/b");
    CHECK(pw::percent_encode("a/b", false, false) == "a%2Fb");

    // Only in a query string does a plus mean a space
    CHECK(pw::percent_decode("a+b") == "a+b");
    CHECK(pw::percent_decode("a+b", true) == "a b");
    CHECK(pw::percent_encode("a b", true) == "a+b");

    CHECK(pw::percent_decode("%41%42%43") == "ABC");
    CHECK(pw::percent_decode("%2f") == "/"); // Lower case hex is just as valid

    // Every byte survives the trip, including the ones that have to be escaped
    std::string all;
    for (int i = 1; i < 256; ++i) {
        all.push_back((char) i);
    }
    CHECK(pw::percent_decode(pw::percent_encode(all, false, false)) == all);
}

TEST(http_dates_round_trip) {
    // A fixed instant, so this does not quietly depend on when it runs
    time_t stamp = 784'111'777; // Sun, 06 Nov 1994 08:49:37 GMT
    std::string formatted = pw::build_date(stamp);
    CHECK(formatted == "Sun, 06 Nov 1994 08:49:37 GMT");
    CHECK(pw::parse_date(formatted) == stamp);

    // The epoch, and a date past the point a signed 32 bit time_t would turn over
    CHECK(pw::parse_date(pw::build_date(0)) == 0);
    CHECK(pw::parse_date(pw::build_date(2'150'000'000)) == 2'150'000'000);
}

TEST(headers_are_looked_up_without_regard_to_case) {
    pw::Headers headers;
    headers["Content-Type"] = "text/plain";

    for (const char* spelling : {"content-type", "CONTENT-TYPE", "cOnTeNt-TyPe", "Content-Type"}) {
        CHECK(headers.count(spelling));
        CHECK(headers.at(spelling) == "text/plain");
    }

    // Assigning through another spelling has to reach the same entry, not add a second
    headers["CONTENT-TYPE"] = "text/html";
    CHECK(headers.size() == 1);
    CHECK(headers.at("Content-Type") == "text/html");

    CHECK(!headers.count("Content-Length"));
}

TEST(xml_escape_covers_the_characters_that_break_markup) {
    CHECK(pw::xml_escape(std::string("<a href=\"x\">tom & jerry</a>")).find('<') == std::string::npos);
    CHECK(pw::xml_escape(std::string("&")).find('&') != std::string::npos); // As an entity
    CHECK(pw::xml_escape(std::string("plain text 123")) == "plain text 123");
    CHECK(pw::xml_escape(std::string("")).empty());
}

TEST(status_codes_carry_their_reason_phrases) {
    CHECK(pw::status_code_to_reason_phrase(200) == "OK");
    CHECK(pw::status_code_to_reason_phrase(404) == "Not Found");
    CHECK(pw::status_code_to_reason_phrase(101) == "Switching Protocols");
    CHECK(pw::status_code_to_reason_phrase(500) == "Internal Server Error");

    // An unknown code falls back to the phrase for its category rather than failing
    CHECK(pw::status_code_to_reason_phrase(299) == "OK");
    CHECK(pw::status_code_to_reason_phrase(499) == "Bad Request");
    CHECK(pw::status_code_to_reason_phrase(599) == "Internal Server Error");
    for (uint16_t status_code = 100; status_code < 600; ++status_code) {
        CHECK(!pw::status_code_to_reason_phrase(status_code).empty());
    }

    // Outside the range there is no category to fall back to, so it throws
    bool threw = false;
    try {
        (void) pw::status_code_to_reason_phrase(99);
    } catch (const std::out_of_range&) {
        threw = true;
    }
    CHECK(threw);

    threw = false;
    try {
        (void) pw::status_code_to_reason_phrase(600);
    } catch (const std::out_of_range&) {
        threw = true;
    }
    CHECK(threw);
}

TEST(a_tls_server_can_listen_without_tls) {
    std::atomic<bool> served_securely {true};

    pw::TLSServer server;
    server.route("/plain",
        pw::TLSRoute {
            [&served_securely](const pw::TLSConnection& conn, const pw::Request&) {
                served_securely = conn.is_secure();
                return pw::Response(200, "no tls here", {{"Content-Type", "text/plain"}});
            },
        });

    CHECK(server.bind("127.0.0.1", (unsigned short) 0));
    uint16_t port = listening_port(server);
    // Listening here rather than leaving it to the server thread, so a connection cannot
    // be refused just because the thread has not got that far yet
    CHECK(::listen(server.fd, 16) == PN_OK);

    std::thread server_thread([&server] {
        (void) server.listen(); // Returns once the socket below it is closed
    });

    pw::Response resp;
    pn::Status result = pw::fetch("http://127.0.0.1:" + std::to_string(port) + "/plain", resp);

    // A shutdown wakes the thread blocked in accept without touching the descriptor, so
    // the close can wait until that thread is gone. Closing first would write the
    // descriptor while accept is still reading it, which is the caller's problem to avoid.
    // Winsock ignores shutdown on a listener and wakes accept on the close instead
#ifdef _WIN32
    (void) server.close();
    server_thread.join();
#else
    (void) ::shutdown(server.fd, SHUT_RDWR);
    server_thread.join();
    (void) server.close();
#endif

    CHECK(result);
    CHECK(resp.status_code == 200);
    CHECK(resp.body_string() == "no tls here");
    // A connection that was never given a context must not claim to be secure
    CHECK(!served_securely);
}
