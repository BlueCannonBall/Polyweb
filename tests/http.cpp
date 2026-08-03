#include "polyweb.hpp"
#include "support.hpp"
#include "test.hpp"
#include <string>
#include <vector>

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
