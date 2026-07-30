#include "../polyweb.hpp"
#include <iostream>
#include <stdlib.h>

int main() {
    (void) pn::init();

    pw::Server server;

    server.route("/hello_world",
        pw::HTTPRoute {
            [](const pw::Connection& conn, const pw::HTTPRequest& req) {
                return pw::HTTPResponse(200, "Hello, World!", {{"Content-Type", "text/plain"}});
            },
        });

    // Since this is a wildcard route, anything may come after /wildcard/
    server.route("/wildcard/",
        pw::HTTPRoute {
            [](const pw::Connection& conn, const pw::HTTPRequest& req) {
                return pw::HTTPResponse(200, req.target, {{"Content-Type", "text/plain"}});
            },
            true,
        });

    server.route("/multiply",
        pw::HTTPRoute {
            [](const pw::Connection& conn, const pw::HTTPRequest& req) {
                int x = std::stoi(req.query_parameters->find("x")->second);
                int y = std::stoi(req.query_parameters->find("y")->second);
                return pw::HTTPResponse(200, std::to_string(x * y), {{"Content-Type", "text/plain"}});
            },
        });

    server.route("/send_stream",
        pw::HTTPRoute {
            [](const pw::Connection& conn, const pw::HTTPRequest& req) {
                return pw::HTTPResponse(200, [i = 0]() mutable -> std::vector<char> {
                    if (i < 10) {
                        std::string str = std::to_string(i++);
                        return std::vector<char>(str.begin(), str.end());
                    }
                    return {};
                },
                    {{"Content-Type", "text/plain"}});
            },
        });

    server.route("/recv_stream",
        pw::HTTPRoute {
            [](pw::Connection& conn, pw::HTTPRequestReceiver& req) {
                std::vector<char> body;
                req.recv_cb = [&body](std::vector<char> chunk) {
                    body.insert(body.end(), chunk.begin(), chunk.end());
                    return true;
                };
                if (pn::Status result = conn.recv(req, PW_HTTP_MESSAGE_PART_BODY); !result) {
                    return pw::HTTPResponse(500, result.error().message());
                }

                return pw::HTTPResponse(200, body);
            },
            false,
            false, // tells Polyweb not to parse the body itself
        });

    if (pn::Status result = server.bind("0.0.0.0", 8000); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    if (pn::Status result = server.listen(); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    (void) server.close();
    (void) pn::quit();
    return 0;
}
