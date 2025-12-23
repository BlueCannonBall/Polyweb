#include "../polyweb.hpp"
#include <iostream>

int main() {
    pn::init();

    pw::SecureServer server;

    server.route("/hello_world",
        pw::SecureHTTPRoute {
            [](const pw::SecureConnection& conn, const pw::HTTPRequest& req) {
                return pw::HTTPResponse(200, "Hello, World!", {{"Content-Type", "text/plain"}});
            },
        });

    // Since this is a wildcard route, anything may come after /wildcard/
    server.route("/wildcard/",
        pw::SecureHTTPRoute {
            [](const pw::SecureConnection& conn, const pw::HTTPRequest& req) {
                return pw::HTTPResponse(200, req.target, {{"Content-Type", "text/plain"}});
            },
            true,
        });

    server.route("/multiply",
        pw::SecureHTTPRoute {
            [](const pw::SecureConnection& conn, const pw::HTTPRequest& req) {
                int x = std::stoi(req.query_parameters->find("x")->second);
                int y = std::stoi(req.query_parameters->find("y")->second);
                return pw::HTTPResponse(200, std::to_string(x * y), {{"Content-Type", "text/plain"}});
            },
        });

    server.route("/stream",
        pw::SecureHTTPRoute {
            [](const pw::SecureConnection& conn, const pw::HTTPRequest& req) {
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

    if (server.bind("0.0.0.0", 443) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (server.ssl_init("cert.pem", "key.pem", SSL_FILETYPE_PEM) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    if (server.listen() == PN_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    server.close();
    pn::quit();
    return 0;
}
