#include "../polyweb.hpp"

int main() {
    pn::init();

    pw::Server server;

    server.route("/hello_world",
        pw::HTTPRoute {
            [](const pw::Connection& conn, const pw::HTTPRequest& req, void* data) {
                return pw::HTTPResponse(200, "Hello, World!", {{"Content-Type", "text/plain"}});
            },
        });

    // Since this is a wildcard route, anything may come after /wildcard/
    server.route("/wildcard/",
        pw::HTTPRoute {
            [](const pw::Connection& conn, const pw::HTTPRequest& req, void* data) {
                return pw::HTTPResponse(200, req.target, {{"Content-Type", "text/plain"}});
            },
            nullptr,
            true,
        });

    server.route("/multiply",
        pw::HTTPRoute {
            [](const pw::Connection& conn, const pw::HTTPRequest& req, void* data) {
                int x = std::stoi(req.query_parameters->find("x")->second);
                int y = std::stoi(req.query_parameters->find("y")->second);
                return pw::HTTPResponse(200, std::to_string(x * y), {{"Content-Type", "text/plain"}});
            },
        });

    if (server.bind("0.0.0.0", 80) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }

    if (server.listen() == PN_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    pn::quit();
}
