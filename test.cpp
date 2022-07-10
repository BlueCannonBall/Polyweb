#include "polyweb.hpp"

int main() {
    pw::Server server;

    server.route("/damn?", [](const pw::Connection& conn, const pw::HTTPRequest& req) {
        std::string response;
        for (const auto& parameter : req.query_parameters) {
            response += parameter.first + "=" + parameter.second + "\n";
        }
        return pw::HTTPResponse("200", response);
    });

    server.bind("0.0.0.0", 7000);
    server.listen(128);
}