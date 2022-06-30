#include "polyweb.hpp"

int main() {
    pw::Server server;

    server.route_ws("/", pw::WSRoute {
        .on_connect = [](pw::Connection& conn, const pw::HTTPRequest& req) -> pw::HTTPResponse {
            return pw::HTTPResponse("101");
        },
        .on_message = [](pw::Connection& conn, const pw::WSMessage& message) {
            std::cout << "message: " << message.opcode << std::endl;
        }
    });

    server.bind("0.0.0.0", 8000);
    server.listen(128);
}