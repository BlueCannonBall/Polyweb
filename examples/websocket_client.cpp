#include "../polyweb.hpp"
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
    pn::init();

    pw::SecureWebSocketClient client;
    if (client.connect("ws.postman-echo.com", 443) == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (client.ssl_init("ws.postman-echo.com") == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (client.ssl_connect() == PN_ERROR) {
        std::cerr << "Error: " << pn::universal_strerror() << std::endl;
        return 1;
    }
    if (client.ws_connect("wss://ws.postman-echo.com/raw") == PN_ERROR) {
        std::cerr << "Error: " << pw::universal_strerror() << std::endl;
        return 1;
    }

    for (int i = 0;; ++i, std::this_thread::sleep_for(std::chrono::seconds(1))) {
        {
            pw::WSMessage message("Message #" + std::to_string(i));
            if (client.send(message) == PN_ERROR) {
                std::cerr << "Error: " << pw::universal_strerror() << std::endl;
                return 1;
            }
            std::cout << "Sent: " << message.to_string() << std::endl;
        }

        {
            pw::WSMessage message;
            int result;
            if ((result = client.recv(message)) == PN_ERROR) {
                std::cerr << "Error: " << pw::universal_strerror() << std::endl;
                return 1;
            } else if (result == 0) {
                std::cout << "Connection closed" << std::endl;
                return 0;
            }
            std::cout << "Received: " << message.to_string() << std::endl;
        }
    }

    pn::quit();
    return 0;
}
