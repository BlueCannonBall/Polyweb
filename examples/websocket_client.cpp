#include "../polyweb.hpp"
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
    pn::init();

    pw::SecureWebSocketClient client;
    if (pw::make_websocket_client(client, "wss://ws.postman-echo.com/raw") == PN_ERROR) {
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
            if (int result = client.recv(message); result == PN_ERROR) {
                std::cerr << "Error: " << pw::universal_strerror() << std::endl;
                return 1;
            } else if (!result) {
                std::cout << "Connection closed" << std::endl;
                return 0;
            }
            std::cout << "Received: " << message.to_string() << std::endl;
        }
    }

    client.ws_close(1000, {}); // Send a WebSocket close frame
    client.close();            // Forcefully close the actual socket
    pn::quit();
    return 0;
}
