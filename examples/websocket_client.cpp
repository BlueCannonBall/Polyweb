#include "../polyweb.hpp"
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

int main() {
    (void) pn::init();

    pw::SecureWSClient client;
    if (pn::Status result = pw::make_ws_client(client, "wss://ws.postman-echo.com/raw"); !result) {
        std::cerr << "Error: " << result.error().message() << std::endl;
        return 1;
    }

    for (int i = 0;; ++i, std::this_thread::sleep_for(std::chrono::seconds(1))) {
        {
            pw::WSMessage message("Message #" + std::to_string(i));
            if (pn::Status result = client.send(std::move(message)); !result) {
                std::cerr << "Error: " << result.error().message() << std::endl;
                return 1;
            }
            std::cout << "Sent: " << message.to_string() << std::endl;
        }

        {
            pw::WSMessage message;
            if (pn::Status result = client.recv(message); !result) {
                std::cerr << "Error: " << result.error().message() << std::endl;
                return 1;
            }
            std::cout << "Received: " << message.to_string() << std::endl;
        }
    }

    (void) client.ws_close(1000, {}); // Send a WebSocket close frame
    (void) client.close();            // Forcefully close the actual socket
    (void) pn::quit();
    return 0;
}
