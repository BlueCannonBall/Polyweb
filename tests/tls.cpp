#include "Polynet/secure_sockets.hpp"
#include "test.hpp"
#include <memory>
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

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> make_server_context() {
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
        CHECK(context);
        CHECK(SSL_CTX_use_certificate_chain_file(context.get(), "../examples/cert.pem") == 1);
        CHECK(SSL_CTX_use_PrivateKey_file(context.get(), "../examples/key.pem", SSL_FILETYPE_PEM) == 1);
        CHECK(SSL_CTX_check_private_key(context.get()) == 1);
        return context;
    }

    int capture_server_name(SSL* ssl, int*, void* arg) {
        std::string& server_name = *(std::string*) arg;
        if (const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name)) {
            server_name = name;
        }
        return SSL_TLSEXT_ERR_OK;
    }
} // namespace

TEST(tls_transfers_large_data_in_both_directions) {
    auto server_context = make_server_context();
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    std::vector<char> client_payload(64 * 1024, 'c');
    std::vector<char> server_payload(64 * 1024, 's');
    std::vector<char> server_received(client_payload.size());
    std::vector<char> client_received(server_payload.size());
    std::string server_error;

    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        if (pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length); fd == PN_INVALID_SOCKFD) {
            server_error = pn::make_last_socket_error("accept test connection").message();
            return;
        } else {
            pn::tcp::SecureConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
                return;
            } else if (pn::Status result = connection.ssl_init(server_context.get()); !result) {
                server_error = result.error().message();
                return;
            } else if (pn::Status result = connection.ssl_accept(); !result) {
                server_error = result.error().message();
                return;
            }

            pn::Result<size_t> sent = 0;
            pn::Result<size_t> received = 0;
            std::thread sender([&] {
                sent = connection.sendall(server_payload.data(), server_payload.size());
            });
            std::thread receiver([&] {
                received = connection.recvall(server_received.data(), server_received.size());
            });
            sender.join();
            receiver.join();

            if (!sent) {
                server_error = sent.error().message();
            } else if (*sent != server_payload.size()) {
                server_error = "send incomplete test payload";
            } else if (!received) {
                server_error = received.error().message();
            } else if (*received != server_received.size()) {
                server_error = "receive incomplete test payload";
            }
        }
    });

    pn::tcp::SecureClient client;
    std::string client_error;
    if (pn::Status result = client.connect("127.0.0.1", listening_port(listener)); !result) {
        client_error = result.error().message();
    } else if (pn::Status result = set_socket_timeout(client); !result) {
        client_error = result.error().message();
    } else if (pn::Status result = client.ssl_init("localhost", SSL_VERIFY_NONE); !result) {
        client_error = result.error().message();
    } else if (pn::Status result = client.ssl_connect(); !result) {
        client_error = result.error().message();
    } else {
        pn::Result<size_t> sent = 0;
        pn::Result<size_t> received = 0;
        std::thread sender([&] {
            sent = client.sendall(client_payload.data(), client_payload.size());
        });
        std::thread receiver([&] {
            received = client.recvall(client_received.data(), client_received.size());
        });
        sender.join();
        receiver.join();

        if (!sent) {
            client_error = sent.error().message();
        } else if (*sent != client_payload.size()) {
            client_error = "send incomplete test payload";
        } else if (!received) {
            client_error = received.error().message();
        } else if (*received != client_received.size()) {
            client_error = "receive incomplete test payload";
        }
    }

    server_thread.join();
    CHECK(client_error.empty());
    CHECK(server_error.empty());
    CHECK(client_received == server_payload);
    CHECK(server_received == client_payload);
}

TEST(tls_verifies_a_trusted_hostname) {
    auto server_context = make_server_context();
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
            pn::tcp::SecureConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.ssl_init(server_context.get()); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.ssl_accept(); !result) {
                server_error = result.error().message();
            }
        }
    });

    pn::tcp::SecureClient client;
    pn::Status client_result = client.connect("127.0.0.1", listening_port(listener));
    if (client_result) {
        client_result = set_socket_timeout(client);
    }
    if (client_result) {
        client_result = client.ssl_init("localhost", SSL_VERIFY_PEER, "../examples/cert.pem");
    }
    if (client_result) {
        client_result = client.ssl_connect();
    }

    server_thread.join();
    CHECK(client_result);
    CHECK(server_error.empty());
}

TEST(tls_rejects_a_hostname_mismatch) {
    auto server_context = make_server_context();
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    bool server_accepted = false;
    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        if (pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length); fd != PN_INVALID_SOCKFD) {
            server_accepted = true;
            pn::tcp::SecureConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (set_socket_timeout(connection) && connection.ssl_init(server_context.get())) {
                (void) connection.ssl_accept();
            }
        }
    });

    pn::tcp::SecureClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(client.ssl_init("wrong.example.test", SSL_VERIFY_PEER, "../examples/cert.pem"));
    CHECK(!client.ssl_connect());

    server_thread.join();
    CHECK(server_accepted);
}

TEST(tls_does_not_send_sni_for_an_ip_literal) {
    auto server_context = make_server_context();
    std::string server_name;
    SSL_CTX_set_tlsext_servername_callback(server_context.get(), capture_server_name);
    SSL_CTX_set_tlsext_servername_arg(server_context.get(), &server_name);

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
            pn::tcp::SecureConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.ssl_init(server_context.get()); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.ssl_accept(); !result) {
                server_error = result.error().message();
            }
        }
    });

    pn::tcp::SecureClient client;
    pn::Status client_result = client.connect("127.0.0.1", listening_port(listener));
    if (client_result) {
        client_result = set_socket_timeout(client);
    }
    if (client_result) {
        client_result = client.ssl_init("127.0.0.1", SSL_VERIFY_NONE);
    }
    if (client_result) {
        client_result = client.ssl_connect();
    }

    server_thread.join();
    CHECK(client_result);
    CHECK(server_error.empty());
    CHECK(server_name.empty());
}

TEST(tls_rejects_an_eof_during_the_handshake) {
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    bool server_accepted = false;
    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        if (pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length); fd != PN_INVALID_SOCKFD) {
            server_accepted = true;
            pn::tcp::Connection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            (void) connection.close(PN_PROTOCOL_LAYER_SYSTEM);
        }
    });

    pn::tcp::SecureClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(client.ssl_init("localhost", SSL_VERIFY_NONE));
    CHECK(!client.ssl_connect());

    server_thread.join();
    CHECK(server_accepted);
}

TEST(tls_rejects_truncated_application_data) {
    auto server_context = make_server_context();
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
            pn::tcp::SecureConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.ssl_init(server_context.get()); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.ssl_accept(); !result) {
                server_error = result.error().message();
            } else {
                (void) connection.close(PN_PROTOCOL_LAYER_SYSTEM);
            }
        }
    });

    pn::tcp::SecureClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(client.ssl_init("localhost", SSL_VERIFY_NONE));
    CHECK(client.ssl_connect());
    char byte;
    CHECK(!client.recv(&byte, sizeof byte));

    server_thread.join();
    CHECK(server_error.empty());
}

TEST(tls_allows_simultaneous_writers) {
    auto server_context = make_server_context();
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    std::vector<char> first_payload(32 * 1024, 'a');
    std::vector<char> second_payload(32 * 1024, 'b');
    std::vector<char> received(first_payload.size() + second_payload.size());
    std::string server_error;
    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        if (pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length); fd == PN_INVALID_SOCKFD) {
            server_error = pn::make_last_socket_error("accept test connection").message();
            return;
        } else {
            pn::tcp::SecureConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.ssl_init(server_context.get()); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.ssl_accept(); !result) {
                server_error = result.error().message();
            } else if (pn::Result<size_t> result = connection.recvall(received.data(), received.size()); !result) {
                server_error = result.error().message();
            } else if (*result != received.size()) {
                server_error = "receive incomplete test payload";
            }
        }
    });

    pn::tcp::SecureClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(client.ssl_init("localhost", SSL_VERIFY_NONE));
    CHECK(client.ssl_connect());

    pn::Result<size_t> first_result = 0;
    pn::Result<size_t> second_result = 0;
    std::thread first_sender([&] {
        first_result = client.sendall(first_payload.data(), first_payload.size());
    });
    std::thread second_sender([&] {
        second_result = client.sendall(second_payload.data(), second_payload.size());
    });
    first_sender.join();
    second_sender.join();
    server_thread.join();

    CHECK(first_result);
    CHECK(*first_result == first_payload.size());
    CHECK(second_result);
    CHECK(*second_result == second_payload.size());
    CHECK(server_error.empty());
    CHECK((size_t) std::count(received.begin(), received.end(), 'a') == first_payload.size());
    CHECK((size_t) std::count(received.begin(), received.end(), 'b') == second_payload.size());
}
