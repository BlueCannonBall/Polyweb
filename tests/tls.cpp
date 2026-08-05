#include "Polynet/tls.hpp"
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

    pn::Status connect_with(pn::tcp::TLSClient& client, pn::StringView hostname, int verify_mode = SSL_VERIFY_PEER, pn::StringView ca_file = {}) {
        pn::TLSContext context;
        if (pn::Status result = context.init_client(verify_mode, ca_file); !result) {
            return result;
        }
        return client.tls_init(context, hostname);
    }

    pn::TLSContext make_server_context() {
        pn::TLSContext context;
        CHECK(context.init_server("../examples/cert.pem", "../examples/key.pem", SSL_FILETYPE_PEM));
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

    // Both payloads must be far larger than the socket buffers, so that each end blocks
    // sending until the other end reads. A payload that fits in the buffers completes
    // without either side ever having to receive while a send is outstanding, which is
    // the only situation in which a receiver can be held up behind a sender
    std::vector<char> client_payload(8 * 1024 * 1024, 'c');
    std::vector<char> server_payload(8 * 1024 * 1024, 's');
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
            pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
                return;
            } else if (pn::Status result = connection.tls_init(server_context); !result) {
                server_error = result.error().message();
                return;
            } else if (pn::Status result = connection.tls_accept(); !result) {
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

    pn::tcp::TLSClient client;
    std::string client_error;
    if (pn::Status result = client.connect("127.0.0.1", listening_port(listener)); !result) {
        client_error = result.error().message();
    } else if (pn::Status result = set_socket_timeout(client); !result) {
        client_error = result.error().message();
    } else if (pn::Status result = connect_with(client, "localhost", SSL_VERIFY_NONE); !result) {
        client_error = result.error().message();
    } else if (pn::Status result = client.tls_connect(); !result) {
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
            pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.tls_init(server_context); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.tls_accept(); !result) {
                server_error = result.error().message();
            }
        }
    });

    pn::tcp::TLSClient client;
    pn::Status client_result = client.connect("127.0.0.1", listening_port(listener));
    if (client_result) {
        client_result = set_socket_timeout(client);
    }
    if (client_result) {
        client_result = connect_with(client, "localhost", SSL_VERIFY_PEER, "../examples/cert.pem");
    }
    if (client_result) {
        client_result = client.tls_connect();
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
            pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (set_socket_timeout(connection) && connection.tls_init(server_context)) {
                (void) connection.tls_accept();
            }
        }
    });

    pn::tcp::TLSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(connect_with(client, "wrong.example.test", SSL_VERIFY_PEER, "../examples/cert.pem"));
    CHECK(!client.tls_connect());

    server_thread.join();
    CHECK(server_accepted);
}

TEST(tls_does_not_send_sni_for_an_ip_literal) {
    auto server_context = make_server_context();
    std::string server_name;
    SSL_CTX_set_tlsext_servername_callback(server_context.ssl_ctx, capture_server_name);
    SSL_CTX_set_tlsext_servername_arg(server_context.ssl_ctx, &server_name);

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
            pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.tls_init(server_context); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.tls_accept(); !result) {
                server_error = result.error().message();
            }
        }
    });

    pn::tcp::TLSClient client;
    pn::Status client_result = client.connect("127.0.0.1", listening_port(listener));
    if (client_result) {
        client_result = set_socket_timeout(client);
    }
    if (client_result) {
        client_result = connect_with(client, "127.0.0.1", SSL_VERIFY_NONE);
    }
    if (client_result) {
        client_result = client.tls_connect();
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

    pn::tcp::TLSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(connect_with(client, "localhost", SSL_VERIFY_NONE));
    CHECK(!client.tls_connect());

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
            pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.tls_init(server_context); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.tls_accept(); !result) {
                server_error = result.error().message();
            } else {
                (void) connection.close(PN_PROTOCOL_LAYER_SYSTEM);
            }
        }
    });

    pn::tcp::TLSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(connect_with(client, "localhost", SSL_VERIFY_NONE));
    CHECK(client.tls_connect());
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
            pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.tls_init(server_context); !result) {
                server_error = result.error().message();
            } else if (pn::Status result = connection.tls_accept(); !result) {
                server_error = result.error().message();
            } else if (pn::Result<size_t> result = connection.recvall(received.data(), received.size()); !result) {
                server_error = result.error().message();
            } else if (*result != received.size()) {
                server_error = "receive incomplete test payload";
            }
        }
    });

    pn::tcp::TLSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(connect_with(client, "localhost", SSL_VERIFY_NONE));
    CHECK(client.tls_connect());

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

TEST(tls_context_is_shared_across_connections) {
    auto server_context = make_server_context();
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 2) == PN_OK);

    std::string server_error;
    std::thread server_thread([&] {
        for (int i = 0; i < 2; ++i) {
            struct sockaddr_storage peer_address = {};
            socklen_t peer_address_length = sizeof peer_address;
            pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length);
            if (fd == PN_INVALID_SOCKFD) {
                server_error = pn::make_last_socket_error("accept test connection").message();
                return;
            }
            pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (pn::Status result = set_socket_timeout(connection); !result) {
                server_error = result.error().message();
                return;
            } else if (pn::Status result = connection.tls_init(server_context); !result) {
                server_error = result.error().message();
                return;
            } else if (pn::Status result = connection.tls_accept(); !result) {
                server_error = result.error().message();
                return;
            }
        }
    });

    pn::TLSContext context;
    CHECK(context.init_client(SSL_VERIFY_PEER, "../examples/cert.pem"));
    CHECK(context);

    for (int i = 0; i < 2; ++i) {
        pn::tcp::TLSClient client;
        CHECK(client.connect("127.0.0.1", listening_port(listener)));
        CHECK(set_socket_timeout(client));
        CHECK(client.tls_init(context, "localhost"));
        CHECK(client.tls_connect());
    }
    CHECK(context); // Lending it out neither consumed nor closed it

    server_thread.join();
    CHECK(server_error.empty());
}

TEST(tls_context_may_be_closed_while_its_connections_live_on) {
    auto server_context = make_server_context();
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    std::vector<char> payload(64 * 1024, 'x');
    std::string server_error;
    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length);
        if (fd == PN_INVALID_SOCKFD) {
            server_error = pn::make_last_socket_error("accept test connection").message();
            return;
        }
        pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
        if (pn::Status result = set_socket_timeout(connection); !result) {
            server_error = result.error().message();
        } else if (pn::Status result = connection.tls_init(server_context); !result) {
            server_error = result.error().message();
        } else if (pn::Status result = connection.tls_accept(); !result) {
            server_error = result.error().message();
        } else if (pn::Result<size_t> result = connection.sendall(payload.data(), payload.size()); !result) {
            server_error = result.error().message();
        }
    });

    pn::tcp::TLSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    {
        pn::TLSContext context;
        CHECK(context.init_client(SSL_VERIFY_NONE));
        CHECK(client.tls_init(context, "localhost"));
    } // The connection holds its own reference, so this closing must not disturb it

    CHECK(client.tls_connect());
    std::vector<char> received(payload.size());
    pn::Result<size_t> result = client.recvall(received.data(), received.size());
    CHECK(result);
    CHECK(*result == payload.size());
    CHECK(received == payload);

    server_thread.join();
    CHECK(server_error.empty());
}

TEST(tls_client_adopts_an_already_connected_socket) {
    auto server_context = make_server_context();
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);
    uint16_t port = listening_port(listener);

    std::string server_error;
    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length);
        if (fd == PN_INVALID_SOCKFD) {
            server_error = pn::make_last_socket_error("accept test connection").message();
            return;
        }
        pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
        if (pn::Status result = set_socket_timeout(connection); !result) {
            server_error = result.error().message();
        } else if (pn::Status result = connection.tls_init(server_context); !result) {
            server_error = result.error().message();
        } else if (pn::Status result = connection.tls_accept(); !result) {
            server_error = result.error().message();
        }
    });

    // Connect by hand, then hand the descriptor to a client that never called connect
    struct sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    CHECK(::inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    pn::sockfd_t fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHECK(fd != PN_INVALID_SOCKFD);
    CHECK(::connect(fd, (struct sockaddr*) &address, sizeof address) == PN_OK);

    pn::tcp::TLSClient client(fd, *(struct sockaddr*) &address, sizeof address);
    CHECK(client.is_valid());
    CHECK(set_socket_timeout(client));
    CHECK(connect_with(client, "localhost", SSL_VERIFY_NONE));
    CHECK(client.tls_connect());
    CHECK(client.is_secure());

    server_thread.join();
    CHECK(server_error.empty());
}

TEST(tls_init_failure_leaves_the_socket_to_its_owner) {
    auto server_context = make_server_context();
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    std::string server_error;
    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length);
        if (fd == PN_INVALID_SOCKFD) {
            server_error = pn::make_last_socket_error("accept test connection").message();
            return;
        }
        pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
        if (pn::Status result = set_socket_timeout(connection); !result) {
            server_error = result.error().message();
        } else if (pn::Status result = connection.tls_init(server_context); !result) {
            server_error = result.error().message();
        } else if (pn::Status result = connection.tls_accept(); !result) {
            server_error = result.error().message();
        }
    });

    pn::tcp::TLSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    pn::sockfd_t fd = client.fd;

    // Names longer than 255 bytes are rejected outright by the SNI extension
    CHECK(!connect_with(client, std::string(300, 'a'), SSL_VERIFY_NONE));
    CHECK(client.is_valid());
    CHECK(client.fd == fd);
    CHECK(!client.is_secure());

    // Having undone only what it created, the failed call left the connection reusable
    CHECK(connect_with(client, "localhost", SSL_VERIFY_NONE));
    CHECK(client.tls_connect());

    server_thread.join();
    CHECK(server_error.empty());
}

TEST(tls_close_honours_the_layers_it_is_given) {
    auto server_context = make_server_context();
    pn::tcp::Server listener;
    CHECK(listener.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(listener.fd, 1) == PN_OK);

    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        if (pn::sockfd_t fd = ::accept(listener.fd, (struct sockaddr*) &peer_address, &peer_address_length); fd != PN_INVALID_SOCKFD) {
            pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
            if (set_socket_timeout(connection) && connection.tls_init(server_context)) {
                (void) connection.tls_accept();
            }
        }
    });

    pn::tcp::TLSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(listener)));
    CHECK(set_socket_timeout(client));
    CHECK(connect_with(client, "localhost", SSL_VERIFY_NONE));
    CHECK(client.tls_connect());

    // Closing the system layer must leave the TLS layer standing
    CHECK(client.close(PN_PROTOCOL_LAYER_SYSTEM));
    CHECK(!client.is_valid());
    CHECK(client.is_secure());

    // And closing the TLS layer afterwards must be the thing that tears it down
    CHECK(client.close(PN_PROTOCOL_LAYER_TLS));
    CHECK(!client.is_secure());

    server_thread.join();

    pn::tcp::TLSServer server;
    CHECK(server.bind("127.0.0.1", (unsigned short) 0));
    CHECK(server.close(PN_PROTOCOL_LAYER_SYSTEM));
    CHECK(!server.is_valid());
}

TEST(tls_context_is_shared_by_two_listeners) {
    pn::TLSContext context;
    CHECK(context.init_server("../examples/cert.pem", "../examples/key.pem", SSL_FILETYPE_PEM));

    // Two listeners, one certificate, as a dual stack setup would want
    pn::tcp::TLSServer first;
    pn::tcp::TLSServer second;
    CHECK(first.bind("127.0.0.1", (unsigned short) 0));
    CHECK(second.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(first.fd, 1) == PN_OK);

    std::string server_error;
    std::thread server_thread([&] {
        struct sockaddr_storage peer_address = {};
        socklen_t peer_address_length = sizeof peer_address;
        pn::sockfd_t fd = ::accept(first.fd, (struct sockaddr*) &peer_address, &peer_address_length);
        if (fd == PN_INVALID_SOCKFD) {
            server_error = pn::make_last_socket_error("accept test connection").message();
            return;
        }
        pn::tcp::TLSConnection connection(fd, *(struct sockaddr*) &peer_address, peer_address_length);
        if (pn::Status result = set_socket_timeout(connection); !result) {
            server_error = result.error().message();
        } else if (pn::Status result = connection.tls_init(context); !result) {
            server_error = result.error().message();
        } else if (pn::Status result = connection.tls_accept(); !result) {
            server_error = result.error().message();
        }
    });

    pn::tcp::TLSClient client;
    CHECK(client.connect("127.0.0.1", listening_port(first)));
    CHECK(set_socket_timeout(client));
    CHECK(connect_with(client, "localhost", SSL_VERIFY_NONE));
    CHECK(client.tls_connect());
    server_thread.join();
    CHECK(server_error.empty());
    CHECK(context); // Lending it out neither consumed nor closed it
}

TEST(one_tls_context_serves_concurrent_handshakes) {
    // Sharing a context is only worth anything if many connections may use it at once.
    // Verification is deliberately off: OpenSSL races on the trust store behind a context
    // during concurrent verification, whether that context is shared or not, so turning it
    // on here would test libcrypto rather than whether an SSL_CTX may be lent out at all
    pn::TLSContext server_context = make_server_context();
    pn::TLSContext client_context;
    CHECK(client_context.init_client(SSL_VERIFY_NONE));

    pn::tcp::TLSServer server;
    CHECK(server.bind("127.0.0.1", (unsigned short) 0));
    CHECK(::listen(server.fd, 16) == PN_OK);
    uint16_t port = listening_port(server);

    static constexpr size_t connection_count = 8;
    std::vector<std::string> server_errors(connection_count);
    std::vector<std::string> client_errors(connection_count);

    std::thread acceptor([&] {
        std::vector<std::thread> handshakes;
        for (size_t i = 0; i < connection_count; ++i) {
            struct sockaddr_storage peer_address = {};
            socklen_t peer_address_length = sizeof peer_address;
            pn::sockfd_t fd = ::accept(server.fd, (struct sockaddr*) &peer_address, &peer_address_length);
            if (fd == PN_INVALID_SOCKFD) {
                server_errors[i] = pn::make_last_socket_error("accept test connection").message();
                continue;
            }
            handshakes.emplace_back([&server_context, &server_errors, i, fd, peer_address, peer_address_length] {
                pn::tcp::TLSConnection conn(fd, *(const struct sockaddr*) &peer_address, peer_address_length);
                if (pn::Status result = set_socket_timeout(conn); !result) {
                    server_errors[i] = result.error().message();
                } else if (pn::Status result = conn.tls_init(server_context); !result) {
                    server_errors[i] = result.error().message();
                } else if (pn::Status result = conn.tls_accept(); !result) {
                    server_errors[i] = result.error().message();
                }
            });
        }
        for (std::thread& handshake : handshakes) {
            handshake.join();
        }
    });

    std::vector<std::thread> clients;
    for (size_t i = 0; i < connection_count; ++i) {
        clients.emplace_back([&client_context, &client_errors, port, i] {
            pn::tcp::TLSClient client;
            if (pn::Status result = client.connect("127.0.0.1", port); !result) {
                client_errors[i] = result.error().message();
            } else if (pn::Status result = set_socket_timeout(client); !result) {
                client_errors[i] = result.error().message();
            } else if (pn::Status result = client.tls_init(client_context, "localhost"); !result) {
                client_errors[i] = result.error().message();
            } else if (pn::Status result = client.tls_connect(); !result) {
                client_errors[i] = result.error().message();
            }
        });
    }
    for (std::thread& client : clients) {
        client.join();
    }
    acceptor.join();

    for (const std::string& error : server_errors) {
        CHECK(error.empty());
    }
    for (const std::string& error : client_errors) {
        CHECK(error.empty());
    }
    CHECK(server_context); // Lending it to eight connections at once neither consumed nor closed it
    CHECK(client_context);
}
