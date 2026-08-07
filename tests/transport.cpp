#include "support.hpp"
#include "test.hpp"
#include "thread_pool.hpp"
#include <array>
#include <chrono>
#include <future>
#include <thread>

TEST(task_manager_waits_for_the_tasks_it_tracks) {
    std::promise<void> task_started;
    std::promise<void> allow_task_to_finish;
    std::future<void> finish_permission = allow_task_to_finish.get_future();
    std::promise<void> waiter_started;
    bool task_finished = false;

    tp::TaskManager manager;
    auto task = std::make_shared<tp::Task>([&] {
        task_started.set_value();
        finish_permission.wait();
        task_finished = true;
    });
    manager.insert(task);

    std::thread worker([task] {
        task->execute();
    });
    task_started.get_future().wait();

    std::future<void> waiter = std::async(std::launch::async, [&] {
        waiter_started.set_value();
        manager.wait();
    });
    waiter_started.get_future().wait();
    CHECK(waiter.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout);

    allow_task_to_finish.set_value();
    waiter.get();
    worker.join();
    CHECK(task_finished);
}

TEST(sendall_handles_partial_writes) {
    ScriptedConnection conn({}, 2);
    static constexpr char input[] = "abcdef";

    if (pn::Result<size_t> result = conn.sendall(input, sizeof input - 1); !result) {
        test::fail(result.error().message().c_str(), __FILE__, __LINE__);
    } else {
        CHECK(*result == sizeof input - 1);
    }
    CHECK(to_string(conn.output) == input);
    CHECK(conn.send_count == 3);
}

TEST(sendall_reports_immediate_errors_and_preserves_partial_progress) {
    static constexpr char input[] = "abcdef";

    ScriptedConnection immediate_error({}, 2);
    immediate_error.send_error_after = 0;
    CHECK(!immediate_error.sendall(input, sizeof input - 1));

    ScriptedConnection partial_error({}, 2);
    partial_error.send_error_after = 1;
    if (pn::Result<size_t> result = partial_error.sendall(input, sizeof input - 1); !result) {
        test::fail(result.error().message().c_str(), __FILE__, __LINE__);
    } else {
        CHECK(*result == 2);
    }
    CHECK(to_string(partial_error.output) == "ab");
}

TEST(recvall_handles_partial_reads_eof_and_errors) {
    std::array<char, 6> output;
    ScriptedConnection partial(to_bytes("abcdef"), 2);
    if (pn::Result<size_t> result = partial.recvall(output.data(), output.size()); !result) {
        test::fail(result.error().message().c_str(), __FILE__, __LINE__);
    } else {
        CHECK(*result == output.size());
    }
    CHECK(std::string(output.begin(), output.end()) == "abcdef");

    ScriptedConnection eof(to_bytes("abc"), 2);
    if (pn::Result<size_t> result = eof.recvall(output.data(), output.size()); !result) {
        test::fail(result.error().message().c_str(), __FILE__, __LINE__);
    } else {
        CHECK(*result == 3);
    }

    ScriptedConnection immediate_error({}, 2);
    immediate_error.recv_error_after = 0;
    CHECK(!immediate_error.recvall(output.data(), output.size()));
}

TEST(buf_receiver_peek_rewind_and_buffer_boundaries) {
    ScriptedConnection conn(to_bytes("abcdef"), 4);
    pn::tcp::BufReceiver receiver(4);
    std::array<char, 3> output;

    CHECK(receiver.peek(conn, output.data(), 2));
    CHECK(std::string(output.data(), 2) == "ab");
    CHECK(receiver.recv(conn, output.data(), 2));
    CHECK(std::string(output.data(), 2) == "ab");

    receiver.rewind("Z", 1);
    CHECK(receiver.recvall(conn, output.data(), output.size()));
    CHECK(std::string(output.data(), output.size()) == "Zcd");

    CHECK(receiver.recv(conn, output.data(), 2));
    CHECK(std::string(output.data(), 2) == "ef");
}

TEST(udp_connected_sockets_send_and_receive) {
    pn::udp::Server server;
    CHECK(server.bind("127.0.0.1", (unsigned short) 0));

    struct sockaddr_in server_address = {};
    socklen_t server_address_length = sizeof server_address;
    CHECK(::getsockname(server.fd, (struct sockaddr*) &server_address, &server_address_length) == PN_OK);

    pn::udp::Client client;
    CHECK(client.connect((struct sockaddr*) &server_address, server_address_length));

    // Connected sockets need no address on either call
    static constexpr char request[] = "ping";
    CHECK(client.send(request, sizeof request - 1));

    char buf[16];
    struct sockaddr_storage peer_address = {};
    socklen_t peer_address_length = sizeof peer_address;
    pn::Result<size_t> received = server.recvfrom(buf, sizeof buf, (struct sockaddr*) &peer_address, &peer_address_length);
    CHECK(received);
    CHECK(*received == sizeof request - 1);
    CHECK(std::string(buf, *received) == "ping");

    static constexpr char response[] = "pong";
    CHECK(server.sendto(response, sizeof response - 1, (struct sockaddr*) &peer_address, peer_address_length));

    pn::Result<size_t> echoed = client.recv(buf, sizeof buf);
    CHECK(echoed);
    CHECK(*echoed == sizeof response - 1);
    CHECK(std::string(buf, *echoed) == "pong");
}

TEST(udp_refuses_a_datagram_it_could_not_send_whole) {
    pn::udp::Client client;
    CHECK(client.init(AF_INET, SOCK_DGRAM, IPPROTO_UDP));

    // Silently truncating to a smaller length would send a different message
    char stub;
    pn::Result<size_t> result = client.send(&stub, (size_t) INT_MAX + 1);
    CHECK(!result);
    CHECK(result.error().code == std::errc::message_size);
}

TEST(udp_reports_a_datagram_that_did_not_fit) {
    pn::udp::Server server;
    CHECK(server.bind("127.0.0.1", (unsigned short) 0));

    struct sockaddr_in server_address = {};
    socklen_t server_address_length = sizeof server_address;
    CHECK(::getsockname(server.fd, (struct sockaddr*) &server_address, &server_address_length) == PN_OK);

    pn::udp::Client client;
    CHECK(client.connect((struct sockaddr*) &server_address, server_address_length));

    std::vector<char> datagram(2000, 'x');
    char buf[512];

    // A receive that loses part of a datagram must say so rather than look like a short one
    CHECK(client.send(datagram.data(), datagram.size()));
    pn::Result<size_t> result = server.recv(buf, sizeof buf);
    CHECK(!result);
    CHECK(result.error().code == std::errc::message_size);

    // A datagram that fits is unaffected
    CHECK(client.send(datagram.data(), sizeof buf));
    result = server.recv(buf, sizeof buf);
    CHECK(result);
    CHECK(*result == sizeof buf);
}

TEST(udp_peek_leaves_the_datagram_queued) {
    pn::udp::Server server;
    CHECK(server.bind("127.0.0.1", (unsigned short) 0));

    struct sockaddr_in server_address = {};
    socklen_t server_address_length = sizeof server_address;
    CHECK(::getsockname(server.fd, (struct sockaddr*) &server_address, &server_address_length) == PN_OK);

    pn::udp::Client client;
    CHECK(client.connect((struct sockaddr*) &server_address, server_address_length));

    static constexpr char datagram[] = "header:payload";
    CHECK(client.send(datagram, sizeof datagram - 1));

    // Peeking at the front of a datagram must not consume it
    char header[6];
    struct sockaddr_storage peer_address = {};
    socklen_t peer_address_length = sizeof peer_address;
    pn::Result<size_t> peeked = server.peekfrom(header, sizeof header, (struct sockaddr*) &peer_address, &peer_address_length);
    CHECK(!peeked); // The datagram does not fit, so it is reported as truncated
    CHECK(peeked.error().code == std::errc::message_size);

    char buf[64];
    pn::Result<size_t> received = server.recv(buf, sizeof buf);
    CHECK(received);
    CHECK(*received == sizeof datagram - 1);
    CHECK(std::string(buf, *received) == datagram);

    // And a peek that does fit leaves it for the next receive
    CHECK(client.send(datagram, sizeof datagram - 1));
    peeked = server.peek(buf, sizeof buf);
    CHECK(peeked);
    CHECK(*peeked == sizeof datagram - 1);
    received = server.recv(buf, sizeof buf);
    CHECK(received);
    CHECK(*received == sizeof datagram - 1);
}
