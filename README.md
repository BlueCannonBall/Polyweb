# Polyweb

Polyweb is a C++ HTTP client/server library built on [Polynet](https://github.com/BlueCannonBall/Polynet). It provides routing, TLS, WebSockets, streamed message bodies, HTTP proxy tunneling, and server-sent event helpers.

Polyweb uses **blocking socket I/O**. Server connections are handled concurrently by connection tasks; coroutine generators produce outgoing data chunks, not asynchronous socket operations. It is a networking toolkit rather than a full application framework with sessions, an ORM, or a template engine.

## Features

- HTTP/1.0 and HTTP/1.1 request/response handling, including keep-alive and chunked bodies.
- HTTP and HTTPS clients and servers, with OpenSSL-backed TLS through Polynet.
- Exact-path and wildcard-prefix routes, query parameters, and customizable error responses.
- Buffered or streamed HTTP bodies, with configurable parser limits.
- WebSocket clients and servers, streamed outgoing messages, and close/ping handling.
- HTTP proxy CONNECT support through `proxied_fetch` and `make_proxied_ws_client`.
- SSE event serialization and incremental parsing in [`sse.hpp`](sse.hpp).

See [current limitations](#current-limitations) before relying on protocol completeness or exposing a server to untrusted traffic.

## Requirements and build

Use a compiler **and standard library** supporting C++23, including `std::expected`, `std::move_only_function`, and `std::generator`. CI uses GCC 14 on Linux and MSVC's `/std:c++latest` mode on Windows. OpenSSL headers and libraries are required, including when your application only serves plaintext HTTP.

On Windows, **default verified TLS clients require an OpenSSL build with Windows certificate-store (`winstore`) support**. Polynet loads system trust through `SSL_CTX_load_verify_store` using `org.openssl.winstore://`; if that store cannot be loaded, client context initialization fails with a `load TLS trust store` error. To use an OpenSSL build without winstore support, supply an explicit CA file or directory to `pn::TLSContext::init_client` and pass that context through `ClientConfig::tls_context`. This requirement concerns default client trust loading, not plaintext HTTP or TLS server certificate loading; do not disable certificate verification as a workaround.

Obtain Polyweb together with its Polynet submodule:

```sh
git clone --recurse-submodules https://github.com/BlueCannonBall/Polyweb.git
cd Polyweb
```

For an existing checkout, run `git submodule update --init --recursive`.

Polyweb is not header-only. To build the examples below on Linux, save them as `server_main.cpp` and `client_main.cpp` in the repository root, then compile the implementation files:

```sh
sources="polyweb.cpp server.cpp client.cpp websocket.cpp string.cpp error.cpp \
Polynet/polynet.cpp Polynet/tls.cpp Polynet/error.cpp"

c++ -O2 -std=c++23 -pthread -I. server_main.cpp $sources \
    -lssl -lcrypto -o polyweb-server
c++ -O2 -std=c++23 -pthread -I. client_main.cpp $sources \
    -lssl -lcrypto -o polyweb-client
```

Keep your application's source separate from the library sources in your build system. The commands above assume OpenSSL is installed in the compiler's default search paths. On Windows, supply the OpenSSL include/library paths and link `libssl.lib`, `libcrypto.lib`, and `ws2_32.lib`; see [`tests/Polybuild.toml`](tests/Polybuild.toml) for the platform-specific settings.

## Quick start

Call `pn::init()` before networking and `pn::quit()` after networking objects and connection tasks have finished. Most networking operations return `pn::Status` (`pn::Result<void>`) or `pn::Result<T>` (`std::expected<T, pn::Error>`). Check the result before using its value; error descriptions are available through `.error().message()`.

### HTTP server

```cpp
#include "polyweb.hpp"
#include <iostream>

int run_server() {
    pw::Server server;
    server.route("/hello", pw::Route{
        [](const pw::Connection&, const pw::Request&) {
            return pw::Response(200, "Hello, World!", {{"Content-Type", "text/plain"}});
        }
    });

    if (pn::Status result = server.bind("127.0.0.1", 8000); !result) {
        std::cerr << result.error().message() << '\n';
        return 1;
    }
    if (pn::Status result = server.listen(); !result) {
        std::cerr << result.error().message() << '\n';
        return 1;
    }
    return 0;
}

int main() {
    if (pn::Status result = pn::init(); !result) {
        std::cerr << result.error().message() << '\n';
        return 1;
    }
    int code = run_server();
    if (pn::Status result = pn::quit(); !result) {
        std::cerr << result.error().message() << '\n';
        return 1;
    }
    return code;
}
```

`listen()` blocks in the accept loop. This example binds only to loopback; bind to `0.0.0.0` to accept connections on all IPv4 interfaces.

### HTTP client

Run this in another terminal while the server is listening:

```cpp
#include "polyweb.hpp"
#include <iostream>

int main() {
    if (pn::Status result = pn::init(); !result) {
        std::cerr << result.error().message() << '\n';
        return 1;
    }

    int code = 0;
    pw::Response response;
    if (pn::Status result = pw::fetch("http://127.0.0.1:8000/hello", response); !result) {
        std::cerr << result.error().message() << '\n';
        code = 1;
    } else {
        std::cout << response.status_code << '\n' << response.body_string() << '\n';
    }

    if (pn::Status result = pn::quit(); !result) {
        std::cerr << result.error().message() << '\n';
        return 1;
    }
    return code;
}
```

```sh
./polyweb-server
# In another terminal:
./polyweb-client
curl http://127.0.0.1:8000/hello
```

`fetch` also accepts a method, headers, a buffered body, or an outgoing generator. A successful `pn::Status` means the operation succeeded, not that the HTTP status was `2xx`; inspect `response.status_code` separately. `fetch` requests connection closure by default and does not maintain a reusable connection pool. Use `pw::Client` or `pw::TLSClient` for explicit connection ownership and `send`/`recv` operations.

## Routing and errors

The following route snippets can be added before `bind()` in `run_server()`.

An exact path takes precedence over wildcard routes. A wildcard matches a path prefix, and the longest matching prefix wins. Routes are not registered by HTTP method; inspect `req.method` when a handler needs method-specific behavior.

```cpp
server.route("/wildcard/", pw::Route{
    [](const pw::Connection&, const pw::Request& req) {
        return pw::Response(200, req.target, {{"Content-Type", "text/plain"}});
    },
    true // Match anything beginning with /wildcard/.
});

server.route("/multiply", pw::Route{
    [](const pw::Connection&, const pw::Request& req) {
        int x = std::stoi(req.query_parameters->at("x"));
        int y = std::stoi(req.query_parameters->at("y"));
        return pw::Response(200, std::to_string(static_cast<long long>(x) * y),
                            {{"Content-Type", "text/plain"}});
    }
});
```

Try `/multiply?x=6&y=7`. Query parameters are parsed into a map; repeated keys are not preserved as separate values. By default, query encoding/decoding treats `+` as a space; set `QueryParameters::plus_as_space` to `false` when literal-plus behavior is required.

Exceptions thrown by HTTP route callbacks are caught and converted to `500` responses. In the example, `at()` throws for a missing parameter and `std::stoi` throws for invalid or out-of-range integers. This demonstrates exception handling, not a complete input-validation policy: applications that want `400` responses should validate the input or handle those exceptions themselves.

The default error handling can include a caught exception's message in the response. To return generic error bodies instead:

```cpp
server.error_cb = [](uint16_t status, pn::StringView) {
    return pw::Response::make_basic(status);
};
```

This exception-to-response behavior does not extend to arbitrary background work or the WebSocket `open_cb` after an upgrade.

## Streaming HTTP bodies

### Sending

A `send_cb` produces `std::vector<char>` chunks through `std::generator`. The chunks are sent using HTTP chunked transfer encoding, so the complete body need not be held in memory.

```cpp
server.route("/send_stream", pw::Route{
    [](const pw::Connection&, const pw::Request&) {
        return pw::Response(200, []() -> std::generator<std::vector<char>> {
            for (int i = 0; i < 10; ++i) {
                std::string line = std::to_string(i) + '\n';
                co_yield std::vector<char>(line.begin(), line.end());
            }
        }, {{"Content-Type", "text/plain"}});
    }
});
```

Generators are consumed synchronously while the message is built/sent. A response's generator callback is consumed once; don't expect to send the same streamed response repeatedly without providing another callback. Captured or referenced application state must remain valid through transmission.

### Receiving

Routes parse the body before calling the handler by default. Set the third `pw::Route` argument, `parse_body`, to `false` to install a receiving callback first:

```cpp
server.route("/recv_stream", pw::Route{
    [](pw::Connection& conn, pw::RequestReceiver& req) {
        size_t received = 0;
        req.recv_cb = [&received](std::vector<char> chunk) {
            received += chunk.size();
            return received <= 1'000'000;
        };
        if (pn::Status result = conn.recv(req, PW_HTTP_MESSAGE_PART_BODY); !result) {
            return pw::Response(400, "Could not receive the complete body");
        }
        return pw::Response(200, std::to_string(received));
    },
    false, // Exact route, not a wildcard.
    false  // Let the handler receive the body.
});
```

Returning `false` from `recv_cb` stops reception and returns an error. The callback above enforces an application-level total size limit. `body_rlimit` limits buffered bodies; it is not an aggregate limit on streamed callback data. `body_chunk_rlimit` limits the chunks passed to the callback.

After an HTTP handler returns, the server attempts to discard unread body data before reusing the connection. If the remaining body cannot be safely drained, the connection is not kept alive. Use the connection's buffered `recv` API rather than reading directly from its socket, which could bypass bytes already buffered by Polyweb.

## TLS

Use `pw::TLSServer` with `pw::TLSRoute` and a `pn::TLSContext` initialized from a certificate chain and private key. With networking initialized, the TLS equivalent of the server setup is:

```cpp
pw::TLSServer server;
server.route("/hello", pw::TLSRoute{
    [](const pw::TLSConnection&, const pw::Request&) {
        return pw::Response(200, "Hello, World!");
    }
});
pn::TLSContext context;
if (pn::Status result = context.init_server("cert.pem", "key.pem", SSL_FILETYPE_PEM); !result) {
    std::cerr << result.error().message() << '\n';
} else if (pn::Status result = server.bind("127.0.0.1", 8443); !result) {
    std::cerr << result.error().message() << '\n';
} else if (pn::Status result = server.listen(context); !result) {
    std::cerr << result.error().message() << '\n';
}
```

See [`examples/tls_server.cpp`](examples/tls_server.cpp) for a full program. The example certificate and private key are development fixtures, not deployment credentials. `TLSServer::listen()` without a context serves plaintext, which is useful behind a TLS-terminating reverse proxy; it does not enable HTTPS automatically.

For clients, use an `https://` URL with `fetch`. The default client context loads OpenSSL's default trust store once and is shared across requests; server certificate and hostname verification are enabled. To supply your own CA settings, initialize a `pn::TLSContext` with `init_client` and assign its address to `ClientConfig::tls_context`. That pointer is borrowed: keep the context object alive while the configuration is used. Established TLS connections hold their own reference to the underlying OpenSSL context.

## WebSockets

Register a WebSocket route separately from HTTP routes. Its `open_cb` receives ownership of the upgraded connection and runs in the connection task:

```cpp
server.ws_route("/echo", pw::WSRoute{
    [](pw::WSConnection conn, pw::Request) {
        while (true) {
            pw::WSMessage message;
            if (!conn.recv(message)) {
                break;
            }
            if (message.opcode == pw::WS_OPCODE_CLOSE) {
                break;
            }
            if (message.opcode == pw::WS_OPCODE_TEXT || message.opcode == pw::WS_OPCODE_BINARY) {
                if (!conn.send(std::move(message))) {
                    break;
                }
            }
        }
    }
});
```

An optional `connect_cb` can accept or reject the HTTP upgrade before `open_cb` runs. `recv` replies to pings and close frames by default, but still returns those messages to the caller. `ws_close` sends a close frame; `close` closes the underlying transport.

For clients, `pw::make_ws_client` initializes a `pw::TLSWSClient` for either a `ws://` or `wss://` URL. See [`examples/websocket_client.cpp`](examples/websocket_client.cpp). Use `TLSWSRoute`/`TLSWSConnection` with a TLS server. Consult the [WebSocket limitations](#current-limitations) before treating the implementation as RFC-complete.

## Server-sent events

Include `sse.hpp` separately. `SSEEvent` builds event/data records; `SSEParser` accepts incremental data chunks and invokes a callback for completed events. These helpers do not implement automatic reconnection, `Last-Event-ID`, or retry handling.

For example, after including `sse.hpp`, add a streamed SSE route:

```cpp
server.route("/events", pw::Route{
    [](const pw::Connection&, const pw::Request&) {
        return pw::Response(200, []() -> std::generator<std::vector<char>> {
            std::string event = pw::SSEEvent("greeting", "Hello, World!").build();
            co_yield std::vector<char>(event.begin(), event.end());
        }, {{"Content-Type", "text/event-stream"}, {"Cache-Control", "no-cache"}});
    }
});
```

This sends one event and ends the response. A generator can produce additional events, but waiting for them occupies the connection task. For receiving, `SSEParser` can be called from an HTTP response's `recv_cb`; its event callback returns `false` to stop parsing.

## HTTP proxies

`proxied_fetch` takes the destination URL followed by the HTTP proxy URL and uses CONNECT to establish the tunnel. HTTPS then performs TLS over that tunnel. After `pn::init()`:

```cpp
pw::Response response;
if (pn::Status result = pw::proxied_fetch("https://example.com/", "http://127.0.0.1:8080", response); !result) {
    std::cerr << result.error().message() << '\n';
}
```

This requires a proxy that permits CONNECT to the destination. `make_proxied_ws_client` provides the corresponding WebSocket setup. These APIs do not imply SOCKS support or that Polyweb itself is a proxy server.

## Configuration and execution model

Configure a server before starting its accept loop. For example:

```cpp
server.config.tcp.recv_timeout = std::chrono::seconds(15);
server.config.tcp.send_timeout = std::chrono::seconds(15);
server.config.http.body_rlimit = 1'000'000;
server.config.ws.message_rlimit = 1'000'000;
```

Choose timeouts for your workload: a receive timeout suitable for short HTTP requests may disconnect an idle WebSocket or long poll. Socket I/O timeouts are not a single end-to-end deadline for an entire request.

| Setting | Default |
| --- | --- |
| Server send/receive timeout | None (`0` milliseconds) |
| `ClientConfig` send/receive timeout | 30 seconds each |
| TCP keepalive / TCP_NODELAY | Enabled |
| Receive buffer capacity | 4,000 bytes |
| HTTP header count limit | 100 |
| HTTP header name / value limit | 500 / 4,000,000 bytes |
| Buffered HTTP body limit | 32,000,000 bytes |
| HTTP callback chunk limit | 16,000,000 bytes |
| HTTP miscellaneous read limit | 1,000 bytes |
| WebSocket callback chunk / buffered message limit | 16,000,000 / 32,000,000 bytes |
| Listen backlog | 128 |

`ServerConfig` contains `tcp`, `http`, and `ws` settings. `ClientConfig` provides corresponding settings and an optional borrowed TLS context. Direct `Client`/`TLSClient` users configure their connection themselves; the 30-second defaults belong to the helpers using `ClientConfig`.

Despite its name, `WSConfig::frame_rlimit` limits receive-callback chunk size, not the total size of a frame. `message_rlimit` limits buffered message data; callback-based reception needs its own aggregate message-size policy.

- The shared `pw::threadpool` starts with at least 16 workers. `resize()` changes its target worker count, **not** the maximum number of active connections: servers can launch extra connection threads when the pool is busy.
- The `listen` configuration callback runs on the accepting thread. Keep it short; returning `false` rejects that connection. TLS handshakes and HTTP handling run in connection tasks.
- Register routes and set configuration/error callbacks before listening. Runtime mutation is not synchronized with handlers.
- HTTP handler connection/request references are borrowed for that invocation. WebSocket `open_cb` receives a moved, owning connection. Synchronize shared application state accessed by concurrent handlers.
- Server destruction waits for its tracked connection tasks. Closing the listener is not cancellation of accepted connections. Stop accepting and arrange for active handlers/connections to finish before destroying the server or calling `pn::quit()`; zero timeouts and idle peers can make that wait unbounded.
- Do not close or move a connection while another thread is performing I/O on it. Connection ownership does not make every operation concurrently safe.

## Standalone threadpool and tasks

[`threadpool.hpp`](threadpool.hpp) is a header-only C++23 component in namespace `tp`. It can be used without Polyweb, Polynet, OpenSSL, or networking initialization. It requires `std::move_only_function` and thread support.

### Scheduling and tracking work

Save this as `pool_main.cpp` in the repository root:

```cpp
#include "threadpool.hpp"
#include <iostream>
#include <memory>
#include <stdexcept>

int main() {
    tp::ThreadPool pool(2);
    tp::TaskManager tasks;
    int value = 0;

    auto success = pool.schedule([&value, input = std::make_unique<int>(42)] {
        value = *input;
    });
    tasks.insert(success);

    auto failure = pool.schedule([] {
        throw std::runtime_error("demo failure");
    });
    tasks.insert(failure);

    tasks.wait();
    if (success->wait() != tp::TASK_STATUS_SUCCESS ||
        failure->wait() != tp::TASK_STATUS_FAILURE) {
        return 1;
    }
    std::cout << "value=" << value << '\n';
    if (auto error = failure->get_exception_ptr()) {
        try {
            std::rethrow_exception(error);
        } catch (const std::exception& e) {
            std::cout << "failure=" << e.what() << '\n';
        }
    }
}
```

```sh
c++ -std=c++23 -pthread -I. pool_main.cpp -o pool-example
./pool-example
```

The output is `value=42` followed by `failure=demo failure`. The write to `value` is read only after task completion; shared data used while tasks are running still needs synchronization. Move-only captures are supported, and `schedule` returns a `std::shared_ptr<tp::Task>` rather than a future holding a return value.

### Task API

| Operation | Behavior |
| --- | --- |
| `pool.schedule(callable)` | Queues work for pool workers; returns a task handle. |
| `pool.schedule(callable, true)` | May launch a detached overflow thread when the pool is busy. |
| `task->get_status()` | Reads the current status without waiting. |
| `task->wait()` | Waits for completion and returns the final status. |
| `task->wait_for(duration)` / `wait_until(time_point)` | Returns the status at completion or timeout; a timeout does not cancel the task. |
| `task->get_exception_ptr()` | Retrieves a captured exception; use after completion to inspect a failure. |
| `tasks.insert(task)` | Adds a weak reference to a task for group waiting. |
| `tasks.wait()` | Waits until no tracked, live task is still running. |
| `pool.size()` / `resize(count)` | Reads or changes the target pool worker count. |

`TASK_STATUS_RUNNING` covers both queued and executing work. Successful completion sets `TASK_STATUS_SUCCESS`; a thrown exception sets `TASK_STATUS_FAILURE`. Waiting does not rethrow exceptions. An empty callable fails with `std::bad_function_call`.

`tp::Task` can also be constructed directly and executed with `execute()` when no pool is needed. Treat execution as single-use: do not call `execute()` on a task already scheduled with a pool, or execute the same task concurrently. A directly constructed task remains in the running state until someone executes it.

`TaskManager` does not schedule work, own tasks, or collect/rethrow their failures. Its destructor waits for the live tasks it still tracks. Retain task handles when you need results or failure details after completion; expired weak references cannot provide that information. Stop inserting tasks before group waiting or destruction: `wait()` is not a barrier against future submissions, and destruction must not race with insertion.

### Capacity and lifetime

- Supply a positive worker count for ordinary queued work. The default constructor uses `std::thread::hardware_concurrency()`, which may return zero; a zero-worker pool cannot execute queued work until workers are added.
- With the default `launch_if_busy = false`, work uses the pool workers, but the pending queue is unbounded. Limit submissions at the application level when a backlog would consume too much memory.
- With `launch_if_busy = true`, overflow threads are outside the target worker count and have no configured ceiling. If an overflow thread cannot be created, the task is queued instead. `size()` does not count these extra threads.
- `resize()` changes a target, not an instantaneous worker count. Shrinking does not interrupt an executing task.
- There is no task cancellation or automatic recovery from a blocked callable. Avoid having all workers wait for additional queued tasks that require the same pool to run.
- Pool destruction waits for its pool workers to exit; it does not guarantee that pending queued tasks are drained or detached overflow tasks have finished. Wait explicitly for submitted tasks while the pool is still alive, and keep captured references alive until those tasks complete.
- Do not destroy a pool while callers are still using it. A task wait can be unbounded if the callable never finishes.

### Using Polyweb's shared pool

Polyweb's `pw::threadpool` is the same `tp::ThreadPool` type and is shared across its servers. Configure it before starting listeners:

```cpp
pw::threadpool.resize(8);
```

A server task handles a connection, not just one request: keep-alive requests, WebSockets, and long polls can retain that task. Polyweb servers schedule with overflow enabled, so eight target workers do **not** mean eight maximum active connections. Standalone application work can use a separate `tp::ThreadPool` to avoid sharing those workers.

## Current limitations

Polyweb implements HTTP/1.x, not HTTP/2 or HTTP/3. Its tests and fuzzing infrastructure are not a claim of complete HTTP or WebSocket conformance. Current implementation boundaries include:

- HTTP response bodies are received using `Content-Length` or chunked framing. Close-delimited response bodies are not currently consumed. `fetch` excludes the body when reading a response to `HEAD` through the message-parts mechanism.
- `Headers` is a case-insensitive map with one value per name; repeated received fields overwrite previous values. In particular, it does not preserve multiple `Set-Cookie` fields.
- WebSocket clients use a fixed default handshake key and a zero default masking key, and do not validate `Sec-WebSocket-Accept`. Handling of control frames interleaved with fragmented data messages also needs protocol hardening.
- There is no built-in bounded connection admission or bounded graceful-shutdown policy. Applications exposed to untrusted clients need appropriate connection limits, timeouts, and lifecycle management; a reverse proxy can enforce limits at the edge.

The public API is declared in [`polyweb.hpp`](polyweb.hpp), with transport/TLS APIs in [`Polynet/polynet.hpp`](Polynet/polynet.hpp) and [`Polynet/tls.hpp`](Polynet/tls.hpp).

## Tests and fuzzing

The test suite uses [Polybuild](https://github.com/BlueCannonBall/Polybuild) and runs against scripted connections and local loopback sockets/TLS, without depending on external web services:

```sh
cd tests
make MODE=debug
./polyweb-tests
```

Coverage includes fragmented HTTP input, streamed bodies, partial transport reads/writes, WebSocket framing, TLS verification failures, bidirectional TLS traffic, and concurrent handshakes. CI configures Linux debug, ASan/UBSan, TSan, and Windows debug jobs.

Clean before changing sanitizer configurations, then rebuild:

```sh
make clean
make MODE=debug ASAN=1
./polyweb-tests

# For ThreadSanitizer instead:
make clean
make MODE=debug TSAN=1
./polyweb-tests
```

The generated `tests/Makefile` and `tests/.polybuild.mk` are committed. Only run Polybuild after changing `tests/Polybuild.toml`, then commit the regenerated files.

LibFuzzer targets cover HTTP requests/responses, WebSockets, URLs, and decoders. From the repository root, with a compatible Clang 20 or newer toolchain and standard library:

```sh
cd tests/fuzz
./build.sh http_request
./http_request corpus/http_request seeds/http_request -max_total_time=60
```

Set `CXX` to select the compiler. Running `./build.sh` without target names builds all five targets. CI configures seed runs on pushes/pull requests and longer scheduled fuzzing runs; see [the workflows](.github/workflows).

## More examples

- [`examples/server.cpp`](examples/server.cpp): plaintext routes and streaming.
- [`examples/tls_server.cpp`](examples/tls_server.cpp): TLS server setup.
- [`examples/client.cpp`](examples/client.cpp): HTTPS fetch.
- [`examples/websocket_client.cpp`](examples/websocket_client.cpp): WebSocket client.
- [`examples/hacker_news.cpp`](examples/hacker_news.cpp): another client application.

Examples using public services require network access. Read and adapt their addresses, ports, certificate paths, and input handling for your application.

## License

See [`LICENSE`](LICENSE) for Polyweb's license and [`Polynet/LICENSE`](Polynet/LICENSE) for Polynet's license.
