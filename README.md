# Polyweb
A web framework utilizing Polynet.

## Tests

The test suite uses [Polybuild](https://github.com/BlueCannonBall/Polybuild) and runs entirely against local scripted connections and loopback TLS:

```sh
cd tests
polybuild
make MODE=debug
./polyweb-tests
```

Use `ASAN=1` or `TSAN=1` with `make` to build the AddressSanitizer/UndefinedBehaviorSanitizer or ThreadSanitizer configurations, respectively. Re-run `polybuild` after changing `tests/Polybuild.toml`.

## Quick Examples
```cpp
(void) pn::init();

pw::Server server;

server.route("/hello_world",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req) {
            return pw::HTTPResponse(200, "Hello, World!", {{"Content-Type", "text/plain"}});
        },
    });

// Since this is a wildcard route, anything may come after /wildcard/
server.route("/wildcard/",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req) {
            return pw::HTTPResponse(200, req.target, {{"Content-Type", "text/plain"}});
        },
        true,
    });

server.route("/multiply",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req) {
            int x = std::stoi(req.query_parameters->find("x")->second);
            int y = std::stoi(req.query_parameters->find("y")->second);
            return pw::HTTPResponse(200, std::to_string(x * y), {{"Content-Type", "text/plain"}});
        },
    });

server.route("/send_stream",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req) {
            return pw::HTTPResponse(200, [i = 0]() mutable -> std::vector<char> {
                if (i < 10) {
                    std::string str = std::to_string(i++);
                    return std::vector<char>(str.begin(), str.end());
                }
                return {};
            },
                {{"Content-Type", "text/plain"}});
        },
    });

server.route("/recv_stream",
    pw::HTTPRoute {
        [](pw::Connection& conn, pw::HTTPRequestReceiver& req) {
            std::vector<char> body;
            req.recv_cb = [&body](std::vector<char> chunk) {
                body.insert(body.end(), chunk.begin(), chunk.end());
                return true;
            };
            if (pn::Status result = conn.recv(req, PW_HTTP_MESSAGE_PART_BODY); !result) {
                return pw::HTTPResponse(500, result.error().message());
            }

            return pw::HTTPResponse(200, body);
        },
        false,
        false, // tells Polyweb not to parse the body
    });

if (pn::Status result = server.bind("0.0.0.0", 8000); !result) {
    std::cerr << "Error: " << result.error().message() << std::endl;
    exit(EXIT_FAILURE);
}

if (pn::Status result = server.listen(); !result) {
    std::cerr << "Error: " << result.error().message() << std::endl;
    exit(EXIT_FAILURE);
}

(void) server.close();
(void) pn::quit();
```
Note that Polyweb and Polynet functions return `pn::Status` (`pn::Result<void>`) or `pn::Result<T>` (`std::expected<T, pn::Error>`). Error messages can be retrieved via `.error().message()`. Do not do anything with the `conn` argument unless you know what you are doing. See `polyweb.hpp` to check out more ways to use Polyweb.
