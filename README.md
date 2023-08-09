# Polyweb
A backend web framework utilizing Polynet.

## Quick Examples
```cpp
pw::Server server;

server.route("/hello_world",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req) -> pw::HTTPResponse {
            return pw::HTTPResponse("Hello, World!", {{"Content-Type", "text/plain"}});
        },
    });

// Since this is a wildcard route, anything may come after /wildcard/
server.route("/wildcard/",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req) -> pw::HTTPResponse {
            return pw::HTTPResponse(req.target, {{"Content-Type", "text/plain"}});
        },
        true,
    });

server.route("/multiply",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req) -> pw::HTTPResponse {
            int x = std::stoi(req.query_parameters->find("x")->second);
            int y = std::stoi(req.query_parameters->find("y")->second);
            return pw::HTTPResponse(std::to_string(x * y), {{"Content-Type", "text/plain"}});
        },
    });

if (server.bind("0.0.0.0", 8000) == PN_ERROR) {
    std::cerr << "Error: " << pn::universal_strerror() << std::endl;
    exit(EXIT_FAILURE);
}

if (server.listen() == PN_ERROR) {
    std::cerr << "Error: " << pw::universal_strerror() << std::endl;
    exit(EXIT_FAILURE);
}
```
Note that Polyweb functions/methods throw Polyweb errors while methods inherited from Polynet throw Polynet errors. Do not attempt to call `recv` on a `pw::Connection`. See `polyweb.h` to check out more ways to use Polynet.
