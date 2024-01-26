# Polyweb
A web framework utilizing Polynet.

## Quick Examples
```cpp
pn::init();

pw::Server server;

server.route("/hello_world",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req, void* data) {
            return pw::HTTPResponse(200, "Hello, World!", {{"Content-Type", "text/plain"}});
        },
    });

// Since this is a wildcard route, anything may come after /wildcard/
server.route("/wildcard/",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req, void* data) {
            return pw::HTTPResponse(200, req.target, {{"Content-Type", "text/plain"}});
        },
        true,
    });

server.route("/multiply",
    pw::HTTPRoute {
        [](const pw::Connection& conn, const pw::HTTPRequest& req, void* data) {
            int x = std::stoi(req.query_parameters->find("x")->second);
            int y = std::stoi(req.query_parameters->find("y")->second);
            return pw::HTTPResponse(200, std::to_string(x * y), {{"Content-Type", "text/plain"}});
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

server.close();
pn::quit();
```
Note that Polyweb functions/methods throw Polyweb errors while methods inherited from Polynet throw Polynet errors. Do not do anything with the `conn` argument unless you know what you are doing. The `data` argument can be used to pass user data to the callbacks, avoiding the use of lambda captures. See `polyweb.h` to check out more ways to use Polyweb.
