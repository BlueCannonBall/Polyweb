# Polyweb
A web framework utilizing Polynet.

## Quick Examples
```cpp
pn::init();

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

server.route("/stream",
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
Note that Polyweb functions/methods throw Polyweb errors while methods inherited from Polynet throw Polynet errors. Do not do anything with the `conn` argument unless you know what you are doing. See `polyweb.hpp` to check out more ways to use Polyweb.
