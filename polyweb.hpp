#ifndef _POLYWEB_HPP
#define _POLYWEB_HPP

#include "Polynet/polynet.hpp"
#include "mimetypes.hpp"
#include "threadpool.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <map>
#include <unordered_map>
#include <vector>

#define PW_ERROR PN_ERROR
#define PW_OK    PN_OK

// Errors
#define PW_ESUCCESS 0
#define PW_ENET     1
#define PW_EWEB     2

namespace pw {
    namespace detail {
        tp::ThreadPool pool;                       // NOLINT
        thread_local int last_error = PW_ESUCCESS; // NOLINT

        inline void set_last_error(int error) {
            last_error = error;
        }

        template <typename InsertIt>
        int read_until(pn::tcp::Connection& conn, InsertIt ret, const std::string& end_sequence) {
            size_t search_pos = 0;
            for (;;) {
                char c;
                ssize_t read_result;
                if ((read_result = conn.recv(&c, sizeof(c), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                    break;
                } else if (read_result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                    break;
                }

                if (c == end_sequence[search_pos]) {
                    if (++search_pos == end_sequence.size()) {
                        break;
                    }
                } else {
                    ret = c;
                    search_pos = 0;

                    if (c == end_sequence[search_pos]) {
                        if (++search_pos == end_sequence.size()) {
                            break;
                        }
                    }
                }
            }

            return PW_OK;
        }

        struct case_insensitive_comparer {
            bool operator()(const std::string& a, const std::string& b) const {
                return boost::iequals(a, b);
            }
        };

        struct case_insensitive_hasher {
            size_t operator()(const std::string& key) const {
                std::string key_copy = boost::to_lower_copy(key);
                return std::hash<std::string>()(key_copy);
            }
        };
    } // namespace detail

    inline int get_last_error(void) {
        return detail::last_error;
    }

    const char* strerror(int error = get_last_error()) { // NOLINT
        static const char* error_strings[] = {
            "Success",       // PW_ESUCCESS
            "Network error", // PW_ENET
            "Web error",     // PW_EWEB
        };

        if (error >= 0 && error < 3) {
            return error_strings[error];
        } else {
            return "Unknown error";
        }
    }

    std::string universal_strerror(int error = get_last_error()) { // NOLINT
        std::string base_error = strerror(error);
        std::string specific_error;

        switch (error) {
            case PW_ENET: {
                specific_error = pn::universal_strerror();
                break;
            }

            default: {
                return base_error;
            }
        }

        return base_error + ": " + specific_error;
    }

    inline void clean_up_target(std::string& target) {
        if (target.size() > 1 && target.back() == '/') {
            target.pop_back();
        }
    }

    std::string status_code_to_reason_phrase(const std::string& status_code) { // NOLINT
        const static std::map<std::string, std::string> conversion_mapping = {
            {"100", "Continue"},
            {"101", "Switching Protocols"},
            {"200", "OK"},
            {"201", "Created"},
            {"202", "Accepted"},
            {"203", "Non-Authoritative Information"},
            {"204", "No Content"},
            {"205", "Reset Content"},
            {"206", "Partial Content"},
            {"300", "Multiple Choices"},
            {"301", "Moved Permanently"},
            {"302", "Found"},
            {"303", "See Other"},
            {"304", "Not Modified"},
            {"305", "Use Proxy"},
            {"307", "Temporary Redirect"},
            {"400", "Bad Request"},
            {"401", "Unauthorized"},
            {"402", "Payment Required"},
            {"403", "Forbidden"},
            {"404", "Not Found"},
            {"405", "Method Not Allowed"},
            {"406", "Not Acceptable"},
            {"407", "Proxy Authentication Required"},
            {"408", "Request Time-out"},
            {"409", "Conflict"},
            {"410", "Gone"},
            {"411", "Length Required"},
            {"412", "Precondition Failed"},
            {"413", "Request Entity Too Large"},
            {"414", "Request-URI Too Large"},
            {"415", "Unsupported Media Type"},
            {"416", "Requested range not satisfiable"},
            {"417", "Expectation Failed"},
            {"500", "Internal Server Error"},
            {"501", "Not Implemented"},
            {"502", "Bad Gateway"},
            {"503", "Service Unavailable"},
            {"504", "Gateway Time-out"},
            {"505", "HTTP Version not supported"}};
        return conversion_mapping.at(status_code);
    }

    typedef std::unordered_map<std::string, std::string, detail::case_insensitive_hasher, detail::case_insensitive_comparer> HTTPHeaders;

    class HTTPRequest {
    public:
        std::string method;
        std::string target;
        HTTPHeaders headers;
        std::vector<char> body;
        std::string http_version = "HTTP/1.1";

        HTTPRequest(void) = default;
        HTTPRequest(const std::string& method, const std::string& target, const HTTPHeaders& headers = {}, const std::vector<char>& body = {}, const std::string& http_version = "HTTP/1.1") :
            method(method),
            target(target),
            headers(headers),
            body(body),
            http_version(http_version) { }
        HTTPRequest(const std::string& method, const std::string& target, const HTTPHeaders& headers = {}, const std::string& body = std::string(), const std::string& http_version = "HTTP/1.1") :
            method(method),
            target(target),
            headers(headers),
            body(body.begin(), body.end()),
            http_version(http_version) { }

        std::vector<char> build(void) const {
            std::vector<char> ret;

            ret.insert(ret.end(), this->method.begin(), this->method.end());
            ret.push_back(' ');
            ret.insert(ret.end(), this->target.begin(), this->target.end());
            ret.push_back(' ');
            ret.insert(ret.end(), this->http_version.begin(), this->http_version.end());
            ret.insert(ret.end(), {'\r', '\n'});

            for (const auto& header : this->headers) {
                ret.insert(ret.end(), header.first.begin(), header.first.end());
                ret.insert(ret.end(), {':', ' '});
                ret.insert(ret.end(), header.second.begin(), header.second.end());
                ret.insert(ret.end(), {'\r', '\n'});
            }

            if (!this->body.empty()) {
                if (headers.find("Content-Length") == headers.end()) {
                    std::string header = "Content-Length: " + std::to_string(this->body.size()) + "\r\n";
                    ret.insert(ret.end(), header.begin(), header.end());
                }

                ret.insert(ret.end(), {'\r', '\n'});
                ret.insert(ret.end(), this->body.begin(), this->body.end());
            } else {
                ret.insert(ret.end(), {'\r', '\n'});
            }

            return ret;
        }

        inline std::string build_str(void) const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn) {
            std::vector<char> method;
            if (detail::read_until(conn, std::back_inserter(method), " ") == PW_ERROR) {
                return PW_ERROR;
            }
            if (method.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }
            this->method = std::string(method.begin(), method.end());

            std::vector<char> target;
            if (detail::read_until(conn, std::back_inserter(target), " ") == PW_ERROR) {
                return PW_ERROR;
            }
            if (target.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }
            this->target = std::string(target.begin(), target.end());

            std::vector<char> http_version;
            if (detail::read_until(conn, std::back_inserter(http_version), "\r\n") == PW_ERROR) {
                return PW_ERROR;
            }
            if (http_version.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }
            this->http_version = std::string(http_version.begin(), http_version.end());

            for (;;) {
                std::vector<char> header_name;
                if (detail::read_until(conn, std::back_inserter(header_name), ": ") == PW_ERROR) {
                    return PW_ERROR;
                }
                if (header_name.empty()) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                }

                std::vector<char> header_value;
                if (detail::read_until(conn, std::back_inserter(header_value), "\r\n") == PW_ERROR) {
                    return PW_ERROR;
                }
                boost::trim_left(header_value);
                if (header_value.empty()) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                }

                {
                    std::string string_header_name = std::string(header_name.begin(), header_name.end());
                    std::string string_header_value = std::string(header_value.begin(), header_value.end());
                    this->headers[std::move(string_header_name)] = std::move(string_header_value);
                }

                char end_check_buf[2];
                ssize_t read_result;
#ifdef _WIN32
                for (;;) {
                    if ((read_result = stream.recv(end_check_buf, sizeof(end_check_buf), MSG_PEEK)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (read_result == PN_ERROR) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (read_result == sizeof(end_check_buf)) {
                        break;
                    }
                }
#else
                if ((read_result = conn.recv(end_check_buf, sizeof(end_check_buf), MSG_PEEK | MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PN_ERROR) {
                    return PW_ERROR;
                }
#endif

                if (memcmp("\r\n", end_check_buf, sizeof(end_check_buf)) == 0) {
                    if ((read_result = conn.recv(end_check_buf, sizeof(end_check_buf), MSG_WAITALL)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (read_result == PN_ERROR) {
                        return PW_ERROR;
                    }

                    break;
                }
            }

            if (headers.find("Content-Length") != headers.end()) {
                this->body.resize(std::stoi(headers["Content-Length"]));

                ssize_t read_result;
                if ((read_result = conn.recv(body.data(), body.size(), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PN_ERROR) {
                    return PW_ERROR;
                }
            }

            return PW_OK;
        }
    };

    class HTTPResponse {
    public:
        std::string status_code;
        std::string reason_phrase;
        std::vector<char> body;
        HTTPHeaders headers;
        std::string http_version = "HTTP/1.1";

        HTTPResponse(void) = default;
        HTTPResponse(const std::string& status_code, const std::vector<char>& body = {}, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body),
            headers(headers),
            http_version(http_version) { }
        HTTPResponse(const std::string& status_code, const std::string& body = std::string(), const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body.begin(), body.end()),
            headers(headers),
            http_version(http_version) { }

        std::vector<char> build(void) const {
            std::vector<char> ret;

            ret.insert(ret.end(), this->http_version.begin(), this->http_version.end());
            ret.push_back(' ');
            ret.insert(ret.end(), this->status_code.begin(), this->status_code.end());
            ret.push_back(' ');
            ret.insert(ret.end(), this->reason_phrase.begin(), this->reason_phrase.end());
            ret.insert(ret.end(), {'\r', '\n'});

            for (const auto& header : this->headers) {
                ret.insert(ret.end(), header.first.begin(), header.first.end());
                ret.insert(ret.end(), {':', ' '});
                ret.insert(ret.end(), header.second.begin(), header.second.end());
                ret.insert(ret.end(), {'\r', '\n'});
            }

            if (!this->body.empty()) {
                if (headers.find("Content-Length") == headers.end()) {
                    std::string header = "Content-Length: " + std::to_string(this->body.size()) + "\r\n";
                    ret.insert(ret.end(), header.begin(), header.end());
                }

                ret.insert(ret.end(), {'\r', '\n'});
                ret.insert(ret.end(), this->body.begin(), this->body.end());
            } else {
                ret.insert(ret.end(), {'\r', '\n'});
            }

            return ret;
        }

        inline std::string build_str(void) const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn) {
            std::vector<char> http_version;
            if (detail::read_until(conn, std::back_inserter(http_version), " ") == PW_ERROR) {
                return PW_ERROR;
            }
            if (http_version.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }
            this->http_version = std::string(http_version.begin(), http_version.end());

            std::vector<char> status_code;
            if (detail::read_until(conn, std::back_inserter(status_code), " ") == PW_ERROR) {
                return PW_ERROR;
            }
            if (status_code.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }
            this->status_code = std::string(status_code.begin(), status_code.end());

            std::vector<char> reason_phrase;
            if (detail::read_until(conn, std::back_inserter(reason_phrase), "\r\n") == PW_ERROR) {
                return PW_ERROR;
            }
            if (reason_phrase.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }
            this->reason_phrase = std::string(reason_phrase.begin(), reason_phrase.end());

            for (;;) {
                std::vector<char> header_name;
                if (detail::read_until(conn, std::back_inserter(header_name), ": ") == PW_ERROR) {
                    return PW_ERROR;
                }
                if (header_name.empty()) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                }

                std::vector<char> header_value;
                if (detail::read_until(conn, std::back_inserter(header_value), "\r\n") == PW_ERROR) {
                    return PW_ERROR;
                }
                boost::trim_left(header_value);
                if (header_value.empty()) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                }

                {
                    std::string string_header_name = std::string(header_name.begin(), header_name.end());
                    std::string string_header_value = std::string(header_value.begin(), header_value.end());
                    this->headers[std::move(string_header_name)] = std::move(string_header_value);
                }

                char end_check_buf[2];
                ssize_t read_result;
#ifdef _WIN32
                for (;;) {
                    if ((read_result = stream.recv(end_check_buf, sizeof(end_check_buf), MSG_PEEK)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (read_result == PN_ERROR) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (read_result == sizeof(end_check_buf)) {
                        break;
                    }
                }
#else
                if ((read_result = conn.recv(end_check_buf, sizeof(end_check_buf), MSG_PEEK | MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PN_ERROR) {
                    return PW_ERROR;
                }
#endif

                if (memcmp("\r\n", end_check_buf, sizeof(end_check_buf)) == 0) {
                    if ((read_result = conn.recv(end_check_buf, sizeof(end_check_buf), MSG_WAITALL)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (read_result == PN_ERROR) {
                        return PW_ERROR;
                    }

                    break;
                }
            }

            if (headers.find("Content-Length") != headers.end()) {
                this->body.resize(std::stoi(headers["Content-Length"]));

                ssize_t read_result;
                if ((read_result = conn.recv(body.data(), body.size(), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PN_ERROR) {
                    return PW_ERROR;
                }
            }

            return PW_OK;
        }
    };

    class Connection: public pn::tcp::Connection {
    public:
        Connection(void) = default;
        Connection(const Connection&) = default;
        Connection(Connection&& s) {
            *this = std::move(s);
        }
        Connection(pn::sockfd_t fd) :
            pn::tcp::Connection(fd) { }
        Connection(struct sockaddr addr, socklen_t addrlen) :
            pn::tcp::Connection(addr, addrlen) { }
        Connection(pn::sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            pn::tcp::Connection(fd, addr, addrlen) { }

        Connection& operator=(const Connection&) = default;
        inline Connection& operator=(Connection&& s) {
            pn::tcp::Connection::operator=(std::move(s));
            return *this;
        }

        ssize_t send(const HTTPResponse& resp) {
            auto data = resp.build();
            ssize_t result;
            if ((result = pn::tcp::Connection::send(data.data(), data.size(), MSG_WAITALL)) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
            }
            return result;
        }
    };

    typedef std::function<HTTPResponse(pw::Connection&, const HTTPRequest&)> RouteCallback;

    class Server: public pn::tcp::Server {
    public:
        Server(void) = default;
        Server(const Server&) = default;
        Server(Server&& s) {
            *this = std::move(s);
        }
        Server(pn::sockfd_t fd) :
            pn::tcp::Server(fd) { }
        Server(struct sockaddr addr, socklen_t addrlen) :
            pn::tcp::Server(addr, addrlen) { }
        Server(pn::sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            pn::tcp::Server(fd, addr, addrlen) { }

        Server& operator=(const Server&) = default;
        inline Server& operator=(Server&& s) {
            pn::tcp::Server::operator=(std::move(s));
            if (this != &s) {
                this->routes = std::move(s.routes);
            }

            return *this;
        }

        inline int bind(const std::string& host, const std::string& port) {
            if (pn::tcp::Server::bind(host, port) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
            return PW_OK;
        }

        inline int bind(const std::string& host, unsigned short port) {
            std::string str_port = std::to_string(port);
            return bind(host, str_port);
        }

        inline int bind(struct sockaddr* addr, socklen_t addrlen) {
            if (pn::tcp::Server::bind(addr, addrlen) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
            return PW_OK;
        }

        void route(std::string target, RouteCallback route_cb) {
            clean_up_target(target);
            routes[target] = route_cb;
        }

        void unroute(std::string target) {
            clean_up_target(target);
            if (routes.find(target) != routes.end()) {
                routes.erase(target);
            }
        }

        int listen(int backlog) {
            if (pn::tcp::Server::listen([](pn::tcp::Connection& conn, void* data) -> bool {
                    auto server = (Server*) data;
                    detail::pool.schedule([conn = std::move(conn)](void* data) {
                        auto server = (Server*) data;
                        pw::Connection web_conn(conn.fd, conn.addr, conn.addrlen);
                        server->handle_connection(std::move(web_conn));
                    },
                        server);
                    return true;
                },
                    backlog,
                    this) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
            return PW_OK;
        }

    protected:
        std::unordered_map<std::string, RouteCallback> routes;

        int handle_connection(pw::Connection conn) {
            bool keep_alive;
            do {
                HTTPRequest req;
                if (req.parse(conn) == PW_ERROR) {
                    HTTPResponse resp;
                    switch (get_last_error()) {
                        case PW_ENET: {
                            resp = HTTPResponse("500", "500 " + status_code_to_reason_phrase("500") + '\n', {{"Content-Type", "text/plain"}});
                            break;
                        }

                        case PW_EWEB: {
                            resp = HTTPResponse("400", "400 " + status_code_to_reason_phrase("400") + '\n', {{"Content-Type", "text/plain"}});
                            break;
                        }
                    }
                    conn.send(resp);
                    return PW_ERROR;
                }

                if (req.headers.find("Connection") != req.headers.end()) {
                    if (req.http_version == "HTTP/1.1") {
                        keep_alive = boost::to_lower_copy(req.headers["Connection"]) != "close";
                    } else {
                        keep_alive = boost::to_lower_copy(req.headers["Connection"]) == "keep-alive";
                    }
                } else {
                    keep_alive = req.http_version == "HTTP/1.1";
                }

                clean_up_target(req.target);

                std::string route_target;
                for (const auto& route : routes) {
                    if (route.first == req.target) {
                        route_target = route.first;
                        break;
                    } else if (boost::ends_with(route.first, "/*") && boost::starts_with(req.target, route.first.substr(0, route.first.size() - 1)) && route.first.size() > route_target.size()) {
                        route_target = route.first;
                    }
                }

                if (!route_target.empty()) {
                    HTTPResponse resp;
                    try {
                        resp = routes[route_target](conn, req);
                    } catch (const pw::HTTPResponse& error_resp) {
                        resp = error_resp;
                    } catch (...) {
                        resp = HTTPResponse("500", "500 " + status_code_to_reason_phrase("500") + '\n', {{"Content-Type", "text/plain"}});
                    }
                    
                    resp.headers["Server"] = "Polyweb/net Engine";
                    if (keep_alive) {
                        resp.headers["Connection"] = "keep-alive";
                    }

                    ssize_t result;
                    if ((result = conn.send(resp)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (result == PW_ERROR) {
                        return PW_ERROR;
                    }
                } else {
                    ssize_t result;
                    if ((result = conn.send(HTTPResponse("404", "404 " + status_code_to_reason_phrase("404") + '\n', {{"Content-Type", "text/plain"}}))) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (result == PW_ERROR) {
                        return PW_ERROR;
                    }
                }
            } while (conn.is_valid() && keep_alive);
            return PW_OK;
        }
    };
} // namespace pw

#endif
