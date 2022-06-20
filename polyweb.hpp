#include "Polynet/polynet.hpp"
#include <boost/algorithm/string.hpp>
#include <thread>
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
        thread_local int last_error; // NOLINT

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

    inline void clean_up_target(std::string& target) {
        if (target.size() > 1 && target.back() == '/') {
            target.pop_back();
        }
    }

    typedef std::unordered_map<std::string, std::string, detail::case_insensitive_hasher, detail::case_insensitive_comparer> HTTPHeaders;

    class HTTPRequest {
    public:
        std::string method;
        std::string target;
        std::string http_version = "HTTP/1.1";
        HTTPHeaders headers;
        std::vector<char> body;

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

            ret.insert(ret.end(), {'\r', '\n'});
            ret.insert(ret.end(), this->body.begin(), this->body.end());

            return ret;
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
        std::string http_version = "HTTP/1.1";
        std::string status_code;
        std::string reason_phrase;
        HTTPHeaders headers;
        std::vector<char> body;

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

            ret.insert(ret.end(), {'\r', '\n'});
            ret.insert(ret.end(), this->body.begin(), this->body.end());

            return ret;
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
        std::unordered_map<std::string, RouteCallback> routes;

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
                this->backlog = s.backlog;
                s.backlog = -1;
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

        int listen(int backlog) {
            if (pn::tcp::Server::listen([](pn::tcp::Connection& conn, void* data) -> bool {
                    auto server = (Server*) data;
                    pw::Connection web_conn(conn.fd, conn.addr, conn.addrlen);
                    conn.release();
                    std::thread(&pw::Server::handle_connection, server, std::move(web_conn)).detach();
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
        int handle_connection(pw::Connection conn) {
            bool keep_alive;
            do {
                HTTPRequest req;
                if (req.parse(conn) == PW_ERROR) {
                    return PW_ERROR;
                }

                if (req.headers.find("Connection") != req.headers.end()) {
                    keep_alive = boost::to_lower_copy(req.headers["Connection"]) == "keep-alive";
                } else {
                    keep_alive = false;
                }

                clean_up_target(req.target);
                if (routes.find(req.target) != routes.end()) {
                    HTTPResponse resp = routes[req.target](conn, req);
                    if (keep_alive) {
                        resp.headers["Connection"] = "Keep-Alive";
                    }

                    ssize_t result;
                    if ((result = conn.send(resp)) == 0) {
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