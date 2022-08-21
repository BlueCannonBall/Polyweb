#ifndef _POLYWEB_HPP
#define _POLYWEB_HPP

#include "Polynet/polynet.hpp"
#include "threadpool.hpp"
#include <boost/algorithm/string.hpp>
#include <cstdint>
#include <ctime>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#define PW_ERROR       PN_ERROR
#define PW_OK          PN_OK
#define PW_SERVER_NAME "Polyweb/net Engine"

// Errors
#define PW_ESUCCESS 0
#define PW_ENET     1
#define PW_EWEB     2

#define PW_DEFAULT_SERVER_ON_ERROR [](const std::string& status_code) -> pw::HTTPResponse { \
    return pw::HTTPResponse::create_basic(status_code);                                     \
}

// WebSocket macros
#define PW_WS_VERSION 13

#define PW_GET_WS_FRAME_FIN(frame_header)            (frame_header[0] & 0b10000000)
#define PW_GET_WS_FRAME_RSV1(frame_header)           (frame_header[0] & 0b01000000)
#define PW_GET_WS_FRAME_RSV2(frame_header)           (frame_header[0] & 0b00100000)
#define PW_GET_WS_FRAME_RSV3(frame_header)           (frame_header[0] & 0b00010000)
#define PW_GET_WS_FRAME_OPCODE(frame_header)         (frame_header[0] & 0b00001111)
#define PW_GET_WS_FRAME_MASKED(frame_header)         (frame_header[1] & 0b10000000)
#define PW_GET_WS_FRAME_PAYLOAD_LENGTH(frame_header) (frame_header[1] & 0b01111111)

#define PW_SET_WS_FRAME_FIN(frame_header)                    (frame_header[0] |= 0b10000000)
#define PW_SET_WS_FRAME_RSV1(frame_header)                   (frame_header[0] |= 0b01000000)
#define PW_SET_WS_FRAME_RSV2(frame_header)                   (frame_header[0] |= 0b00100000)
#define PW_SET_WS_FRAME_RSV3(frame_header)                   (frame_header[0] |= 0b00010000)
#define PW_SET_WS_FRAME_OPCODE(frame_header, opcode)         (frame_header[0] = (frame_header[0] & ~0x0f) | (opcode & ~0xf0))
#define PW_SET_WS_FRAME_MASKED(frame_header)                 (frame_header[1] |= 0b10000000)
#define PW_SET_WS_FRAME_PAYLOAD_LENGTH(frame_header, length) (frame_header[1] = (frame_header[1] & ~0x7f) | (length & ~0x80))

#define PW_CLEAR_WS_FRAME_FIN(frame_header)            (frame_header[0] &= ~0b10000000)
#define PW_CLEAR_WS_FRAME_RSV1(frame_header)           (frame_header[0] &= ~0b01000000)
#define PW_CLEAR_WS_FRAME_RSV2(frame_header)           (frame_header[0] &= ~0b00100000)
#define PW_CLEAR_WS_FRAME_RSV3(frame_header)           (frame_header[0] &= ~0b00010000)
#define PW_CLEAR_WS_FRAME_OPCODE(frame_header)         (frame_header[0] &= ~0x0f)
#define PW_CLEAR_WS_FRAME_MASKED(frame_header)         (frame_header[1] &= ~0b10000000)
#define PW_CLEAR_WS_FRAME_PAYLOAD_LENGTH(frame_header) (frame_header[1] &= ~0x7f)

#define PW_TOGGLE_WS_FRAME_FIN(frame_header)            (frame_header[0] ^= 0b10000000)
#define PW_TOGGLE_WS_FRAME_RSV1(frame_header)           (frame_header[0] ^= 0b01000000)
#define PW_TOGGLE_WS_FRAME_RSV2(frame_header)           (frame_header[0] ^= 0b00100000)
#define PW_TOGGLE_WS_FRAME_RSV3(frame_header)           (frame_header[0] ^= 0b00010000)
#define PW_TOGGLE_WS_FRAME_OPCODE(frame_header)         (frame_header[0] ^= 0x0f)
#define PW_TOGGLE_WS_FRAME_MASKED(frame_header)         (frame_header[1] ^= 0b10000000)
#define PW_TOGGLE_WS_FRAME_PAYLOAD_LENGTH(frame_header) (frame_header[1] ^= 0x7f)

namespace pw {
    extern tp::ThreadPool threadpool;
    namespace detail {
        extern thread_local int last_error;

        inline void set_last_error(int error) {
            last_error = error;
        }

        template <typename InsertIt>
        int read_until(pn::tcp::Connection& conn, InsertIt ret, char end, size_t rl = 1'000) {
            for (size_t i = 0;; i++) {
                if (i > rl) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                }

                char c;
                ssize_t read_result;
                if ((read_result = conn.recv(&c, sizeof(c), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PW_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                }

                if (c == end) {
                    break;
                } else {
                    ret = c;
                }
            }

            return PW_OK;
        }

        template <typename InsertIt>
        int read_until(pn::tcp::Connection& conn, InsertIt ret, const std::string& end_sequence, size_t rl = 1'000) {
            for (size_t i = 0, search_pos = 0;; i++) {
                if (i > rl) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                }

                char c;
                ssize_t read_result;
                if ((read_result = conn.recv(&c, sizeof(c), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PW_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
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

        int days_from_epoch(int mon, int day, int year);
        time_t timegm(const struct tm* timeinfo);
    } // namespace detail

    void reverse_memcpy(char* dest, const char* src, size_t len);

    inline int get_last_error(void) {
        return detail::last_error;
    }

    std::string strerror(int error = get_last_error());

    std::string universal_strerror(int error = get_last_error());

    inline std::string status_code_to_reason_phrase(const std::string& status_code) {
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
            {"426", "Upgrade Required"},
            {"500", "Internal Server Error"},
            {"501", "Not Implemented"},
            {"502", "Bad Gateway"},
            {"503", "Service Unavailable"},
            {"504", "Gateway Time-out"},
            {"505", "HTTP Version not supported"}};
        return conversion_mapping.at(status_code);
    }

    std::string build_date(time_t rawtime = time(NULL));
    time_t parse_date(const std::string& date);

    std::vector<char> b64_decode(const std::string& str);
    std::string b64_encode(const std::vector<char>& data);

    std::string percent_encode(const std::string& str, bool plus_as_space = false, bool allow_slash = true);
    std::string percent_decode(const std::string& str, bool plus_as_space = false);

    typedef std::unordered_map<std::string, std::string, detail::case_insensitive_hasher, detail::case_insensitive_comparer> HTTPHeaders;

    class QueryParameters {
    private:
        std::unordered_map<std::string, std::string> map;

    public:
        typedef decltype(map) map_type;

        operator map_type() const {
            return map;
        }

        const map_type& operator*() const {
            return map;
        }

        map_type& operator*() {
            return map;
        }

        const map_type* operator->() const {
            return &map;
        }

        map_type* operator->() {
            return &map;
        }

        std::string build(void) const;
        void parse(const std::string& query_string);
    };

    class HTTPRequest {
    public:
        std::string method;
        std::string target;
        HTTPHeaders headers;
        std::vector<char> body;
        QueryParameters query_parameters;
        std::string http_version = "HTTP/1.1";

        HTTPRequest(void) = default;
        HTTPRequest(const std::string& method, const std::string& target, const HTTPHeaders& headers = {}) :
            method(method),
            target(target),
            headers(headers) { }
        HTTPRequest(const std::string& method, const std::string& target, const std::vector<char>& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            method(method),
            target(target),
            headers(headers),
            body(body),
            http_version(http_version) { }
        HTTPRequest(const std::string& method, const std::string& target, const std::string& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            method(method),
            target(target),
            headers(headers),
            body(body.begin(), body.end()),
            http_version(http_version) { }
        HTTPRequest(const std::string& method, const std::string& target, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            method(method),
            target(target),
            headers(headers),
            query_parameters(query_parameters),
            http_version(http_version) { }

        std::vector<char> build(void) const;

        inline std::string build_str(void) const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn, size_t header_climit = 100, size_t header_name_rlimit = 500, size_t header_value_rlimit = 4'000'000, size_t body_rlimit = 32'000'000, size_t misc_rlimit = 1'000);

        inline std::string body_to_string(void) const {
            return std::string(body.begin(), body.end());
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
        HTTPResponse(const std::string& status_code, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            headers(headers),
            http_version(http_version) { }
        HTTPResponse(const std::string& status_code, const std::vector<char>& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body),
            headers(headers),
            http_version(http_version) { }
        HTTPResponse(const std::string& status_code, const std::string& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body.begin(), body.end()),
            headers(headers),
            http_version(http_version) { }

        static inline HTTPResponse create_basic(const std::string& status_code, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") {
            HTTPResponse resp(status_code, status_code + ' ' + status_code_to_reason_phrase(status_code) + '\n', headers, http_version);
            if (!resp.headers.count("Content-Type")) {
                resp.headers["Content-Type"] = "text/plain";
            }
            return resp;
        }

        std::vector<char> build(void) const;

        inline std::string build_str(void) const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn, size_t header_climit = 100, size_t header_name_rlimit = 500, size_t header_value_rlimit = 4'000'000, size_t body_rlimit = 32'000'000, size_t misc_rlimit = 1'000);

        inline std::string body_to_string(void) const {
            return std::string(body.begin(), body.end());
        }
    };

    class WSMessage {
    public:
        std::vector<char> data;
        uint8_t opcode = 2;

        WSMessage(void) = default;
        WSMessage(const std::string& str, uint8_t opcode = 1) :
            data(str.begin(), str.end()),
            opcode(opcode) { }
        WSMessage(const std::vector<char>& data, uint8_t opcode = 2) :
            data(data),
            opcode(opcode) { }
        WSMessage(uint8_t opcode) :
            opcode(opcode) { }

        inline std::string to_string(void) const {
            return std::string(data.begin(), data.end());
        }

        std::vector<char> build(bool masked, char* masking_key = NULL) const;
        int parse(pn::tcp::Connection& conn, size_t frame_rlimit = 16'000'000, size_t message_rlimit = 32'000'000);
    };

    class Connection: public pn::tcp::Connection {
    public:
        bool ws_closed = false;
        void* data = NULL; // User data

        Connection(void) = default;
        Connection(const Connection&) = default;
        Connection(const pn::tcp::Connection& s) {
            *this = s;
        }
        Connection(Connection&& s) {
            *this = std::move(s);
        }
        Connection(pn::tcp::Connection&& s) {
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
            if (this != &s) {
                this->ws_closed = s.ws_closed;
                this->data = s.data;

                s.ws_closed = false;
                s.data = NULL;
            }

            return *this;
        }

        inline Connection& operator=(const pn::tcp::Connection& s) {
            this->fd = s.fd;
            this->addr = s.addr;
            this->addrlen = s.addrlen;
            return *this;
        }
        inline Connection& operator=(pn::tcp::Connection&& s) {
            pn::tcp::Connection::operator=(std::move(s));
            if (this != &s) {
                this->ws_closed = false;
                this->data = NULL;
            }

            return *this;
        }

        using pn::tcp::Connection::send;

        inline ssize_t send(const HTTPResponse& resp) {
            auto data = resp.build();
            ssize_t result;
            if ((result = send(data.data(), data.size())) == PW_ERROR) {
                detail::set_last_error(PW_ENET);
            }
            return result;
        }

        inline ssize_t send(const WSMessage& message, bool masked = false, char* masking_key = NULL) {
            auto data = message.build(masked, masking_key);
            ssize_t result;
            if ((result = send(data.data(), data.size())) == PW_ERROR) {
                detail::set_last_error(PW_ENET);
            }
            return result;
        }

        inline auto send_basic(const std::string& status_code, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") {
            return send(HTTPResponse::create_basic(status_code, headers, http_version));
        }

        int close_ws(uint16_t status_code, const std::string& reason, bool masked = false, char* masking_key = NULL, bool validity_check = true);
    };

    typedef std::function<HTTPResponse(const Connection&, const HTTPRequest&)> RouteCallback;

    class Route {
    public:
        bool wildcard = false;

        Route(bool wildcard = false) :
            wildcard(wildcard) { }
    };

    class HTTPRoute: public Route {
    public:
        RouteCallback cb;

        HTTPRoute() = default;
        HTTPRoute(RouteCallback cb, bool wildcard = false) :
            Route(wildcard),
            cb(cb) { }
    };

    class WSRoute: public Route {
    public:
        RouteCallback on_connect;
        std::function<void(Connection&)> on_open;
        std::function<void(Connection&, const WSMessage&)> on_message;
        std::function<void(Connection&, uint16_t, const std::string&, bool clean)> on_close;

        WSRoute() = default;
        WSRoute(RouteCallback on_connect, decltype(on_open) on_open, decltype(on_message) on_message, decltype(on_close) on_close, bool wildcard = false) :
            Route(wildcard),
            on_connect(on_connect),
            on_open(on_open),
            on_message(on_message),
            on_close(on_close) { }
    };

    class Server: public pn::tcp::Server {
    public:
        std::function<HTTPResponse(const std::string&)> on_error = PW_DEFAULT_SERVER_ON_ERROR;
        size_t header_climit = 100;
        size_t header_name_rlimit = 500;
        size_t header_value_rlimit = 4'000'000;
        size_t body_rlimit = 32'000'000;
        size_t ws_frame_rlimit = 16'000'000;
        size_t ws_message_rlimit = 32'000'000;
        size_t misc_rlimit = 1'000;

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
                this->on_error = std::move(s.on_error);
                this->header_climit = s.header_climit;
                this->header_name_rlimit = s.header_name_rlimit;
                this->header_value_rlimit = s.header_value_rlimit;
                this->body_rlimit = s.body_rlimit;
                this->ws_frame_rlimit = s.ws_frame_rlimit;
                this->ws_message_rlimit = s.ws_message_rlimit;
                this->misc_rlimit = s.misc_rlimit;

                s.on_error = PW_DEFAULT_SERVER_ON_ERROR;
                s.header_climit = 100;
                s.header_name_rlimit = 500;
                s.header_value_rlimit = 4'000'000;
                s.body_rlimit = 32'000'000;
                s.ws_frame_rlimit = 16'000'000;
                s.ws_message_rlimit = 32'000'000;
                s.misc_rlimit = 1'000;
            }

            return *this;
        }

        inline int bind(const std::string& host, const std::string& port) {
            if (pn::tcp::Server::bind(host, port) == PW_ERROR) {
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
            if (pn::tcp::Server::bind(addr, addrlen) == PW_ERROR) {
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
            return PW_OK;
        }

        inline void route(const std::string& target, HTTPRoute route) {
            routes[target] = route;
        }

        inline void unroute(const std::string& target) {
            decltype(routes)::const_iterator route_it;
            if ((route_it = routes.find(target)) != routes.end()) {
                routes.erase(route_it);
            }
        }

        inline void route_ws(const std::string& target, const WSRoute& route) {
            ws_routes[target] = route;
        }

        inline void unroute_ws(const std::string& target) {
            decltype(ws_routes)::const_iterator route_it;
            if ((route_it = ws_routes.find(target)) != ws_routes.end()) {
                ws_routes.erase(route_it);
            }
        }

        int listen(int backlog = 128);

    protected:
        std::unordered_map<std::string, HTTPRoute> routes;
        std::unordered_map<std::string, WSRoute> ws_routes;

        int handle_ws_connection(Connection conn, WSRoute& route);
        int handle_connection(Connection conn);
        int handle_error(Connection& conn, const std::string& status_code, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1");
        int handle_error(Connection& conn, const std::string& status_code, bool keep_alive, const std::string& http_version = "HTTP/1.1");
    };
} // namespace pw

#endif
