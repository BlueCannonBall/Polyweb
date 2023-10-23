#ifndef _POLYWEB_HPP
#define _POLYWEB_HPP

#include "Polynet/polynet.hpp"
#include "string.hpp"
#include "threadpool.hpp"
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#define PW_SERVER_NAME "Polyweb"

// Bridged
#ifdef _WIN32
    #define timegm _mkgmtime
#endif

// Errors
#define PW_ESUCCESS 0
#define PW_ENET     1
#define PW_EWEB     2

// Default callback macros
#define PW_DEFAULT_WS_ROUTE_ON_CONNECT [](const pw::Connection&, const pw::HTTPRequest&, void*) -> pw::HTTPResponse { \
    return pw::HTTPResponse(101);                                                                                     \
}
#define PW_DEFAULT_SERVER_ON_ERROR [](uint16_t status_code) -> pw::HTTPResponse { \
    return pw::HTTPResponse::make_basic(status_code);                             \
}

// WebSocket macros
#define PW_WS_VERSION "13"

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
#define PW_SET_WS_FRAME_OPCODE(frame_header, opcode)         (frame_header[0] = (frame_header[0] & ~0x0F) | (opcode & ~0xF0))
#define PW_SET_WS_FRAME_MASKED(frame_header)                 (frame_header[1] |= 0b10000000)
#define PW_SET_WS_FRAME_PAYLOAD_LENGTH(frame_header, length) (frame_header[1] = (frame_header[1] & ~0x7F) | (length & ~0x80))

#define PW_CLEAR_WS_FRAME_FIN(frame_header)            (frame_header[0] &= ~0b10000000)
#define PW_CLEAR_WS_FRAME_RSV1(frame_header)           (frame_header[0] &= ~0b01000000)
#define PW_CLEAR_WS_FRAME_RSV2(frame_header)           (frame_header[0] &= ~0b00100000)
#define PW_CLEAR_WS_FRAME_RSV3(frame_header)           (frame_header[0] &= ~0b00010000)
#define PW_CLEAR_WS_FRAME_OPCODE(frame_header)         (frame_header[0] &= ~0x0F)
#define PW_CLEAR_WS_FRAME_MASKED(frame_header)         (frame_header[1] &= ~0b10000000)
#define PW_CLEAR_WS_FRAME_PAYLOAD_LENGTH(frame_header) (frame_header[1] &= ~0x7F)

#define PW_TOGGLE_WS_FRAME_FIN(frame_header)            (frame_header[0] ^= 0b10000000)
#define PW_TOGGLE_WS_FRAME_RSV1(frame_header)           (frame_header[0] ^= 0b01000000)
#define PW_TOGGLE_WS_FRAME_RSV2(frame_header)           (frame_header[0] ^= 0b00100000)
#define PW_TOGGLE_WS_FRAME_RSV3(frame_header)           (frame_header[0] ^= 0b00010000)
#define PW_TOGGLE_WS_FRAME_OPCODE(frame_header)         (frame_header[0] ^= 0x0F)
#define PW_TOGGLE_WS_FRAME_MASKED(frame_header)         (frame_header[1] ^= 0b10000000)
#define PW_TOGGLE_WS_FRAME_PAYLOAD_LENGTH(frame_header) (frame_header[1] ^= 0x7F)

namespace pw {
    extern tp::ThreadPool threadpool;
    namespace detail {
        extern thread_local int last_error;

        inline void set_last_error(int error) {
            last_error = error;
        }

        template <typename OutputIt>
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, char end, size_t rlimit = 1'000) {
            for (size_t i = 0;; ++i) {
                if (i >= rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                char c;
                ssize_t result;
                if ((result = buf_receiver.recv(conn, &c, 1)) == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 1) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                if (c == end) {
                    break;
                } else {
                    *ret++ = c;
                }
            }

            return PN_OK;
        }

        template <typename OutputIt>
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, const std::vector<char>& end_sequence, size_t rlimit = 1'000) {
            for (size_t i = 0, search_pos = 0;; i++) {
                if (i >= rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                char c;
                ssize_t result;
                if ((result = buf_receiver.recv(conn, &c, 1)) == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 1) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                if (c == end_sequence[search_pos]) {
                    if (++search_pos == end_sequence.size()) {
                        break;
                    }
                } else {
                    *ret++ = c;
                    search_pos = 0;

                    if (c == end_sequence[search_pos]) {
                        if (++search_pos == end_sequence.size()) {
                            break;
                        }
                    }
                }
            }

            return PN_OK;
        }

        template <typename OutputIt>
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, const std::string& end_sequence, size_t rlimit = 1'000) {
            return recv_until(conn, buf_receiver, ret, std::vector<char>(end_sequence.begin(), end_sequence.end()), rlimit);
        }

        struct CaseInsensitiveComparer {
            bool operator()(const std::string& a, const std::string& b) const {
                return string::iequals(a, b);
            }
        };

        struct CaseInsensitiveHasher {
            size_t operator()(const std::string& str) const {
                return std::hash<std::string>()(string::to_lower_copy(str));
            }
        };
    } // namespace detail

    void reverse_memcpy(void* dest, const void* src, size_t size);

    inline int get_last_error() {
        return detail::last_error;
    }

    std::string strerror(int error = get_last_error());

    std::string universal_strerror(int error = get_last_error());

    inline std::string status_code_to_reason_phrase(uint16_t status_code) {
        const static std::unordered_map<uint16_t, std::string> conversion_mapping = {
            {100, "Continue"},
            {101, "Switching Protocols"},
            {200, "OK"},
            {201, "Created"},
            {202, "Accepted"},
            {203, "Non-Authoritative Information"},
            {204, "No Content"},
            {205, "Reset Content"},
            {206, "Partial Content"},
            {300, "Multiple Choices"},
            {301, "Moved Permanently"},
            {302, "Found"},
            {303, "See Other"},
            {304, "Not Modified"},
            {305, "Use Proxy"},
            {307, "Temporary Redirect"},
            {400, "Bad Request"},
            {401, "Unauthorized"},
            {402, "Payment Required"},
            {403, "Forbidden"},
            {404, "Not Found"},
            {405, "Method Not Allowed"},
            {406, "Not Acceptable"},
            {407, "Proxy Authentication Required"},
            {408, "Request Time-out"},
            {409, "Conflict"},
            {410, "Gone"},
            {411, "Length Required"},
            {412, "Precondition Failed"},
            {413, "Request Entity Too Large"},
            {414, "Request-URI Too Large"},
            {415, "Unsupported Media Type"},
            {416, "Requested range not satisfiable"},
            {417, "Expectation Failed"},
            {426, "Upgrade Required"},
            {500, "Internal Server Error"},
            {501, "Not Implemented"},
            {502, "Bad Gateway"},
            {503, "Service Unavailable"},
            {504, "Gateway Time-out"},
            {505, "HTTP Version not supported"},
        };

        decltype(conversion_mapping)::const_iterator ret_it;
        if ((ret_it = conversion_mapping.find(status_code)) != conversion_mapping.end()) {
            return ret_it->second;
        } else if (status_code >= 100 && status_code < 600) {
            return conversion_mapping.at(status_code / 100 * 100); // Zero out last two digits
        } else {
            throw std::out_of_range("Invalid status code");
        }
    }

    std::string build_date(time_t rawtime = time(nullptr));
    time_t parse_date(const std::string& date);

    std::string base64_encode(const std::vector<char>& data);
    std::vector<char> base64_decode(const std::string& str);

    std::string percent_encode(const std::string& str, bool plus_as_space = false, bool allow_slash = true);
    std::string percent_decode(const std::string& str, bool plus_as_space = false);

    std::wstring escape_xml(const std::wstring& str);
    std::string escape_xml(const std::string& str); // Automatically converts std::string to std::wstring and calls the former function

    typedef std::unordered_map<std::string, std::string, detail::CaseInsensitiveHasher, detail::CaseInsensitiveComparer> HTTPHeaders;

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

        std::string build() const;
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

        HTTPRequest() = default;
        HTTPRequest(const std::string& method, const std::string& target, const HTTPHeaders& headers = {}):
            method(method),
            target(target),
            headers(headers) {}
        HTTPRequest(const std::string& method, const std::string& target, const std::vector<char>& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1"):
            method(method),
            target(target),
            headers(headers),
            body(body),
            http_version(http_version) {}
        HTTPRequest(const std::string& method, const std::string& target, const std::string& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1"):
            method(method),
            target(target),
            headers(headers),
            body(body.begin(), body.end()),
            http_version(http_version) {}
        HTTPRequest(const std::string& method, const std::string& target, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1"):
            method(method),
            target(target),
            headers(headers),
            query_parameters(query_parameters),
            http_version(http_version) {}

        std::vector<char> build() const;

        inline std::string build_str() const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, size_t header_climit = 100, size_t header_name_rlimit = 500, size_t header_value_rlimit = 4'000'000, size_t body_rlimit = 32'000'000, size_t misc_rlimit = 1'000);

        inline std::string body_to_string() const {
            return std::string(body.begin(), body.end());
        }
    };

    class HTTPResponse {
    public:
        uint16_t status_code;
        std::string reason_phrase;
        std::vector<char> body;
        HTTPHeaders headers;
        std::string http_version = "HTTP/1.1";

        HTTPResponse() = default;
        HTTPResponse(uint16_t status_code, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            headers(headers),
            http_version(http_version) {}
        HTTPResponse(uint16_t status_code, const std::vector<char>& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body),
            headers(headers),
            http_version(http_version) {}
        HTTPResponse(uint16_t status_code, const std::string& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body.begin(), body.end()),
            headers(headers),
            http_version(http_version) {}

        static inline HTTPResponse make_basic(uint16_t status_code, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") {
            HTTPResponse resp(status_code, std::to_string(status_code) + ' ' + status_code_to_reason_phrase(status_code), headers, http_version);
            if (!resp.headers.count("Content-Type")) {
                resp.headers["Content-Type"] = "text/plain";
            }
            return resp;
        }

        std::vector<char> build() const;

        inline std::string build_str() const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, size_t header_climit = 100, size_t header_name_rlimit = 500, size_t header_value_rlimit = 4'000'000, size_t body_chunk_rlimit = 16'000'000, size_t body_rlimit = 32'000'000, size_t misc_rlimit = 1'000);

        inline std::string body_to_string() const {
            return std::string(body.begin(), body.end());
        }
    };

    class WSMessage {
    public:
        std::vector<char> data;
        uint8_t opcode = 2;

        WSMessage() = default;
        WSMessage(const std::string& str, uint8_t opcode = 1):
            data(str.begin(), str.end()),
            opcode(opcode) {}
        WSMessage(const std::vector<char>& data, uint8_t opcode = 2):
            data(data),
            opcode(opcode) {}
        WSMessage(std::vector<char>&& data, uint8_t opcode = 2):
            data(data),
            opcode(opcode) {}
        WSMessage(uint8_t opcode):
            opcode(opcode) {}

        inline std::string to_string() const {
            return std::string(data.begin(), data.end());
        }

        std::vector<char> build(const char* masking_key = nullptr) const;
        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, size_t frame_rlimit = 16'000'000, size_t message_rlimit = 32'000'000);
    };

    class Connection : public pn::tcp::Connection {
    public:
        bool ws_closed = false;
        void* data = nullptr; // User data

        Connection() = default;
        Connection(const pn::tcp::Connection& conn) {
            *this = conn;
        }
        Connection(pn::sockfd_t fd):
            pn::tcp::Connection(fd) {}
        Connection(struct sockaddr addr, socklen_t addrlen):
            pn::tcp::Connection(addr, addrlen) {}
        Connection(pn::sockfd_t fd, struct sockaddr addr, socklen_t addrlen):
            pn::tcp::Connection(fd, addr, addrlen) {}

        inline Connection& operator=(const pn::tcp::Connection& conn) {
            if (this != &conn) {
                this->fd = conn.fd;
                this->addr = conn.addr;
                this->addrlen = conn.addrlen;
            }
            return *this;
        }

        using pn::tcp::Connection::send;

        inline ssize_t send(const HTTPResponse& resp, int flags = 0) {
            auto data = resp.build();
            ssize_t result;
            if ((result = send(data.data(), data.size(), flags)) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
            }
            return result;
        }

        inline ssize_t send(const WSMessage& message, const char* masking_key = nullptr, int flags = 0) {
            auto data = message.build(masking_key);
            ssize_t result;
            if ((result = send(data.data(), data.size(), flags)) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
            }
            return result;
        }

        inline auto send_basic(uint16_t status_code, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1", int flags = 0) {
            return send(HTTPResponse::make_basic(status_code, headers, http_version), flags);
        }

        int close_ws(uint16_t status_code, const std::string& reason, const char* masking_key = nullptr, bool validity_check = true);
    };

    typedef std::function<HTTPResponse(const Connection&, const HTTPRequest&, void*)> RouteCallback;

    class Route {
    public:
        void* data = nullptr; // User data
        bool wildcard = false;

        Route(void* data = nullptr, bool wildcard = false):
            data(data),
            wildcard(wildcard) {}
    };

    class HTTPRoute : public Route {
    public:
        RouteCallback cb;

        HTTPRoute() = default;
        HTTPRoute(RouteCallback cb, void* data = nullptr, bool wildcard = false):
            Route(data, wildcard),
            cb(cb) {}
    };

    class WSRoute : public Route {
    public:
        RouteCallback on_connect = PW_DEFAULT_WS_ROUTE_ON_CONNECT;
        std::function<void(Connection&, void*)> on_open;
        std::function<void(Connection&, WSMessage, void*)> on_message;
        std::function<void(Connection&, uint16_t, const std::string&, bool clean, void*)> on_close;

        WSRoute() = default;
        WSRoute(decltype(on_open) on_open, decltype(on_message) on_message, decltype(on_close) on_close, void* data = nullptr, bool wildcard = false):
            Route(data, wildcard),
            on_open(on_open),
            on_message(on_message),
            on_close(on_close) {}
        WSRoute(RouteCallback on_connect, decltype(on_open) on_open, decltype(on_message) on_message, decltype(on_close) on_close, void* data = nullptr, bool wildcard = false):
            Route(data, wildcard),
            on_connect(on_connect),
            on_open(on_open),
            on_message(on_message),
            on_close(on_close) {}
    };

    class Server : public pn::tcp::Server {
    public:
        std::function<HTTPResponse(uint16_t)> on_error = PW_DEFAULT_SERVER_ON_ERROR;
        size_t buffer_size = 4'000;
        size_t header_climit = 100;
        size_t header_name_rlimit = 500;
        size_t header_value_rlimit = 4'000'000;
        size_t body_rlimit = 32'000'000;
        size_t ws_frame_rlimit = 16'000'000;
        size_t ws_message_rlimit = 32'000'000;
        size_t misc_rlimit = 1'000;

        Server() = default;
        Server(pn::sockfd_t fd):
            pn::tcp::Server(fd) {}
        Server(struct sockaddr addr, socklen_t addrlen):
            pn::tcp::Server(addr, addrlen) {}
        Server(pn::sockfd_t fd, struct sockaddr addr, socklen_t addrlen):
            pn::tcp::Server(fd, addr, addrlen) {}

        inline void route(const std::string& target, HTTPRoute route) {
            routes[target] = route;
        }

        inline void unroute(const std::string& target) {
            routes.erase(target);
        }

        inline void route_ws(const std::string& target, const WSRoute& route) {
            ws_routes[target] = route;
        }

        inline void unroute_ws(const std::string& target) {
            ws_routes.erase(target);
        }

        int listen(
            std::function<bool(pn::tcp::Connection&, void*)> filter = [](pn::tcp::Connection&, void*) {
                return false;
            },
            void* filter_data = nullptr,
            int backlog = 128);

    protected:
        std::unordered_map<std::string, HTTPRoute> routes;
        std::unordered_map<std::string, WSRoute> ws_routes;

        int handle_ws_connection(pn::UniqueSock<Connection> conn, pn::tcp::BufReceiver& buf_receiver, WSRoute& route);
        int handle_connection(pn::UniqueSock<Connection> conn, pn::tcp::BufReceiver& buf_receiver);
        int handle_error(Connection& conn, uint16_t status_code, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1");
        int handle_error(Connection& conn, uint16_t status_code, bool keep_alive, const std::string& http_version = "HTTP/1.1");
    };
} // namespace pw

#endif
