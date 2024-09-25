#ifndef _POLYWEB_HPP
#define _POLYWEB_HPP

#include "Polynet/polynet.hpp"
#include "Polynet/secure_sockets.hpp"
#include "Polynet/smart_sockets.hpp"
#include "string.hpp"
#include "threadpool.hpp"
#include <chrono>
#include <functional>
#include <iostream>
#include <stddef.h>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <utility>
#include <vector>

#define PW_SERVER_CLIENT_NAME "Polyweb"

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
#define PW_WS_KEY     "cG9seXdlYiBpcyBncmVhdA==" // polyweb is great

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
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, char end, long rlimit = 1'000) {
            for (long i = 0;; ++i) {
                if (i >= rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                char c;
                long result;
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
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, const std::vector<char>& end_sequence, long rlimit = 1'000) {
            for (long i = 0, search_pos = 0;; ++i) {
                if (i >= rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                char c;
                long result;
                if ((result = buf_receiver.recv(conn, &c, 1)) == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 1) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                if (c == end_sequence[search_pos]) {
                    if ((size_t) ++search_pos == end_sequence.size()) {
                        break;
                    }
                } else {
                    *ret++ = c;
                    search_pos = 0;

                    if (c == end_sequence[search_pos]) {
                        if ((size_t) ++search_pos == end_sequence.size()) {
                            break;
                        }
                    }
                }
            }

            return PN_OK;
        }

        template <typename OutputIt>
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, pn::StringView end_sequence, long rlimit = 1'000) {
            return recv_until(conn, buf_receiver, ret, std::vector<char>(end_sequence.begin(), end_sequence.end()), rlimit);
        }
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

    std::string base64_encode(const unsigned char* data, size_t size);
    std::string base64_encode(const char* data, size_t size);
    std::vector<char> base64_decode(pn::StringView str);

    std::string percent_encode(pn::StringView str, bool plus_as_space = false, bool allow_slash = true);
    std::string percent_decode(pn::StringView str, bool plus_as_space = false);

    std::wstring xml_escape(pn::WStringView str);
    std::string xml_escape(const std::string& str); // Automatically converts std::string to std::wstring and calls the former function

    typedef std::unordered_map<std::string, std::string, string::CaseInsensitiveHasher, string::CaseInsensitiveComparer> HTTPHeaders;

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
        void parse(pn::StringView query_string);
    };

    inline std::ostream& operator<<(std::ostream& os, const QueryParameters& query_parameters) {
        return os << query_parameters.build();
    }

    inline std::istream& operator>>(std::istream& is, QueryParameters& query_parameters) {
        std::string query_string;
        is >> query_string;
        query_parameters.parse(query_string);
        return is;
    }

    class URLInfo {
    public:
        std::string scheme;
        std::string credentials;
        std::string host;
        std::string path = "/";
        QueryParameters query_parameters;

        URLInfo() = default;
        URLInfo(pn::StringView url) { // Avoid using this constructor unless you're certain that the URL is valid!
            if (parse(url) == PN_ERROR) {
                throw std::runtime_error("Invalid URL passed to pw::URLInfo constructor");
            }
        }

        std::string build() const;
        int parse(pn::StringView url);

        std::string hostname() const {
            return host.substr(0, host.find(':'));
        }

        unsigned short port() const;

        std::string path_with_query_parameters() const {
            if (query_parameters->empty()) {
                return path;
            } else {
                return path + '?' + query_parameters.build();
            }
        }

        std::string username() const {
            return credentials.substr(0, host.find(':'));
        }

        std::string password() const {
            return credentials.substr(host.find(':') + 1);
        }
    };

    inline std::ostream& operator<<(std::ostream& os, const URLInfo& url_info) {
        return os << url_info.build();
    }

    inline std::istream& operator>>(std::istream& is, URLInfo& url_info) {
        std::string url;
        if (is >> url && url_info.parse(url) == PN_ERROR) {
            is.setstate(std::istream::failbit);
        }
        return is;
    }

    class HTTPRequest {
    public:
        std::string method;
        std::string target;
        HTTPHeaders headers;
        std::vector<char> body;
        QueryParameters query_parameters;
        std::string http_version = "HTTP/1.1";

        HTTPRequest() = default;
        HTTPRequest(pn::StringView method, pn::StringView target, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1"):
            method(method),
            target(target),
            headers(headers),
            http_version(http_version) {}
        HTTPRequest(pn::StringView method, pn::StringView target, const std::vector<char>& body, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1"):
            method(method),
            target(target),
            headers(headers),
            body(body),
            http_version(http_version) {}
        HTTPRequest(pn::StringView method, pn::StringView target, pn::StringView body, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1"):
            method(method),
            target(target),
            headers(headers),
            body(body.begin(), body.end()),
            http_version(http_version) {}
        HTTPRequest(pn::StringView method, pn::StringView target, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1"):
            method(method),
            target(target),
            headers(headers),
            query_parameters(query_parameters),
            http_version(http_version) {}

        std::vector<char> build() const;

        std::string build_string() const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, unsigned int header_climit = 100, long header_name_rlimit = 500, long header_value_rlimit = 4'000'000, long body_rlimit = 32'000'000, long misc_rlimit = 1'000);

        std::string body_to_string() const {
            return std::string(body.begin(), body.end());
        }

        std::string target_with_query_parameters() const {
            if (query_parameters->empty()) {
                return target;
            } else {
                return target + '?' + query_parameters.build();
            }
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
        HTTPResponse(uint16_t status_code, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            headers(headers),
            http_version(http_version) {}
        HTTPResponse(uint16_t status_code, const std::vector<char>& body, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body),
            headers(headers),
            http_version(http_version) {}
        HTTPResponse(uint16_t status_code, pn::StringView body, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body.begin(), body.end()),
            headers(headers),
            http_version(http_version) {}

        static HTTPResponse make_basic(uint16_t status_code, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1") {
            HTTPResponse resp(status_code, std::to_string(status_code) + ' ' + status_code_to_reason_phrase(status_code), headers, http_version);
            if (!resp.headers.count("Content-Type")) {
                resp.headers["Content-Type"] = "text/plain";
            }
            return resp;
        }

        std::vector<char> build(bool head_only = false) const;

        std::string build_string(bool head_only = false) const {
            std::vector<char> ret = build(head_only);
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, bool head_only = false, unsigned int header_climit = 100, long header_name_rlimit = 500, long header_value_rlimit = 4'000'000, long body_chunk_rlimit = 16'000'000, long body_rlimit = 32'000'000, long misc_rlimit = 1'000);

        std::string body_string() const {
            return std::string(body.begin(), body.end());
        }

        uint16_t status_code_category() const {
            return status_code / 100 * 100;
        }
    };

    class WSMessage {
    public:
        std::vector<char> data;
        uint8_t opcode = 2;

        WSMessage() = default;
        WSMessage(pn::StringView str, uint8_t opcode = 1):
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

        const std::vector<char>& operator*() const {
            return data;
        }

        std::vector<char>& operator*() {
            return data;
        }

        const std::vector<char>* operator->() const {
            return &data;
        }

        std::vector<char>* operator->() {
            return &data;
        }

        std::string to_string() const {
            return std::string(data.begin(), data.end());
        }

        std::vector<char> build(const char* masking_key = nullptr) const;
        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, long frame_rlimit = 16'000'000, long message_rlimit = 32'000'000);
    };

    template <typename Base>
    class BasicConnection : public Base {
    public:
        bool ws_closed = false;
        void* data = nullptr; // User data

        template <typename... Args>
        BasicConnection(Args&&... args):
            Base(std::forward<Args>(args)...) {}
        BasicConnection(const Base& conn) {
            *this = conn;
        }

        BasicConnection<Base>& operator=(const Base& conn);

        using pn::tcp::Connection::send;

        int send(const HTTPRequest& req) {
            auto data = req.build();
            long result;
            if ((result = Base::sendall(data.data(), data.size())) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if ((size_t) result != data.size()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }
            return PN_OK;
        }

        int send(const HTTPResponse& resp, bool head_only = false) {
            auto data = resp.build(head_only);
            long result;
            if ((result = Base::sendall(data.data(), data.size())) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if ((size_t) result != data.size()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }
            return PN_OK;
        }

        virtual int send(const WSMessage& message, const char* masking_key = nullptr) {
            auto data = message.build(masking_key);
            long result;
            if ((result = Base::sendall(data.data(), data.size())) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if ((size_t) result != data.size()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }
            return PN_OK;
        }

        int send_basic(uint16_t status_code, const HTTPHeaders& headers = {}, pn::StringView http_version = "HTTP/1.1", bool head_only = false) {
            return send(HTTPResponse::make_basic(status_code, headers, http_version), head_only);
        }

        virtual int ws_close(uint16_t status_code, pn::StringView reason, const char* masking_key = nullptr, bool validity_check = true);
    };

    using Connection = BasicConnection<pn::tcp::Connection>;
    using SecureConnection = BasicConnection<pn::tcp::SecureConnection>;

    using Client = BasicConnection<pn::tcp::Client>;
    using SecureClient = BasicConnection<pn::tcp::SecureClient>;

    class Route {
    public:
        void* data = nullptr; // User data
        bool wildcard = false;

        Route(void* data = nullptr, bool wildcard = false):
            data(data),
            wildcard(wildcard) {}
    };

    template <typename T>
    class BasicHTTPRoute : public Route {
    public:
        std::function<HTTPResponse(const T&, const HTTPRequest&, void*)> cb;

        BasicHTTPRoute() = default;
        BasicHTTPRoute(decltype(cb) cb, void* data = nullptr, bool wildcard = false):
            Route(data, wildcard),
            cb(cb) {}
    };

    using HTTPRoute = BasicHTTPRoute<Connection>;
    using SecureHTTPRoute = BasicHTTPRoute<SecureConnection>;

    template <typename T>
    class BasicWSRoute : public Route {
    public:
        std::function<HTTPResponse(const Connection&, const HTTPRequest&, void*)> on_connect = PW_DEFAULT_WS_ROUTE_ON_CONNECT;
        std::function<void(T&, void*)> on_open;
        std::function<void(T&, WSMessage, void*)> on_message;
        std::function<void(T&, uint16_t, pn::StringView, bool clean, void*)> on_close;

        BasicWSRoute() = default;
        BasicWSRoute(decltype(on_open) on_open, decltype(on_message) on_message, decltype(on_close) on_close, void* data = nullptr, bool wildcard = false):
            Route(data, wildcard),
            on_open(on_open),
            on_message(on_message),
            on_close(on_close) {}
        BasicWSRoute(decltype(on_connect) on_connect, decltype(on_open) on_open, decltype(on_message) on_message, decltype(on_close) on_close, void* data = nullptr, bool wildcard = false):
            Route(data, wildcard),
            on_connect(on_connect),
            on_open(on_open),
            on_message(on_message),
            on_close(on_close) {}
    };

    using WSRoute = BasicWSRoute<Connection>;
    using SecureWSRoute = BasicWSRoute<SecureConnection>;

    template <typename Base>
    class BasicServer : public Base {
    public:
        std::function<HTTPResponse(uint16_t)> on_error = PW_DEFAULT_SERVER_ON_ERROR;
        size_t buffer_size = 4'000;
        unsigned int header_climit = 100;
        long header_name_rlimit = 500;
        long header_value_rlimit = 4'000'000;
        long body_rlimit = 32'000'000;
        long ws_frame_rlimit = 16'000'000;
        long ws_message_rlimit = 32'000'000;
        long misc_rlimit = 1'000;

        typedef BasicConnection<typename Base::connection_type> connection_type;
        typedef BasicHTTPRoute<connection_type> http_route_type;
        typedef BasicWSRoute<connection_type> ws_route_type;

        template <typename... Args>
        BasicServer(Args&&... args):
            Base(std::forward<Args>(args)...) {}

        void route(const std::string& target, const http_route_type& route) {
            http_routes[target] = route;
        }

        void unroute(const std::string& target) {
            http_routes.erase(target);
        }

        void route_ws(const std::string& target, const ws_route_type& route) {
            ws_routes[target] = route;
        }

        void unroute_ws(const std::string& target) {
            ws_routes.erase(target);
        }

        // Warning: filter is called on the LISTENING THREAD, BEFORE ssl_accept
        int listen(
            std::function<bool(typename Base::connection_type&, void*)> filter = [](typename Base::connection_type&, void*) {
                return false;
            },
            void* filter_data = nullptr,
            int backlog = 128);

    protected:
        std::unordered_map<std::string, http_route_type> http_routes;
        std::unordered_map<std::string, ws_route_type> ws_routes;

        int handle_connection(pn::UniqueSocket<connection_type> conn, pn::tcp::BufReceiver& buf_receiver) const;
        int handle_ws_connection(pn::UniqueSocket<connection_type> conn, pn::tcp::BufReceiver& buf_receiver, const ws_route_type& route) const;
        int handle_error(connection_type& conn, uint16_t status_code, const HTTPHeaders& headers = {}, bool head_only = false, pn::StringView http_version = "HTTP/1.1") const;
        int handle_error(connection_type& conn, uint16_t status_code, bool keep_alive, bool head_only = false, pn::StringView http_version = "HTTP/1.1") const;
    };

    using Server = BasicServer<pn::tcp::Server>;
    using SecureServer = BasicServer<pn::tcp::SecureServer>;

    class ClientConfig {
    public:
        std::chrono::milliseconds send_timeout = std::chrono::seconds(30);
        std::chrono::milliseconds recv_timeout = std::chrono::seconds(30);
        bool tcp_keep_alive = true;

        int verify_mode = SSL_VERIFY_PEER;
        std::string ca_file;
        std::string ca_path;

        size_t recv_buf_size = 4'000;
        unsigned int header_climit = 100;
        long header_name_rlimit = 500;
        long header_value_rlimit = 4'000'000;
        long body_chunk_rlimit = 16'000'000;
        long body_rlimit = 32'000'000;
        long misc_rlimit = 1'000;

        int configure_sockopts(pn::tcp::Connection& conn) const;
        int configure_ssl(pn::tcp::SecureClient& client, pn::StringView hostname) const;
    };

    int fetch(pn::StringView hostname, unsigned short port, bool secure, HTTPRequest req, HTTPResponse& resp, const ClientConfig& = {}, unsigned short max_redirects = 5);
    int fetch(pn::StringView url, HTTPResponse& resp, const HTTPHeaders& headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, pn::StringView http_version = "HTTP/1.1");
    int fetch(pn::StringView method, pn::StringView url, HTTPResponse& resp, const HTTPHeaders& headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, pn::StringView http_version = "HTTP/1.1");
    int fetch(pn::StringView method, pn::StringView url, HTTPResponse& resp, const std::vector<char>& body, const HTTPHeaders& headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, pn::StringView http_version = "HTTP/1.1");
    int fetch(pn::StringView method, pn::StringView url, HTTPResponse& resp, pn::StringView body, const HTTPHeaders& headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, pn::StringView http_version = "HTTP/1.1");

    int proxied_fetch(pn::StringView hostname, unsigned short port, bool secure, pn::StringView proxy_url, HTTPRequest req, HTTPResponse& resp, const ClientConfig& = {}, unsigned short max_redirects = 5);
    int proxied_fetch(pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, const HTTPHeaders& headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, pn::StringView http_version = "HTTP/1.1");
    int proxied_fetch(pn::StringView method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, const HTTPHeaders& headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, pn::StringView http_version = "HTTP/1.1");
    int proxied_fetch(pn::StringView method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, const std::vector<char>& body, const HTTPHeaders& headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, pn::StringView http_version = "HTTP/1.1");
    int proxied_fetch(pn::StringView method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, pn::StringView body, const HTTPHeaders& headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, pn::StringView http_version = "HTTP/1.1");

    template <typename Base>
    class BasicWebSocketClient : public BasicConnection<Base> {
    public:
        pn::tcp::BufReceiver buf_receiver;
        std::function<void(BasicWebSocketClient&, uint16_t, pn::StringView, bool clean, void*)> on_close;

        template <typename... Args>
        BasicWebSocketClient(Args&&... args):
            BasicConnection<Base>(std::forward<Args>(args)...) {}
        BasicWebSocketClient(const Base& conn) {
            *this = conn;
        }

        BasicWebSocketClient<Base>& operator=(const Base& conn);

        int ws_connect(pn::StringView hostname, unsigned short port, pn::StringView target, HTTPResponse& resp, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, unsigned int header_climit = 100, long header_name_rlimit = 500, long header_value_rlimit = 4'000'000, long body_chunk_rlimit = 16'000'000, long body_rlimit = 32'000'000, long misc_rlimit = 1'000);
        int ws_connect(pn::StringView hostname, unsigned short port, pn::StringView target, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, unsigned int header_climit = 100, long header_name_rlimit = 500, long header_value_rlimit = 4'000'000, long body_chunk_rlimit = 16'000'000, long body_rlimit = 32'000'000, long misc_rlimit = 1'000);
        int ws_connect(pn::StringView url, HTTPHeaders headers = {}, unsigned int header_climit = 100, long header_name_rlimit = 500, long header_value_rlimit = 4'000'000, long body_chunk_rlimit = 16'000'000, long body_rlimit = 32'000'000, long misc_rlimit = 1'000);
        int ws_connect(pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, unsigned int header_climit = 100, long header_name_rlimit = 500, long header_value_rlimit = 4'000'000, long body_chunk_rlimit = 16'000'000, long body_rlimit = 32'000'000, long misc_rlimit = 1'000);

        using BasicConnection<Base>::send;

        int send(const WSMessage& message, const char* masking_key = nullptr) override {
            if (masking_key) {
                return BasicConnection<Base>::send(message, masking_key);
            } else {
                static constexpr char masking_key[4] = {0};
                return BasicConnection<Base>::send(message, masking_key);
            }
        }

        using BasicConnection<Base>::recv;

        // Returns the number of messages handled, including the one returned
        // If this returns 0, no messages were handled because the connection was closed
        int recv(WSMessage& message, bool handle_pings = true, long frame_rlimit = 16'000'000, long message_rlimit = 32'000'000);

        int ws_close(uint16_t status_code, pn::StringView reason, const char* masking_key = nullptr, bool validity_check = true) override {
            if (masking_key) {
                return BasicConnection<Base>::ws_close(status_code, reason, masking_key, validity_check);
            } else {
                static constexpr char masking_key[4] = {0};
                return BasicConnection<Base>::ws_close(status_code, reason, masking_key, validity_check);
            }
        }
    };

    using WebSocketClient = BasicWebSocketClient<pn::tcp::Client>;
    using SecureWebSocketClient = BasicWebSocketClient<pn::tcp::SecureClient>;

    int make_websocket_client(SecureWebSocketClient& client, pn::StringView hostname, unsigned short port, bool secure, pn::StringView target, HTTPResponse& resp, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, const ClientConfig& config = {});
    int make_websocket_client(SecureWebSocketClient& client, pn::StringView hostname, unsigned short port, bool secure, pn::StringView target, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, const ClientConfig& config = {});
    int make_websocket_client(SecureWebSocketClient& client, pn::StringView url, HTTPHeaders headers = {}, const ClientConfig& config = {});
    int make_websocket_client(SecureWebSocketClient& client, pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& config = {});

    int make_proxied_websocket_client(SecureWebSocketClient& client, pn::StringView hostname, unsigned short port, bool secure, pn::StringView target, pn::StringView proxy_url, HTTPResponse& resp, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, const ClientConfig& config = {});
    int make_proxied_websocket_client(SecureWebSocketClient& client, pn::StringView hostname, unsigned short port, bool secure, pn::StringView target, pn::StringView proxy_url, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, const ClientConfig& config = {});
    int make_proxied_websocket_client(SecureWebSocketClient& client, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& config = {});
    int make_proxied_websocket_client(SecureWebSocketClient& client, pn::StringView url, pn::StringView proxy_url, HTTPHeaders headers = {}, const ClientConfig& config = {});
} // namespace pw

#endif
