#ifndef POLYWEB_HPP_
#define POLYWEB_HPP_

#include "Polynet/polynet.hpp"
#include "Polynet/secure_sockets.hpp"
#include "string.hpp"
#include "thread_pool.hpp"
#include <algorithm>
#include <chrono>
#include <functional>
#include <iostream>
#include <mutex>
#include <stddef.h>
#include <stdexcept>
#include <stdint.h>
#include <string>
#include <time.h>
#include <unordered_map>
#include <utility>
#include <vector>

#define PW_SERVER_CLIENT_NAME "Polyweb"

// Errors
#define PW_ESUCCESS 0
#define PW_ENET     1
#define PW_EWEB     2

// Protocol layers
#define PW_PROTOCOL_LAYER_WS (1 << 16)

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
    extern tp::ThreadPool thread_pool;

    namespace detail {
        extern thread_local int last_error;

        inline void set_last_error(int error) {
            last_error = error;
        }

        template <typename OutputIt>
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, char end, pn::ssize_t rlimit = 1'000) {
            for (pn::ssize_t i = 0;; ++i) {
                if (i >= rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                char c;
                if (pn::ssize_t result = buf_receiver.recv(conn, &c, 1); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 1) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                if (c == end) {
                    break;
                }
                *ret++ = c;
            }

            return PN_OK;
        }

        template <typename OutputIt>
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, const std::vector<char>& end_sequence, pn::ssize_t rlimit = 1'000) {
            std::vector<char> found_buf;
            for (pn::ssize_t i = 0, search_pos = 0;; ++i) {
                if (i >= rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                char c;
                if (pn::ssize_t result = buf_receiver.recv(conn, &c, 1); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 1) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                if (c == end_sequence[search_pos]) {
                    found_buf.push_back(c);
                    if ((size_t) ++search_pos == end_sequence.size()) {
                        break;
                    }
                } else {
                    std::copy(found_buf.begin(), found_buf.end(), ret);
                    *ret++ = c;
                    found_buf.clear();
                    search_pos = 0;

                    if (c == end_sequence[search_pos]) {
                        found_buf.push_back(c);
                        if ((size_t) ++search_pos == end_sequence.size()) {
                            break;
                        }
                    }
                }
            }

            return PN_OK;
        }

        template <typename OutputIt>
        int recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, pn::StringView end_sequence, pn::ssize_t rlimit = 1'000) {
            return recv_until(conn, buf_receiver, ret, std::vector<char>(end_sequence.begin(), end_sequence.end()), rlimit);
        }
    } // namespace detail

    void reverse_memcpy(void* __restrict dest, const void* __restrict src, size_t size);
    void reverse_memmove(void* dest, const void* src, size_t size);

    inline int get_last_error() {
        return detail::last_error;
    }

    std::string strerror(int error = get_last_error());

    std::string universal_strerror(int error = get_last_error());

    std::string build_date(time_t rawtime = time(nullptr));
    time_t parse_date(const std::string& date);

    std::string base64_encode(const unsigned char* data, size_t size);
    std::string base64_encode(const char* data, size_t size);
    std::vector<char> base64_decode(pn::StringView str);

    std::string percent_encode(pn::StringView str, bool plus_as_space = false, bool allow_slash = true);
    std::string percent_decode(pn::StringView str, bool plus_as_space = false);

    std::wstring xml_escape(pn::WStringView str);
    std::string xml_escape(const std::string& str);

    typedef std::unordered_map<std::string, std::string, string::CaseInsensitiveHasher, string::CaseInsensitiveComparer> HTTPHeaders;

    class QueryParameters {
    private:
        std::unordered_map<std::string, std::string> map;

    public:
        typedef decltype(map) map_type;

        QueryParameters() = default;
        QueryParameters(pn::StringView query_string) {
            parse(query_string);
        }

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
        if (is >> query_string) {
            query_parameters.parse(query_string);
        }
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
            }
            return path + '?' + query_parameters.build();
        }

        std::string username() const {
            return credentials.substr(0, credentials.find(':'));
        }

        std::string password() const {
            if (size_t pos = credentials.find(':'); pos != std::string::npos && ++pos != credentials.size()) {
                return credentials.substr(pos);
            }
            return {};
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

    std::string status_code_to_reason_phrase(uint16_t status_code);

    class HTTPRequest {
    public:
        std::string method;
        std::string target;
        HTTPHeaders headers;
        std::vector<char> body;
        QueryParameters query_parameters;
        std::string http_version = "HTTP/1.1";

        HTTPRequest() = default;
        HTTPRequest(std::string method, std::string target, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            method(std::move(method)),
            target(std::move(target)),
            headers(std::move(headers)),
            http_version(std::move(http_version)) {}
        HTTPRequest(std::string method, std::string target, std::vector<char> body, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            method(std::move(method)),
            target(std::move(target)),
            headers(std::move(headers)),
            body(std::move(body)),
            http_version(std::move(http_version)) {}
        HTTPRequest(std::string method, std::string target, pn::StringView body, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            method(std::move(method)),
            target(std::move(target)),
            headers(std::move(headers)),
            body(body.begin(), body.end()),
            http_version(std::move(http_version)) {}
        HTTPRequest(std::string method, std::string target, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            method(std::move(method)),
            target(std::move(target)),
            headers(std::move(headers)),
            query_parameters(std::move(query_parameters)),
            http_version(std::move(http_version)) {}

        std::vector<char> build() const;

        std::string build_string() const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, unsigned int header_climit = 100, pn::ssize_t header_name_rlimit = 500, pn::ssize_t header_value_rlimit = 4'000'000, pn::ssize_t body_chunk_rlimit = 16'000'000, pn::ssize_t body_rlimit = 32'000'000, pn::ssize_t misc_rlimit = 1'000);

        std::string body_to_string() const {
            return std::string(body.begin(), body.end());
        }

        std::string target_with_query_parameters() const {
            if (query_parameters->empty()) {
                return target;
            }
            return target + '?' + query_parameters.build();
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
        HTTPResponse(uint16_t status_code, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            headers(std::move(headers)),
            http_version(std::move(http_version)) {}
        HTTPResponse(uint16_t status_code, std::vector<char> body, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(std::move(body)),
            headers(std::move(headers)),
            http_version(std::move(http_version)) {}
        HTTPResponse(uint16_t status_code, pn::StringView body, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body.begin(), body.end()),
            headers(std::move(headers)),
            http_version(std::move(http_version)) {}

        static HTTPResponse make_basic(uint16_t status_code, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1") {
            HTTPResponse resp(status_code, std::to_string(status_code) + ' ' + status_code_to_reason_phrase(status_code), std::move(headers), std::move(http_version));
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

        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, bool head_only = false, unsigned int header_climit = 100, pn::ssize_t header_name_rlimit = 500, pn::ssize_t header_value_rlimit = 4'000'000, pn::ssize_t body_chunk_rlimit = 16'000'000, pn::ssize_t body_rlimit = 32'000'000, pn::ssize_t misc_rlimit = 1'000);

        std::string body_string() const {
            return std::string(body.begin(), body.end());
        }

        uint16_t status_code_category() const {
            return status_code / 100 * 100;
        }
    };

    enum WSOpcode : uint8_t {
        WS_OPCODE_CONTINUATION = 0x0,
        WS_OPCODE_TEXT = 0x1,
        WS_OPCODE_BINARY = 0x2,
        WS_OPCODE_CLOSE = 0x8,
        WS_OPCODE_PING = 0x9,
        WS_OPCODE_PONG = 0xA,
    };

    class WSMessage {
    public:
        std::vector<char> data;
        WSOpcode opcode = WS_OPCODE_BINARY;

        WSMessage() = default;
        WSMessage(pn::StringView str, WSOpcode opcode = WS_OPCODE_TEXT):
            data(str.begin(), str.end()),
            opcode(opcode) {}
        WSMessage(std::vector<char> data, WSOpcode opcode = WS_OPCODE_BINARY):
            data(std::move(data)),
            opcode(opcode) {}
        WSMessage(WSOpcode opcode):
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

        std::vector<char> build(const char* masking_key = nullptr) const;
        int parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, pn::ssize_t frame_rlimit = 16'000'000, pn::ssize_t message_rlimit = 32'000'000);

        std::string to_string() const {
            return std::string(data.begin(), data.end());
        }

        uint16_t close_status_code() const;
        std::string close_reason() const;
    };

    template <typename Base>
    class BasicConnection : public Base {
    public:
        template <typename... Args>
        BasicConnection(Args&&... args):
            Base(std::forward<Args>(args)...) {}

        using Base::send;

        int send(const HTTPRequest& req) {
            auto data = req.build();
            if (pn::ssize_t result = Base::sendall(data.data(), data.size()); result == PN_ERROR) {
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
            if (pn::ssize_t result = Base::sendall(data.data(), data.size()); result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if ((size_t) result != data.size()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }
            return PN_OK;
        }

        int send_basic(uint16_t status_code, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1", bool head_only = false) {
            return send(HTTPResponse::make_basic(status_code, std::move(headers), std::move(http_version)), head_only);
        }
    };

    using Connection = BasicConnection<pn::tcp::Connection>;
    using SecureConnection = BasicConnection<pn::tcp::SecureConnection>;

    template <typename Base>
    class BasicWSConnection : public BasicConnection<Base> {
    protected:
        std::mutex mutex;

    public:
        pn::tcp::BufReceiver buf_receiver;
        bool ws_closed = false;

        template <typename... Args>
        BasicWSConnection(Args&&... args):
            BasicConnection<Base>(std::forward<Args>(args)...) {}
        template <typename... Args>
        BasicWSConnection(BasicConnection<Base> conn, pn::tcp::BufReceiver buf_receiver):
            BasicConnection<Base>(std::move(conn)),
            buf_receiver(std::move(buf_receiver)) {}

        virtual int ws_close(uint16_t status_code, pn::StringView reason, const char* masking_key = nullptr);

        // This function can optionally do a WebSocket close, but it would only be somewhat graceful
        int close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override {
            if ((protocol_layers & PW_PROTOCOL_LAYER_WS) && this->is_valid() && !ws_closed) ws_close(1001, {});
            return BasicConnection<Base>::close(protocol_layers);
        }

        using BasicConnection<Base>::send;

        virtual int send(const WSMessage& message, const char* masking_key = nullptr) {
            auto data = message.build(masking_key);
            std::lock_guard<std::mutex> lock(mutex);
            if (pn::ssize_t result = BasicConnection<Base>::sendall(data.data(), data.size()); result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if ((size_t) result != data.size()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }
            return PN_OK;
        }

        using BasicConnection<Base>::recv;

        int recv(WSMessage& message, bool handle_close = true, bool handle_pings = true, pn::ssize_t frame_rlimit = 16'000'000, pn::ssize_t message_rlimit = 32'000'000);
    };

    using WSConnection = BasicWSConnection<pn::tcp::Connection>;
    using SecureWSConnection = BasicWSConnection<pn::tcp::SecureConnection>;

    class Route {
    public:
        bool wildcard = false;

        Route(bool wildcard = false):
            wildcard(wildcard) {}
    };

    template <typename T>
    class BasicHTTPRoute : public Route {
    public:
        std::function<HTTPResponse(const BasicConnection<T>&, const HTTPRequest&)> cb;

        BasicHTTPRoute() = default;
        BasicHTTPRoute(decltype(cb) cb, bool wildcard = false):
            Route(wildcard),
            cb(std::move(cb)) {}
    };

    using HTTPRoute = BasicHTTPRoute<pn::tcp::Connection>;
    using SecureHTTPRoute = BasicHTTPRoute<pn::tcp::SecureConnection>;

    template <typename T>
    class BasicWSRoute : public Route {
    public:
        std::function<HTTPResponse(const BasicConnection<T>&, const HTTPRequest&)> on_connect;
        std::function<void(BasicWSConnection<T>, HTTPRequest)> on_open;

        BasicWSRoute() = default;
        BasicWSRoute(decltype(on_open) on_open, bool wildcard = false):
            Route(wildcard),
            on_open(std::move(on_open)) {}
        BasicWSRoute(decltype(on_connect) on_connect, decltype(on_open) on_open, bool wildcard = false, bool handle_pings = true):
            Route(wildcard),
            on_connect(std::move(on_connect)),
            on_open(std::move(on_open)) {}
    };

    using WSRoute = BasicWSRoute<pn::tcp::Connection>;
    using SecureWSRoute = BasicWSRoute<pn::tcp::SecureConnection>;

    template <typename Base>
    class BasicServer : public Base {
    protected:
        tp::TaskManager task_manager;

    public:
        std::function<HTTPResponse(uint16_t)> on_error;
        size_t buf_size = 4'000;
        unsigned int header_climit = 100;
        pn::ssize_t header_name_rlimit = 500;
        pn::ssize_t header_value_rlimit = 4'000'000;
        pn::ssize_t body_chunk_rlimit = 16'000'000;
        pn::ssize_t body_rlimit = 32'000'000;
        pn::ssize_t misc_rlimit = 1'000;

        typedef BasicConnection<typename Base::connection_type> connection_type;
        typedef BasicWSConnection<typename Base::connection_type> ws_connection_type;

        typedef BasicHTTPRoute<typename Base::connection_type> http_route_type;
        typedef BasicWSRoute<typename Base::connection_type> ws_route_type;

        template <typename... Args>
        BasicServer(Args&&... args):
            Base(std::forward<Args>(args)...) {}

        void route(std::string target, http_route_type route) {
            http_routes.insert_or_assign(std::move(target), std::move(route));
        }

        void unroute(const std::string& target) {
            http_routes.erase(target);
        }

        void route_ws(std::string target, ws_route_type route) {
            ws_routes.insert_or_assign(std::move(target), std::move(route));
        }

        void unroute_ws(const std::string& target) {
            ws_routes.erase(target);
        }

        // Returning false from config_cb allows you to reject a connection very early
        int listen(std::function<bool(typename Base::connection_type&)> config_cb = {}, int backlog = 128);

    protected:
        std::unordered_map<std::string, http_route_type> http_routes;
        std::unordered_map<std::string, ws_route_type> ws_routes;

        int handle_connection(connection_type conn, pn::tcp::BufReceiver buf_receiver) const;
        int handle_error(connection_type& conn, uint16_t status_code, const HTTPHeaders& headers = {}, bool head_only = false, std::string http_version = "HTTP/1.1") const;
        int handle_error(connection_type& conn, uint16_t status_code, bool keep_alive, bool head_only = false, std::string http_version = "HTTP/1.1") const;
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

        size_t buf_size = 4'000;
        unsigned int header_climit = 100;
        pn::ssize_t header_name_rlimit = 500;
        pn::ssize_t header_value_rlimit = 4'000'000;
        pn::ssize_t body_chunk_rlimit = 16'000'000;
        pn::ssize_t body_rlimit = 32'000'000;
        pn::ssize_t misc_rlimit = 1'000;

        int configure_sockopts(pn::tcp::Connection& conn) const;
        int configure_ssl(pn::tcp::SecureClient& client, pn::StringView hostname) const;
    };

    using Client = BasicConnection<pn::tcp::Client>;
    using SecureClient = BasicConnection<pn::tcp::SecureClient>;

    int fetch(pn::StringView hostname, unsigned short port, bool secure, HTTPRequest req, HTTPResponse& resp, const ClientConfig& = {}, unsigned short max_redirects = 5);
    int fetch(pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, std::string http_version = "HTTP/1.1");
    int fetch(std::string method, pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, std::string http_version = "HTTP/1.1");
    int fetch(std::string method, pn::StringView url, HTTPResponse& resp, std::vector<char> body, HTTPHeaders headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, std::string http_version = "HTTP/1.1");
    int fetch(std::string method, pn::StringView url, HTTPResponse& resp, pn::StringView body, HTTPHeaders headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, std::string http_version = "HTTP/1.1");

    int proxied_fetch(pn::StringView hostname, unsigned short port, bool secure, pn::StringView proxy_url, HTTPRequest req, HTTPResponse& resp, const ClientConfig& = {}, unsigned short max_redirects = 5);
    int proxied_fetch(pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, std::string http_version = "HTTP/1.1");
    int proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, std::string http_version = "HTTP/1.1");
    int proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, std::vector<char> body, HTTPHeaders headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, std::string http_version = "HTTP/1.1");
    int proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, pn::StringView body, HTTPHeaders headers = {}, const ClientConfig& = {}, unsigned short max_redirects = 5, std::string http_version = "HTTP/1.1");

    template <typename Base>
    class BasicWSClient : public BasicWSConnection<Base> {
    public:
        template <typename... Args>
        BasicWSClient(Args&&... args):
            BasicWSConnection<Base>(std::forward<Args>(args)...) {}

        int ws_connect(pn::StringView hostname, unsigned short port, std::string target, HTTPResponse& resp, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, unsigned int header_climit = 100, pn::ssize_t header_name_rlimit = 500, pn::ssize_t header_value_rlimit = 4'000'000, pn::ssize_t body_chunk_rlimit = 16'000'000, pn::ssize_t body_rlimit = 32'000'000, pn::ssize_t misc_rlimit = 1'000);
        int ws_connect(pn::StringView hostname, unsigned short port, std::string target, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, unsigned int header_climit = 100, pn::ssize_t header_name_rlimit = 500, pn::ssize_t header_value_rlimit = 4'000'000, pn::ssize_t body_chunk_rlimit = 16'000'000, pn::ssize_t body_rlimit = 32'000'000, pn::ssize_t misc_rlimit = 1'000);
        int ws_connect(pn::StringView url, HTTPHeaders headers = {}, unsigned int header_climit = 100, pn::ssize_t header_name_rlimit = 500, pn::ssize_t header_value_rlimit = 4'000'000, pn::ssize_t body_chunk_rlimit = 16'000'000, pn::ssize_t body_rlimit = 32'000'000, pn::ssize_t misc_rlimit = 1'000);
        int ws_connect(pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, unsigned int header_climit = 100, pn::ssize_t header_name_rlimit = 500, pn::ssize_t header_value_rlimit = 4'000'000, pn::ssize_t body_chunk_rlimit = 16'000'000, pn::ssize_t body_rlimit = 32'000'000, pn::ssize_t misc_rlimit = 1'000);

        using BasicWSConnection<Base>::send;

        int send(const WSMessage& message, const char* masking_key = nullptr) override {
            if (!masking_key) {
                static constexpr char default_masking_key[4] = {0};
                masking_key = default_masking_key;
            }
            return BasicWSConnection<Base>::send(message, masking_key);
        }
    };

    using WSClient = BasicWSClient<pn::tcp::Client>;
    using SecureWSClient = BasicWSClient<pn::tcp::SecureClient>;

    int make_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, HTTPResponse& resp, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, const ClientConfig& config = {});
    int make_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, const ClientConfig& config = {});
    int make_ws_client(SecureWSClient& client, pn::StringView url, HTTPHeaders headers = {}, const ClientConfig& config = {});
    int make_ws_client(SecureWSClient& client, pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& config = {});

    int make_proxied_websocket_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, HTTPResponse& resp, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, const ClientConfig& config = {});
    int make_proxied_websocket_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, const ClientConfig& config = {});
    int make_proxied_websocket_client(SecureWSClient& client, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& config = {});
    int make_proxied_websocket_client(SecureWSClient& client, pn::StringView url, pn::StringView proxy_url, HTTPHeaders headers = {}, const ClientConfig& config = {});
} // namespace pw

#endif
