#ifndef POLYWEB_HPP_
#define POLYWEB_HPP_

#include "Polynet/polynet.hpp"
#include "Polynet/tls.hpp"
#include "error.hpp"
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

#define PW_AGENT_NAME "Polyweb"

// Protocol layers
#define PW_PROTOCOL_LAYER_WS (1 << 16)

// HTTP macros
#define PW_HTTP_MESSAGE_PART_NONE       0
#define PW_HTTP_MESSAGE_PART_START_LINE 0b001
#define PW_HTTP_MESSAGE_PART_HEADERS    0b010
#define PW_HTTP_MESSAGE_PART_HEAD       0b011
#define PW_HTTP_MESSAGE_PART_BODY       0b100
#define PW_HTTP_MESSAGE_PART_ALL        0b111

// WebSocket macros
#define PW_WS_VERSION "13"
#define PW_WS_KEY     "cG9seXdlYiBpcyBncmVhdA==" // polyweb is great

namespace pw {
    extern tp::ThreadPool thread_pool;

    namespace detail {
        template <typename OutputIt>
        pn::Status recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, char end, size_t rlimit = 1'000) {
            for (size_t i = 0;; ++i) {
                if (i >= rlimit) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "read HTTP line"));
                }

                char c;
                if (pn::Result<size_t> result = buf_receiver.recv(conn, &c, sizeof c); !result) {
                    return std::unexpected(result.error());
                } else if (*result != sizeof c) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP line"));
                }

                if (c == end) {
                    break;
                }
                *ret++ = c;
            }

            return {};
        }

        template <typename OutputIt>
        pn::Status recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, const std::vector<char>& end_sequence, size_t rlimit = 1'000) {
            std::vector<char> found_buf;
            for (size_t i = 0, search_pos = 0;; ++i) {
                if (i >= rlimit) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "read HTTP delimiter"));
                }

                char c;
                if (pn::Result<size_t> result = buf_receiver.recv(conn, &c, sizeof c); !result) {
                    return std::unexpected(result.error());
                } else if (*result != sizeof c) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP delimiter"));
                }

                if (c == end_sequence[search_pos]) {
                    found_buf.push_back(c);
                    if (++search_pos == end_sequence.size()) {
                        break;
                    }
                } else {
                    std::copy(found_buf.begin(), found_buf.end(), ret);
                    *ret++ = c;
                    found_buf.clear();
                    search_pos = 0;

                    if (c == end_sequence[search_pos]) {
                        found_buf.push_back(c);
                        if (++search_pos == end_sequence.size()) {
                            break;
                        }
                    }
                }
            }

            return {};
        }

        template <typename OutputIt>
        pn::Status recv_until(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, OutputIt ret, pn::StringView end_sequence, size_t rlimit = 1'000) {
            return recv_until(conn, buf_receiver, ret, std::vector<char>(end_sequence.begin(), end_sequence.end()), rlimit);
        }
    } // namespace detail

    void reverse_memcpy(void* __restrict dest, const void* __restrict src, size_t size);
    void reverse_memmove(void* dest, const void* src, size_t size);

    std::string build_date(time_t rawtime = time(nullptr));
    time_t parse_date(const std::string& date);

    std::string base64_encode(const unsigned char* data, size_t size);
    std::string base64_encode(const char* data, size_t size);
    std::vector<char> base64_decode(pn::StringView str);

    std::string percent_encode(pn::StringView str, bool plus_as_space = false, bool allow_slash = true);
    std::string percent_decode(pn::StringView str, bool plus_as_space = false);

    std::wstring xml_escape(pn::WStringView str);
    std::string xml_escape(const std::string& str);

    std::string status_code_to_reason_phrase(uint16_t status_code);

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

        const map_type& operator*() const noexcept {
            return map;
        }

        map_type& operator*() noexcept {
            return map;
        }

        const map_type* operator->() const noexcept {
            return &map;
        }

        map_type* operator->() noexcept {
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
            if (!parse(url)) {
                throw std::runtime_error("Invalid URL passed to pw::URLInfo constructor");
            }
        }

        std::string build() const;
        pn::Status parse(pn::StringView url);

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
        if (std::string url; (is >> url) && !url_info.parse(url)) {
            is.setstate(std::istream::failbit);
        }
        return is;
    }

    struct HTTPMessageConfig {
        unsigned int header_climit = 100;
        size_t header_name_rlimit = 500;
        size_t header_value_rlimit = 4'000'000;
        size_t body_chunk_rlimit = 16'000'000;
        size_t body_rlimit = 32'000'000;
        size_t misc_rlimit = 1'000;
    };

    class HTTPRequest {
    public:
        std::string method;
        std::string target;
        HTTPHeaders headers;
        std::vector<char> body;
        std::move_only_function<std::vector<char>()> send_cb;
        std::move_only_function<bool(std::vector<char>)> recv_cb;
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
        HTTPRequest(std::string method, std::string target, decltype(send_cb) body_cb, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            method(std::move(method)),
            target(std::move(target)),
            headers(std::move(headers)),
            send_cb(std::move(body_cb)),
            http_version(std::move(http_version)) {}
        HTTPRequest(std::string method, std::string target, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            method(std::move(method)),
            target(std::move(target)),
            headers(std::move(headers)),
            query_parameters(std::move(query_parameters)),
            http_version(std::move(http_version)) {}

        std::vector<char> build(int parts = PW_HTTP_MESSAGE_PART_ALL);
        pn::Status build(pn::tcp::Connection& conn, int parts = PW_HTTP_MESSAGE_PART_ALL);

        std::string build_string(int parts = PW_HTTP_MESSAGE_PART_ALL) {
            std::vector<char> ret = build(parts);
            return std::string(ret.begin(), ret.end());
        }

        pn::Status parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, int parts = PW_HTTP_MESSAGE_PART_ALL, const HTTPMessageConfig& config = {});

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

    class HTTPRequestReceiver : public HTTPRequest {
    public:
        int parts_parsed = 0;

        pn::Status parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, int parts = PW_HTTP_MESSAGE_PART_ALL, const HTTPMessageConfig& config = {});
    };

    class HTTPResponse {
    public:
        uint16_t status_code;
        std::string reason_phrase;
        std::vector<char> body;
        std::move_only_function<std::vector<char>()> send_cb;
        std::move_only_function<bool(std::vector<char>)> recv_cb;
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
        HTTPResponse(uint16_t status_code, decltype(send_cb) send_cb, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1"):
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            send_cb(std::move(send_cb)),
            headers(std::move(headers)),
            http_version(std::move(http_version)) {}

        static HTTPResponse make_basic(uint16_t status_code, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1") {
            HTTPResponse resp(status_code, std::to_string(status_code) + ' ' + status_code_to_reason_phrase(status_code), std::move(headers), std::move(http_version));
            if (!resp.headers.count("Content-Type")) {
                resp.headers["Content-Type"] = "text/plain";
            }
            return resp;
        }

        std::vector<char> build(int parts = PW_HTTP_MESSAGE_PART_ALL);
        pn::Status build(pn::tcp::Connection& conn, int parts = PW_HTTP_MESSAGE_PART_ALL);

        std::string build_string(int parts = PW_HTTP_MESSAGE_PART_ALL) {
            std::vector<char> ret = build(parts);
            return std::string(ret.begin(), ret.end());
        }

        pn::Status parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, int parts = PW_HTTP_MESSAGE_PART_ALL, const HTTPMessageConfig& config = {});

        std::string body_string() const {
            return std::string(body.begin(), body.end());
        }

        constexpr uint16_t status_code_category() const noexcept {
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

    struct WSConfig {
        size_t frame_rlimit = 16'000'000;
        size_t message_rlimit = 32'000'000;
    };

    class WSMessage {
    public:
        WSOpcode opcode = WS_OPCODE_BINARY;
        std::vector<char> data;
        std::move_only_function<std::vector<char>()> send_cb;
        std::move_only_function<bool(std::vector<char>)> recv_cb;

        WSMessage() = default;
        WSMessage(pn::StringView str, WSOpcode opcode = WS_OPCODE_TEXT):
            opcode(opcode),
            data(str.begin(), str.end()) {}
        WSMessage(std::vector<char> data, WSOpcode opcode = WS_OPCODE_BINARY):
            opcode(opcode),
            data(std::move(data)) {}
        WSMessage(decltype(send_cb) send_cb, WSOpcode opcode = WS_OPCODE_BINARY):
            opcode(opcode),
            send_cb(std::move(send_cb)) {}
        WSMessage(WSOpcode opcode) noexcept:
            opcode(opcode) {}

        static WSMessage make_close(uint16_t status_code, pn::StringView reason);

        const std::vector<char>& operator*() const noexcept {
            return data;
        }

        std::vector<char>& operator*() noexcept {
            return data;
        }

        const std::vector<char>* operator->() const noexcept {
            return &data;
        }

        std::vector<char>* operator->() noexcept {
            return &data;
        }

        std::vector<char> build(const char* masking_key = nullptr);
        pn::Status build(pn::tcp::Connection& conn, const char* masking_key = nullptr);

        pn::Status parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, const WSConfig& config = {});

        std::string to_string() const {
            return std::string(data.begin(), data.end());
        }

        uint16_t close_status_code() const;
        std::string close_reason() const;
    };

    template <typename Base>
    class BasicConnection : public Base {
    public:
        pn::tcp::BufReceiver buf_receiver;
        HTTPMessageConfig http_config;

        using Base::Base;

        BasicConnection(Base conn, pn::tcp::BufReceiver buf_receiver, HTTPMessageConfig http_config = {}):
            Base(std::move(conn)),
            buf_receiver(std::move(buf_receiver)),
            http_config(std::move(http_config)) {}

        using Base::send;

        pn::Status send(HTTPRequest req, int parts = PW_HTTP_MESSAGE_PART_ALL) {
            return req.build(*this, parts);
        }

        pn::Status send(HTTPResponse resp, int parts = PW_HTTP_MESSAGE_PART_ALL) {
            return resp.build(*this, parts);
        }

        pn::Status send_basic(uint16_t status_code, HTTPHeaders headers = {}, std::string http_version = "HTTP/1.1", int parts = PW_HTTP_MESSAGE_PART_ALL) {
            return send(HTTPResponse::make_basic(status_code, std::move(headers), std::move(http_version)), parts);
        }

        using Base::recv;

        pn::Status recv(HTTPRequest& req, int parts = PW_HTTP_MESSAGE_PART_ALL) {
            return req.parse(*this, buf_receiver, parts, http_config);
        }

        pn::Status recv(HTTPRequestReceiver& req, int parts = PW_HTTP_MESSAGE_PART_ALL) {
            return req.parse(*this, buf_receiver, parts, http_config);
        }

        pn::Status recv(HTTPResponse& resp, int parts = PW_HTTP_MESSAGE_PART_ALL) {
            return resp.parse(*this, buf_receiver, parts, http_config);
        }
    };

    using Connection = BasicConnection<pn::tcp::Connection>;
    using TLSConnection = BasicConnection<pn::tcp::TLSConnection>;

    template <typename Base>
    class BasicWSConnection : public BasicConnection<Base> {
    protected:
        std::mutex send_mutex;

    public:
        WSConfig ws_config;
        bool ws_closed = false;

        using BasicConnection<Base>::BasicConnection;
        BasicWSConnection(BasicConnection<Base> conn, WSConfig ws_config):
            BasicConnection<Base>(std::move(conn)),
            ws_config(std::move(ws_config)) {}
        BasicWSConnection(BasicWSConnection&& conn) {
            *this = std::move(conn);
        }

        BasicWSConnection& operator=(BasicWSConnection&& conn) {
            if (this != &conn) {
                BasicConnection<Base>::operator=(std::move(conn));
                ws_closed = std::exchange(conn.ws_closed, false);
                ws_config = std::move(conn.ws_config);
            }
            return *this;
        }

        ~BasicWSConnection() {
            (void) close();
        }

        virtual pn::Status ws_close(uint16_t status_code, pn::StringView reason, const char* masking_key = nullptr);

        // This function can optionally do a WebSocket close, but it would only be somewhat graceful
        pn::Status close(int protocol_layers = PN_PROTOCOL_LAYER_DEFAULT) override {
            if ((protocol_layers & PW_PROTOCOL_LAYER_WS) && this->is_valid() && !ws_closed) {
                (void) ws_close(1001, {});
            }
            return BasicConnection<Base>::close(protocol_layers);
        }

        using BasicConnection<Base>::send;

        virtual pn::Status send(WSMessage message, const char* masking_key = nullptr) {
            std::lock_guard<std::mutex> lock(send_mutex);
            return message.build(*this, masking_key);
        }

        using BasicConnection<Base>::recv;

        pn::Status recv(WSMessage& message, bool handle_close = true, bool handle_pings = true);
    };

    using WSConnection = BasicWSConnection<pn::tcp::Connection>;
    using TLSWSConnection = BasicWSConnection<pn::tcp::TLSConnection>;

    class Route {
    public:
        bool wildcard;

        Route(bool wildcard = false):
            wildcard(wildcard) {}
    };

    template <typename T>
    class BasicHTTPRoute : public Route {
    public:
        std::function<HTTPResponse(BasicConnection<T>&, HTTPRequestReceiver&)> cb;
        bool parse_body = true;

        BasicHTTPRoute() = default;
        BasicHTTPRoute(decltype(cb) cb, bool wildcard = false, bool parse_body = true):
            Route(wildcard),
            cb(std::move(cb)),
            parse_body(parse_body) {}
    };

    using HTTPRoute = BasicHTTPRoute<pn::tcp::Connection>;
    using TLSHTTPRoute = BasicHTTPRoute<pn::tcp::TLSConnection>;

    template <typename T>
    class BasicWSRoute : public Route {
    public:
        std::function<HTTPResponse(const BasicConnection<T>&, const HTTPRequest&)> on_connect;
        std::function<void(BasicWSConnection<T>, HTTPRequest)> on_open;

        BasicWSRoute() = default;
        BasicWSRoute(decltype(on_open) on_open, bool wildcard = false):
            Route(wildcard),
            on_open(std::move(on_open)) {}
        BasicWSRoute(decltype(on_connect) on_connect, decltype(on_open) on_open, bool wildcard = false):
            Route(wildcard),
            on_connect(std::move(on_connect)),
            on_open(std::move(on_open)) {}
    };

    using WSRoute = BasicWSRoute<pn::tcp::Connection>;
    using TLSWSRoute = BasicWSRoute<pn::tcp::TLSConnection>;

    struct ServerConfig {
        size_t buf_capacity = 4'000;
        HTTPMessageConfig http;
        WSConfig ws;
    };

    template <typename Base>
    class BasicServer : public Base {
    protected:
        tp::TaskManager task_manager;

    public:
        std::function<HTTPResponse(uint16_t, pn::StringView)> on_error;
        ServerConfig config;

        typedef BasicConnection<typename Base::connection_type> connection_type;
        typedef BasicWSConnection<typename Base::connection_type> ws_connection_type;

        typedef BasicHTTPRoute<typename Base::connection_type> http_route_type;
        typedef BasicWSRoute<typename Base::connection_type> ws_route_type;

        using Base::Base;

        void route(std::string target, http_route_type route) {
            http_routes.insert_or_assign(std::move(target), std::move(route));
        }

        void unroute(const std::string& target) {
            http_routes.erase(target);
        }

        void ws_route(std::string target, ws_route_type route) {
            ws_routes.insert_or_assign(std::move(target), std::move(route));
        }

        void ws_unroute(const std::string& target) {
            ws_routes.erase(target);
        }

        // Returning false from config_cb allows you to reject a connection very early
        pn::Status listen(std::function<bool(typename Base::connection_type&)> config_cb = {}, int backlog = 128)
            requires(!std::is_same_v<Base, pn::tcp::TLSServer>);

        pn::Status listen(const pn::TLSContext& context, std::function<bool(typename Base::connection_type&)> config_cb = {}, int backlog = 128)
            requires std::is_same_v<Base, pn::tcp::TLSServer>;

    protected:
        std::unordered_map<std::string, http_route_type> http_routes;
        std::unordered_map<std::string, ws_route_type> ws_routes;

        pn::Status handle_conn(connection_type conn) const;
        pn::Status handle_error(connection_type& conn, uint16_t status_code, const HTTPHeaders& headers = {}, int parts = PW_HTTP_MESSAGE_PART_ALL, std::string http_version = "HTTP/1.1") const;
        pn::Status handle_error(connection_type& conn, uint16_t status_code, bool keep_alive, int parts = PW_HTTP_MESSAGE_PART_ALL, std::string http_version = "HTTP/1.1") const;
        pn::Status handle_error(connection_type& conn, uint16_t status_code, pn::StringView what, const HTTPHeaders& headers = {}, int parts = PW_HTTP_MESSAGE_PART_ALL, std::string http_version = "HTTP/1.1") const;
        pn::Status handle_error(connection_type& conn, uint16_t status_code, pn::StringView what, bool keep_alive, int parts = PW_HTTP_MESSAGE_PART_ALL, std::string http_version = "HTTP/1.1") const;
    };

    using Server = BasicServer<pn::tcp::Server>;
    using TLSServer = BasicServer<pn::tcp::TLSServer>;

    class ClientConfig {
    public:
        std::chrono::milliseconds send_timeout = std::chrono::seconds(30);
        std::chrono::milliseconds recv_timeout = std::chrono::seconds(30);
        bool tcp_keep_alive = true;
        bool tcp_no_delay = true;

        int verify_mode = SSL_VERIFY_PEER;
        std::string ca_file;
        std::string ca_path;
        std::function<bool(SSL_CTX*)> tls_config_cb; // Applied to the TLS context once it is built

        size_t buf_capacity = 4'000;
        HTTPMessageConfig http;
        WSConfig ws;

        pn::Status configure_sockopts(pn::tcp::Connection& conn) const;
        pn::Status configure_tls(pn::TLSContext& context) const;
    };

    using Client = BasicConnection<pn::tcp::Client>;
    using TLSClient = BasicConnection<pn::tcp::TLSClient>;

    pn::Status fetch(pn::StringView hostname, unsigned short port, bool secure, HTTPRequest req, HTTPResponse& resp, const ClientConfig& = {});
    pn::Status fetch(pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");
    pn::Status fetch(std::string method, pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");
    pn::Status fetch(std::string method, pn::StringView url, HTTPResponse& resp, std::vector<char> body, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");
    pn::Status fetch(std::string method, pn::StringView url, HTTPResponse& resp, pn::StringView body, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");
    pn::Status fetch(std::string method, pn::StringView url, HTTPResponse& resp, std::move_only_function<std::vector<char>()> body_cb, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");

    pn::Status proxied_fetch(pn::StringView hostname, unsigned short port, bool secure, pn::StringView proxy_url, HTTPRequest req, HTTPResponse& resp, const ClientConfig& = {});
    pn::Status proxied_fetch(pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");
    pn::Status proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");
    pn::Status proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, std::vector<char> body, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");
    pn::Status proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, pn::StringView body, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");
    pn::Status proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, std::move_only_function<std::vector<char>()> body_cb, HTTPHeaders headers = {}, const ClientConfig& = {}, std::string http_version = "HTTP/1.1");

    template <typename Base>
    class BasicWSClient : public BasicWSConnection<Base> {
    public:
        using BasicWSConnection<Base>::BasicWSConnection;

        pn::Status ws_connect(pn::StringView hostname, unsigned short port, std::string target, HTTPResponse& resp, QueryParameters query_parameters = {}, HTTPHeaders headers = {});
        pn::Status ws_connect(pn::StringView hostname, unsigned short port, std::string target, QueryParameters query_parameters = {}, HTTPHeaders headers = {});
        pn::Status ws_connect(pn::StringView url, HTTPHeaders headers = {});
        pn::Status ws_connect(pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {});

        using BasicWSConnection<Base>::send;

        pn::Status send(WSMessage message, const char* masking_key = nullptr) override {
            if (!masking_key) {
                static constexpr char default_masking_key[4] = {0};
                masking_key = default_masking_key;
            }
            return BasicWSConnection<Base>::send(std::move(message), masking_key);
        }
    };

    using WSClient = BasicWSClient<pn::tcp::Client>;
    using TLSWSClient = BasicWSClient<pn::tcp::TLSClient>;

    pn::Status make_ws_client(TLSWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, HTTPResponse& resp, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, const ClientConfig& config = {});
    pn::Status make_ws_client(TLSWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, const ClientConfig& config = {});
    pn::Status make_ws_client(TLSWSClient& client, pn::StringView url, HTTPHeaders headers = {}, const ClientConfig& config = {});
    pn::Status make_ws_client(TLSWSClient& client, pn::StringView url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& config = {});

    pn::Status make_proxied_ws_client(TLSWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, HTTPResponse& resp, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, const ClientConfig& config = {});
    pn::Status make_proxied_ws_client(TLSWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, QueryParameters query_parameters = {}, HTTPHeaders headers = {}, const ClientConfig& config = {});
    pn::Status make_proxied_ws_client(TLSWSClient& client, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers = {}, const ClientConfig& config = {});
    pn::Status make_proxied_ws_client(TLSWSClient& client, pn::StringView url, pn::StringView proxy_url, HTTPHeaders headers = {}, const ClientConfig& config = {});
} // namespace pw

#endif
