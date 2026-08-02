#include "binary.hpp"
#include "polyweb.hpp"
#include <span>
#include <string.h>
#ifdef POLYWEB_SIMD
    #ifdef _MSC_VER
        #include <intrin.h>
    #else
        #include <x86intrin.h>
    #endif
#endif

namespace pw {
    namespace detail {
        void apply_mask(char* dest, const char* src, size_t len, const char* key) {
            size_t i = 0;
#ifdef POLYWEB_SIMD
            int32_t masking_key_int;
            memcpy(&masking_key_int, key, 4);
            __m256i mask_vec256 = _mm256_set1_epi32(masking_key_int);
            for (; i + 32 <= len; i += 32) {
                __m256i src_v = _mm256_loadu_si256((const __m256i_u*) &src[i]);
                _mm256_storeu_si256((__m256i_u*) &dest[i], _mm256_xor_si256(src_v, mask_vec256));
            }
            __m128i mask_vec128 = _mm_set1_epi32(masking_key_int);
            for (; i + 16 <= len; i += 16) {
                __m128i src_v = _mm_loadu_si128((const __m128i_u*) &src[i]);
                _mm_storeu_si128((__m128i_u*) &dest[i], _mm_xor_si128(src_v, mask_vec128));
            }
#endif
            for (; i < len; ++i) {
                dest[i] = src[i] ^ key[i % 4];
            }
        }

        void apply_mask(char* buf, size_t len, const char* key) {
            apply_mask(buf, buf, len, key);
        }
    } // namespace detail

    WSMessage WSMessage::make_close(uint16_t status_code, pn::StringView reason) {
        WSMessage ret(WS_OPCODE_CLOSE);
        ret->resize(2 + reason.size());
        binary::write(ret->begin(), status_code);
        memcpy(ret->data() + 2, reason.data(), reason.size());
        return ret;
    }

    std::vector<char> WSMessage::build(const char* masking_key) const {
        std::vector<char> ret;

        auto write_frame = [this, masking_key, &ret](std::span<const char> chunk, bool is_first, bool is_final) {
            ret.push_back((is_final ? 0x80 : 0x00) | (is_first ? opcode : WS_OPCODE_CONTINUATION));

            unsigned char mask_bit = masking_key ? 0x80 : 0x00;
            if (chunk.size() < 126) {
                ret.push_back(mask_bit | chunk.size());
            } else if (chunk.size() <= 0xFFFF) {
                ret.push_back(mask_bit | 126);
                binary::write<uint16_t>(std::back_inserter(ret), chunk.size());
            } else {
                ret.push_back(mask_bit | 127);
                binary::write<uint64_t>(std::back_inserter(ret), chunk.size());
            }

            if (masking_key) {
                ret.insert(ret.end(), masking_key, masking_key + 4);
            }

            if (!chunk.empty()) {
                size_t end = ret.size();
                ret.resize(end + chunk.size());
                if (masking_key) {
                    detail::apply_mask(ret.data() + end, chunk.data(), chunk.size(), masking_key);
                } else {
                    memcpy(ret.data() + end, chunk.data(), chunk.size());
                }
            }
        };

        if (send_cb) {
            for (bool first = true;; first = false) {
                auto chunk = send_cb();
                write_frame(chunk, first, chunk.empty());
                if (chunk.empty()) break;
            }
        } else {
            write_frame(data, true, true);
        }

        return ret;
    }

    pn::Status WSMessage::build(pn::tcp::Connection& conn, const char* masking_key) const {
        if (send_cb) {
            for (bool first_frame = true;; first_frame = false) {
                std::vector<char> chunk = send_cb();

                std::vector<char> header = {(char) ((chunk.empty() ? 0x80 : 0x00) | (first_frame ? (uint8_t) opcode : (uint8_t) WS_OPCODE_CONTINUATION))};

                uint8_t mask_bit = masking_key ? 0x80 : 0x00;
                if (chunk.size() < 126) {
                    header.push_back(mask_bit | (uint8_t) chunk.size());
                } else if (chunk.size() <= 0xFFFF) {
                    header.push_back(mask_bit | 126);
                    binary::write<uint16_t>(std::back_inserter(header), chunk.size());
                } else {
                    header.push_back(mask_bit | 127);
                    binary::write<uint64_t>(std::back_inserter(header), chunk.size());
                }

                if (masking_key) {
                    header.insert(header.end(), masking_key, masking_key + 4);
                    if (!chunk.empty()) {
                        detail::apply_mask(chunk.data(), chunk.size(), masking_key);
                    }
                }

                if (pn::Result<size_t> result = conn.sendall(header.data(), header.size()); !result) {
                    return std::unexpected(result.error());
                } else if (*result != header.size()) {
                    return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write WebSocket header"});
                }

                if (!chunk.empty()) {
                    if (pn::Result<size_t> result = conn.sendall(chunk.data(), chunk.size()); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != chunk.size()) {
                        return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write WebSocket payload"});
                    }
                }

                if (chunk.empty()) break;
            }
        } else {
            std::vector<char> header = {(char) (0x80 | (uint8_t) opcode)};

            uint8_t mask_bit = (masking_key ? 0x80 : 0x00);
            if (data.size() < 126) {
                header.push_back(mask_bit | (uint8_t) data.size());
            } else if (data.size() <= 0xFFFF) {
                header.push_back(mask_bit | 126);
                binary::write<uint16_t>(std::back_inserter(header), data.size());
            } else {
                header.push_back(mask_bit | 127);
                binary::write<uint64_t>(std::back_inserter(header), data.size());
            }

            if (masking_key) {
                header.insert(header.end(), masking_key, masking_key + 4);
            }

            if (pn::Result<size_t> result = conn.sendall(header.data(), header.size()); !result) {
                return std::unexpected(result.error());
            } else if (*result != header.size()) {
                return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write WebSocket header"});
            }

            if (!data.empty()) {
                if (masking_key) {
                    auto masked_data = new char[data.size()];
                    detail::apply_mask(masked_data, data.data(), data.size(), masking_key);
                    if (pn::Result<size_t> result = conn.sendall(masked_data, data.size()); !result) {
                        delete[] masked_data;
                        return std::unexpected(result.error());
                    } else if (*result != data.size()) {
                        delete[] masked_data;
                        return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write WebSocket payload"});
                    }
                    delete[] masked_data;
                } else {
                    if (pn::Result<size_t> result = conn.sendall(data.data(), data.size()); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != data.size()) {
                        return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write WebSocket payload"});
                    }
                }
            }
        }

        return {};
    }

    pn::Status WSMessage::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, const WSConfig& config) {
        const auto& [frame_rlimit, message_rlimit] = config;
        data.clear();
        for (bool fin = false; !fin;) {
            char header[2];
            if (pn::Result<size_t> result = buf_receiver.recvall(conn, header, sizeof header); !result) {
                return std::unexpected(result.error());
            } else if (*result != sizeof header) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_WS, "parse WebSocket header"));
            }

            fin = header[0] & 0x80;
            WSOpcode opcode = (WSOpcode) (header[0] & 0x0F);
            if (opcode != WS_OPCODE_CONTINUATION) {
                this->opcode = opcode;
            }
            bool masked = header[1] & 0x80;
            uint8_t len7 = header[1] & 0x7F;

            uint64_t payload_len;
            if (len7 == 126) {
                char buf[2];
                if (pn::Result<size_t> result = buf_receiver.recvall(conn, buf, sizeof buf); !result) {
                    return std::unexpected(result.error());
                } else if (*result != sizeof buf) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_WS, "parse WebSocket payload length"));
                }

                uint16_t len16;
                binary::read(buf, buf + 2, len16, BIG_ENDIAN);
                payload_len = len16;
            } else if (len7 == 127) {
                char buf[8];
                if (pn::Result<size_t> result = buf_receiver.recvall(conn, buf, sizeof buf); !result) {
                    return std::unexpected(result.error());
                } else if (*result != sizeof buf) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_WS, "parse WebSocket payload length"));
                }

                uint64_t len64;
                binary::read(buf, buf + 8, len64, BIG_ENDIAN);
                payload_len = len64;
            } else {
                payload_len = len7;
            }

            char masking_key[4];
            if (masked) {
                if (pn::Result<size_t> result = buf_receiver.recvall(conn, masking_key, sizeof masking_key); !result) {
                    return std::unexpected(result.error());
                } else if (*result != sizeof masking_key) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_WS, "parse WebSocket masking key"));
                }
            }

            if (payload_len > 0) {
                if (recv_cb) {
                    for (size_t received = 0; received < payload_len;) {
                        std::vector<char> chunk(std::min<size_t>(payload_len - received, frame_rlimit));
                        if (pn::Result<size_t> result = buf_receiver.recvall(conn, chunk.data(), chunk.size()); !result) {
                            return std::unexpected(result.error());
                        } else if (*result != chunk.size()) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_WS, "read WebSocket payload"));
                        }

                        if (masked) {
                            for (size_t i = 0; i < chunk.size(); ++i) {
                                chunk[i] ^= masking_key[(received + i) % 4];
                            }
                        }
                        received += chunk.size();
                        if (!recv_cb(std::move(chunk))) {
                            return std::unexpected(pn::make_polynet_error(pn::PN_ERROR_USER_CALLBACK, "process WebSocket message callback"));
                        }
                    }
                } else {
                    size_t end = data.size();
                    if ((end + payload_len) > message_rlimit) {
                        return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "read WebSocket payload"));
                    }
                    data.resize(end + payload_len);
                    if (pn::Result<size_t> result = buf_receiver.recvall(conn, &data[end], payload_len); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != payload_len) {
                        data.resize(end + *result);
                        return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_WS, "read WebSocket payload"));
                    }
                    if (masked) {
                        detail::apply_mask(&data[end], payload_len, masking_key);
                    }
                }
            }
        }
        return {};
    }

    uint16_t WSMessage::close_status_code() const {
        uint16_t ret = 0;
        if (data.size() >= 2) {
            binary::read(data.begin(), data.begin() + 2, ret);
        }
        return ret;
    }

    std::string WSMessage::close_reason() const {
        std::string ret;
        if (data.size() > 2) {
            ret.assign(data.begin() + 2, data.end());
        }
        return ret;
    }

    template <typename Base>
    pn::Status BasicWSConnection<Base>::recv(WSMessage& message, bool handle_close, bool handle_pings) {
        if (pn::Status result = message.parse(*this, this->buf_receiver, ws_config); !result) {
            return result;
        }

        if (handle_close && message.opcode == WS_OPCODE_CLOSE) {
            if (!ws_closed) {
                if (pn::Status result = send(message); !result) {
                    return result;
                }
            }
            ws_closed = true;
        } else if (handle_pings && message.opcode == WS_OPCODE_PING) {
            if (pn::Status result = send(WSMessage(std::move(message.data), WS_OPCODE_PONG)); !result) {
                return result;
            }
        }

        return {};
    }

    template <typename Base>
    pn::Status BasicWSConnection<Base>::ws_close(uint16_t status_code, pn::StringView reason, const char* masking_key) {
        if (pn::Status result = send(WSMessage::make_close(status_code, reason), masking_key); !result) {
            return result;
        }
        ws_closed = true;
        return {};
    }

    template <typename Base>
    pn::Status BasicWSClient<Base>::ws_connect(pn::StringView hostname, unsigned short port, std::string target, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers) {
        HTTPRequest req("GET", std::move(target), std::move(query_parameters), std::move(headers));

        if (!req.headers.count("User-Agent")) {
            req.headers["User-Agent"] = PW_AGENT_NAME;
        }
        if (!req.headers.count("Host")) {
            unsigned short default_port[2] = {80, 443};
            if (port == default_port[this->is_secure()]) {
                req.headers["Host"] = hostname;
            } else {
                req.headers["Host"] = std::string(hostname) + ':' + std::to_string(port);
            }
        }
        if (!req.headers.count("Connection")) {
            req.headers["Connection"] = "upgrade";
        }
        if (!req.headers.count("Upgrade")) {
            req.headers["Upgrade"] = "websocket";
        }
        if (!req.headers.count("Sec-WebSocket-Version")) {
            req.headers["Sec-WebSocket-Version"] = PW_WS_VERSION;
        }
        if (!req.headers.count("Sec-WebSocket-Key")) {
            req.headers["Sec-WebSocket-Key"] = PW_WS_KEY;
        }

        if (pn::Status result = send(req); !result) {
            return result;
        }

        if (pn::Status result = resp.parse(*this, this->buf_receiver, PW_HTTP_MESSAGE_PART_HEAD, this->http_config); !result) {
            return result;
        }
        if (resp.status_code != 101) {
            return std::unexpected(make_polyweb_error(PW_ERROR_WS_HANDSHAKE_REJECTED, "validate WebSocket handshake response"));
        }

        return {};
    }

    template <typename Base>
    pn::Status BasicWSClient<Base>::ws_connect(pn::StringView hostname, unsigned short port, std::string target, QueryParameters query_parameters, HTTPHeaders headers) {
        HTTPResponse resp;
        return ws_connect(hostname, port, std::move(target), resp, std::move(query_parameters), std::move(headers));
    }

    template <typename Base>
    pn::Status BasicWSClient<Base>::ws_connect(pn::StringView url, HTTPResponse& resp, HTTPHeaders headers) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        if (!url_info.credentials.empty() && !headers.count("WWW-Authenticate")) {
            headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return ws_connect(url_info.hostname(), url_info.port(), std::move(url_info.path), resp, std::move(url_info.query_parameters), std::move(headers));
    }

    template <typename Base>
    pn::Status BasicWSClient<Base>::ws_connect(pn::StringView url, HTTPHeaders headers) {
        HTTPResponse resp;
        return ws_connect(url, resp, std::move(headers));
    }

    pn::Status make_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        client.http_config = config.http;
        client.ws_config = config.ws;
        pn::Error config_error;
        if (pn::Status result = client.connect(hostname, port, [&config, &config_error](auto& client) {
                if (pn::Status result = config.configure_sockopts(client); !result) {
                    config_error = result.error();
                    return false;
                }
                return true;
            });
            !result) {
            if (config_error) {
                return std::unexpected(config_error);
            }
            return result;
        }

        if (secure) {
            if (pn::Status result = config.configure_ssl(client, hostname); !result) {
                return result;
            }
            if (pn::Status result = client.ssl_connect(); !result) {
                return result;
            }
        }

        if (pn::Status result = client.ws_connect(hostname, port, std::move(target), resp, std::move(query_parameters), std::move(headers)); !result) {
            return result;
        }

        return {};
    }

    pn::Status make_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_ws_client(client, hostname, port, secure, std::move(target), resp, std::move(query_parameters), std::move(headers), config);
    }

    pn::Status make_ws_client(SecureWSClient& client, pn::StringView url, HTTPResponse& resp, HTTPHeaders headers, const ClientConfig& config) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        if (!url_info.credentials.empty() && !headers.count("WWW-Authenticate")) {
            headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return make_ws_client(client, url_info.hostname(), url_info.port(), url_info.scheme == "wss", std::move(url_info.path), resp, std::move(url_info.query_parameters), std::move(headers), config);
    }

    pn::Status make_ws_client(SecureWSClient& client, pn::StringView url, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_ws_client(client, url, resp, std::move(headers), config);
    }

    pn::Status make_proxied_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        client.http_config = config.http;
        client.ws_config = config.ws;
        URLInfo proxy_url_info;
        if (pn::Status result = proxy_url_info.parse(proxy_url); !result) {
            return result;
        }
        if (proxy_url_info.scheme != "http") {
            return std::unexpected(make_polyweb_error(PW_ERROR_UNSUPPORTED, "use non-HTTP proxy"));
        }

        HTTPRequest connect_req("CONNECT",
            std::string(hostname) + ':' + std::to_string(port),
            {
                {"Host", std::string(hostname) + ':' + std::to_string(port)},
                {"Connection", "close"},
            });
        if (!proxy_url_info.credentials.empty() && !connect_req.headers.count("Proxy-Authorization")) {
            connect_req.headers["Proxy-Authorization"] = "basic " + base64_encode(proxy_url_info.credentials.data(), proxy_url_info.credentials.size());
        }

        client.buf_receiver.capacity = 0;
        pn::Error config_error;
        if (pn::Status result = client.connect(proxy_url_info.hostname(), proxy_url_info.port(), [&config, &config_error](auto& client) {
                if (pn::Status result = config.configure_sockopts(client); !result) {
                    config_error = result.error();
                    return false;
                }
                return true;
            });
            !result) {
            if (config_error) {
                return std::unexpected(config_error);
            }
            return result;
        }

        if (pn::Status result = client.send(connect_req); !result) {
            return result;
        }

        HTTPResponse connect_resp;
        if (pn::Status result = client.recv(connect_resp); !result) {
            return result;
        } else if (connect_resp.status_code_category() != 200) {
            return std::unexpected(make_polyweb_error(PW_ERROR_PROXY_CONNECT_REJECTED, "perform HTTP proxy CONNECT"));
        }
        client.buf_receiver.capacity = config.buf_capacity;

        if (secure) {
            if (pn::Status result = config.configure_ssl(client, hostname); !result) {
                return result;
            }
            if (pn::Status result = client.ssl_connect(); !result) {
                return result;
            }
        }

        if (pn::Status result = client.ws_connect(hostname, port, std::move(target), resp, std::move(query_parameters), std::move(headers)); !result) {
            return result;
        }

        return {};
    }

    pn::Status make_proxied_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_proxied_ws_client(client, hostname, port, secure, std::move(target), proxy_url, resp, std::move(query_parameters), std::move(headers), config);
    }

    pn::Status make_proxied_ws_client(SecureWSClient& client, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers, const ClientConfig& config) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        if (!url_info.credentials.empty() && !headers.count("WWW-Authenticate")) {
            headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return make_proxied_ws_client(client, url_info.hostname(), url_info.port(), url_info.scheme == "wss", std::move(url_info.path), proxy_url, resp, std::move(url_info.query_parameters), std::move(headers), config);
    }

    pn::Status make_proxied_ws_client(SecureWSClient& client, pn::StringView url, pn::StringView proxy_url, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_proxied_ws_client(client, url, proxy_url, resp, std::move(headers), config);
    }

    template class BasicWSConnection<pn::tcp::Connection>;
    template class BasicWSConnection<pn::tcp::SecureConnection>;

    template class BasicWSConnection<pn::tcp::Client>;
    template class BasicWSConnection<pn::tcp::SecureClient>;

    template class BasicWSClient<pn::tcp::Client>;
    template class BasicWSClient<pn::tcp::SecureClient>;
} // namespace pw
