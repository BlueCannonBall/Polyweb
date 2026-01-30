#include "binary.hpp"
#include "polyweb.hpp"
#include <span>
#include <string.h>
#ifdef POLYWEB_SIMD
    #include <x86intrin.h>
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

    int WSMessage::build(pn::tcp::Connection& conn, const char* masking_key) const {
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

                if (pn::ssize_t result = conn.sendall(header.data(), header.size()); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if ((size_t) result != header.size()) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                if (!chunk.empty()) {
                    if (pn::ssize_t result = conn.sendall(chunk.data(), chunk.size()); result == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    } else if ((size_t) result != chunk.size()) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
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

            if (pn::ssize_t result = conn.sendall(header.data(), header.size()); result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if ((size_t) result != header.size()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            if (!data.empty()) {
                if (masking_key) {
                    auto masked_data = new char[data.size()];
                    detail::apply_mask(masked_data, data.data(), data.size(), masking_key);
                    if (pn::ssize_t result = conn.sendall(masked_data, data.size()); result == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        delete[] masked_data;
                        return PN_ERROR;
                    } else if ((size_t) result != data.size()) {
                        detail::set_last_error(PW_EWEB);
                        delete[] masked_data;
                        return PN_ERROR;
                    }
                    delete[] masked_data;
                } else {
                    if (pn::ssize_t result = conn.sendall(data.data(), data.size()); result == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    } else if ((size_t) result != data.size()) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    }
                }
            }
        }

        return PN_OK;
    }

    int WSMessage::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, pn::ssize_t frame_rlimit, pn::ssize_t message_rlimit) {
        data.clear();
        for (bool fin = false; !fin;) {
            char header[2];
            if (pn::ssize_t result = buf_receiver.recvall(conn, header, 2); result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if (result != 2) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
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
                if (pn::ssize_t result = buf_receiver.recvall(conn, buf, 2); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 2) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                uint16_t len16;
                binary::read(buf, buf + 2, len16, BIG_ENDIAN);
                payload_len = len16;
            } else if (len7 == 127) {
                char buf[8];
                if (pn::ssize_t result = buf_receiver.recvall(conn, buf, 8); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 8) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                uint64_t len64;
                binary::read(buf, buf + 8, len64, BIG_ENDIAN);
                payload_len = len64;
            } else {
                payload_len = len7;
            }

            char masking_key[4];
            if (masked) {
                if (pn::ssize_t result = buf_receiver.recvall(conn, masking_key, 4); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 4) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }
            }

            if (payload_len > 0) {
                if (recv_cb) {
                    for (size_t received = 0; received < payload_len;) {
                        std::vector<char> chunk(std::min<size_t>(payload_len - received, frame_rlimit));
                        if (pn::ssize_t result = buf_receiver.recvall(conn, chunk.data(), chunk.size()); result == PN_ERROR) {
                            detail::set_last_error(PW_ENET);
                            return PN_ERROR;
                        } else if ((unsigned long long) result != chunk.size()) {
                            detail::set_last_error(PW_EWEB);
                            return PN_ERROR;
                        }

                        if (masked) {
                            for (size_t i = 0; i < chunk.size(); ++i) {
                                chunk[i] ^= masking_key[(received + i) % 4];
                            }
                        }
                        received += chunk.size();
                        if (!recv_cb(std::move(chunk))) {
                            detail::set_last_error(PW_EWEB);
                            return PN_ERROR;
                        }
                    }
                } else {
                    size_t end = data.size();
                    if ((end + payload_len) > (uint64_t) message_rlimit) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    }
                    data.resize(end + payload_len);
                    if (pn::ssize_t result = buf_receiver.recvall(conn, &data[end], payload_len); result == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    } else if ((uint64_t) result != payload_len) {
                        detail::set_last_error(PW_EWEB);
                        data.resize(end + result);
                        return PN_ERROR;
                    }
                    if (masked) {
                        detail::apply_mask(&data[end], payload_len, masking_key);
                    }
                }
            }
        }
        return PN_OK;
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
    int BasicWSConnection<Base>::recv(WSMessage& message, bool handle_close, bool handle_pings, pn::ssize_t frame_rlimit, pn::ssize_t message_rlimit) {
        std::unique_lock<std::mutex> lock(recv_mutex);
        if (message.parse(*this, this->buf_receiver, frame_rlimit, message_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        lock.unlock();

        if (handle_close && message.opcode == WS_OPCODE_CLOSE) {
            if (!ws_closed && send(message) == PN_ERROR) {
                return PN_ERROR;
            }
            ws_closed = true;
        } else if (handle_pings && message.opcode == WS_OPCODE_PING) {
            if (send(WSMessage(std::move(message.data), WS_OPCODE_PONG)) == PN_ERROR) {
                return PN_ERROR;
            }
        }

        return PN_OK;
    }

    template <typename Base>
    int BasicWSConnection<Base>::ws_close(uint16_t status_code, pn::StringView reason, const char* masking_key) {
        if (send(WSMessage::make_close(status_code, reason), masking_key) == PN_ERROR) {
            return PN_ERROR;
        }
        ws_closed = true;
        return PN_OK;
    }

    template <typename Base>
    int BasicWSClient<Base>::ws_connect(pn::StringView hostname, unsigned short port, std::string target, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers, unsigned int header_climit, pn::ssize_t header_name_rlimit, pn::ssize_t header_value_rlimit, pn::ssize_t body_chunk_rlimit, pn::ssize_t body_rlimit, pn::ssize_t misc_rlimit) {
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

        if (send(req) == PN_ERROR) {
            return PN_ERROR;
        }

        if (resp.parse(*this, this->buf_receiver, PW_HTTP_MESSAGE_PART_HEAD, header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (resp.status_code != 101) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        return PN_OK;
    }

    template <typename Base>
    int BasicWSClient<Base>::ws_connect(pn::StringView hostname, unsigned short port, std::string target, QueryParameters query_parameters, HTTPHeaders headers, unsigned int header_climit, pn::ssize_t header_name_rlimit, pn::ssize_t header_value_rlimit, pn::ssize_t body_chunk_rlimit, pn::ssize_t body_rlimit, pn::ssize_t misc_rlimit) {
        HTTPResponse resp;
        return ws_connect(hostname, port, std::move(target), resp, std::move(query_parameters), std::move(headers), header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit);
    }

    template <typename Base>
    int BasicWSClient<Base>::ws_connect(pn::StringView url, HTTPResponse& resp, HTTPHeaders headers, unsigned int header_climit, pn::ssize_t header_name_rlimit, pn::ssize_t header_value_rlimit, pn::ssize_t body_chunk_rlimit, pn::ssize_t body_rlimit, pn::ssize_t misc_rlimit) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        if (!url_info.credentials.empty() && !headers.count("WWW-Authenticate")) {
            headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return ws_connect(url_info.hostname(), url_info.port(), std::move(url_info.path), resp, std::move(url_info.query_parameters), std::move(headers), header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit);
    }

    template <typename Base>
    int BasicWSClient<Base>::ws_connect(pn::StringView url, HTTPHeaders headers, unsigned int header_climit, pn::ssize_t header_name_rlimit, pn::ssize_t header_value_rlimit, pn::ssize_t body_chunk_rlimit, pn::ssize_t body_rlimit, pn::ssize_t misc_rlimit) {
        HTTPResponse resp;
        return ws_connect(url, resp, std::move(headers), header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit);
    }

    int make_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        if (client.connect(hostname, port, [&config](auto& client) {
                return config.configure_sockopts(client) == PN_OK;
            }) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }

        if (secure) {
            if (config.configure_ssl(client, hostname) == PN_ERROR) {
                return PN_ERROR;
            }
            if (client.ssl_connect() == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
        }

        if (client.ws_connect(hostname, port, std::move(target), resp, std::move(query_parameters), std::move(headers), config.header_climit, config.header_name_rlimit, config.header_value_rlimit, config.body_chunk_rlimit, config.body_rlimit, config.misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }

        return PN_OK;
    }

    int make_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_ws_client(client, hostname, port, secure, std::move(target), resp, std::move(query_parameters), std::move(headers), config);
    }

    int make_ws_client(SecureWSClient& client, pn::StringView url, HTTPResponse& resp, HTTPHeaders headers, const ClientConfig& config) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        if (!url_info.credentials.empty() && !headers.count("WWW-Authenticate")) {
            headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return make_ws_client(client, url_info.hostname(), url_info.port(), url_info.scheme == "wss", std::move(url_info.path), resp, std::move(url_info.query_parameters), std::move(headers), config);
    }

    int make_ws_client(SecureWSClient& client, pn::StringView url, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_ws_client(client, url, resp, std::move(headers), config);
    }

    int make_proxied_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        URLInfo proxy_url_info;
        if (proxy_url_info.parse(proxy_url) == PN_ERROR) {
            return PN_ERROR;
        }
        if (proxy_url_info.scheme != "http") {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
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
        if (client.connect(proxy_url_info.hostname(), proxy_url_info.port(), [&config](auto& client) {
                return config.configure_sockopts(client) == PN_OK;
            }) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }

        if (client.send(connect_req) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPResponse connect_resp;
        if (connect_resp.parse(client, client.buf_receiver, PW_HTTP_MESSAGE_PART_ALL, config.header_climit, config.header_name_rlimit, config.header_value_rlimit, config.body_chunk_rlimit, config.body_rlimit, config.misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        } else if (connect_resp.status_code_category() != 200) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }
        client.buf_receiver.capacity = config.buf_size;

        if (secure) {
            if (config.configure_ssl(client, hostname) == PN_ERROR) {
                return PN_ERROR;
            }
            if (client.ssl_connect() == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
        }

        if (client.ws_connect(hostname, port, std::move(target), resp, std::move(query_parameters), std::move(headers), config.header_climit, config.header_name_rlimit, config.header_value_rlimit, config.body_chunk_rlimit, config.body_rlimit, config.misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }

        return PN_OK;
    }

    int make_proxied_ws_client(SecureWSClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_proxied_ws_client(client, hostname, port, secure, std::move(target), proxy_url, resp, std::move(query_parameters), std::move(headers), config);
    }

    int make_proxied_ws_client(SecureWSClient& client, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers, const ClientConfig& config) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        if (!url_info.credentials.empty() && !headers.count("WWW-Authenticate")) {
            headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return make_proxied_ws_client(client, url_info.hostname(), url_info.port(), url_info.scheme == "wss", std::move(url_info.path), proxy_url, resp, std::move(url_info.query_parameters), std::move(headers), config);
    }

    int make_proxied_ws_client(SecureWSClient& client, pn::StringView url, pn::StringView proxy_url, HTTPHeaders headers, const ClientConfig& config) {
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
