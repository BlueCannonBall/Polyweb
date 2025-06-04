#include "polyweb.hpp"
#include <string.h>
#ifdef POLYWEB_SIMD
    #include <x86intrin.h>
#endif

namespace pw {
    std::vector<char> WSMessage::build(const char* masking_key) const {
        std::vector<char> ret(2);

        PW_SET_WS_FRAME_FIN(ret);
        PW_CLEAR_WS_FRAME_RSV1(ret);
        PW_CLEAR_WS_FRAME_RSV2(ret);
        PW_CLEAR_WS_FRAME_RSV3(ret);
        PW_SET_WS_FRAME_OPCODE(ret, opcode);

        if (data.size() < 126) {
            PW_SET_WS_FRAME_PAYLOAD_LENGTH(ret, data.size());
        } else if (data.size() <= UINT16_MAX) {
            PW_SET_WS_FRAME_PAYLOAD_LENGTH(ret, 126);
            ret.resize(4);
            uint16_t size_16 = data.size();
#if BYTE_ORDER == BIG_ENDIAN
            memcpy(ret.data() + 2, &size_16, 2);
#else
            reverse_memcpy(ret.data() + 2, &size_16, 2);
#endif
        } else {
            PW_SET_WS_FRAME_PAYLOAD_LENGTH(ret, 127);
            ret.resize(10);
            uint64_t size_64 = data.size();
#if BYTE_ORDER == BIG_ENDIAN
            memcpy(ret.data() + 2, &size_64, 8);
#else
            reverse_memcpy(ret.data() + 2, &size_64, 8);
#endif
        }

        if (masking_key) {
            PW_SET_WS_FRAME_MASKED(ret);
            size_t end = ret.size();
            ret.resize(end + 4 + data.size());
            memcpy(&ret[end], masking_key, 4);

            size_t i = 0;
#ifdef POLYWEB_SIMD
            int32_t masking_key_integer;
            memcpy(&masking_key_integer, masking_key, 4);
            for (__m256i mask_vec = _mm256_set1_epi32(masking_key_integer); i + 32 <= data.size(); i += 32) {
                __m256i src_vec = _mm256_loadu_si256((const __m256i_u*) &data[i]);
                __m256i masked_vec = _mm256_xor_si256(src_vec, mask_vec);
                _mm256_storeu_si256((__m256i_u*) &ret[end + 4 + i], masked_vec);
            }
            for (__m128i mask_vec = _mm_set1_epi32(masking_key_integer); i + 16 <= data.size(); i += 16) {
                __m128i src_vec = _mm_loadu_si128((const __m128i_u*) &data[i]);
                __m128i masked_vec = _mm_xor_si128(src_vec, mask_vec);
                _mm_storeu_si128((__m128i_u*) &ret[end + 4 + i], masked_vec);
            }
#endif
            for (; i < data.size(); ++i) {
                ret[end + 4 + i] = data[i] ^ masking_key[i % 4];
            }
        } else {
            PW_CLEAR_WS_FRAME_MASKED(ret);
            ret.insert(ret.end(), data.begin(), data.end());
        }

        return ret;
    }

    int WSMessage::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, long frame_rlimit, long message_rlimit) {
        for (bool fin = false; !fin;) {
            char frame_header[2];
            {
                if (long result = buf_receiver.recvall(conn, frame_header, 2); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 2) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }
            }

            fin = PW_GET_WS_FRAME_FIN(frame_header);
            if (PW_GET_WS_FRAME_OPCODE(frame_header) != 0) opcode = PW_GET_WS_FRAME_OPCODE(frame_header);
            bool masked = PW_GET_WS_FRAME_MASKED(frame_header);

            unsigned long long payload_length;
            uint8_t payload_length_7 = PW_GET_WS_FRAME_PAYLOAD_LENGTH(frame_header);
            if (payload_length_7 == 126) {
                uint16_t payload_length_16;
                if (long result = buf_receiver.recvall(conn, &payload_length_16, 2); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 2) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }
                payload_length = ntohs(payload_length_16);
            } else if (payload_length_7 == 127) {
                uint64_t payload_length_64;
                if (long result = buf_receiver.recvall(conn, &payload_length_64, 8); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 8) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }
                payload_length = ntohll(payload_length_64);
            } else {
                payload_length = payload_length_7;
            }

            char masking_key[4];
            if (masked) {
                if (long result = buf_receiver.recvall(conn, &masking_key, 4); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 4) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }
            }

            if (payload_length) {
                size_t end = data.size();

                if (payload_length > (unsigned long long) frame_rlimit || end + payload_length > (unsigned long long) message_rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else {
                    data.resize(end + payload_length);
                    if (long result = buf_receiver.recvall(conn, &data[end], payload_length); result == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    } else if ((unsigned long long) result != payload_length) {
                        detail::set_last_error(PW_EWEB);
                        data.resize(end + result);
                        return PN_ERROR;
                    }
                }

                if (masked) {
                    size_t i = 0;
#ifdef POLYWEB_SIMD
                    int32_t masking_key_integer;
                    memcpy(&masking_key_integer, masking_key, 4);
                    for (__m256i mask_vec = _mm256_set1_epi32(masking_key_integer); i + 32 <= payload_length; i += 32) {
                        __m256i src_vec = _mm256_loadu_si256((const __m256i_u*) &data[end + i]);
                        __m256i masked_vec = _mm256_xor_si256(src_vec, mask_vec);
                        _mm256_storeu_si256((__m256i_u*) &data[end + i], masked_vec);
                    }
                    for (__m128i mask_vec = _mm_set1_epi32(masking_key_integer); i + 16 <= payload_length; i += 16) {
                        __m128i src_vec = _mm_loadu_si128((const __m128i_u*) &data[end + i]);
                        __m128i masked_vec = _mm_xor_si128(src_vec, mask_vec);
                        _mm_storeu_si128((__m128i_u*) &data[end + i], masked_vec);
                    }
#endif
                    for (; i < payload_length; ++i) {
                        data[end + i] ^= masking_key[i % 4];
                    }
                }
            }
        }
        return PN_OK;
    }

    template <typename Base>
    int BasicWebSocketClient<Base>::ws_connect(pn::StringView hostname, unsigned short port, std::string target, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers, unsigned int header_climit, long header_name_rlimit, long header_value_rlimit, long body_chunk_rlimit, long body_rlimit, long misc_rlimit) {
        HTTPRequest req("GET", std::move(target), std::move(query_parameters), std::move(headers));

        if (!req.headers.count("User-Agent")) {
            req.headers["User-Agent"] = PW_SERVER_CLIENT_NAME;
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

        if (resp.parse(*this, buf_receiver, header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (resp.status_code != 101) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        return PN_OK;
    }

    template <typename Base>
    int BasicWebSocketClient<Base>::ws_connect(pn::StringView hostname, unsigned short port, std::string target, QueryParameters query_parameters, HTTPHeaders headers, unsigned int header_climit, long header_name_rlimit, long header_value_rlimit, long body_chunk_rlimit, long body_rlimit, long misc_rlimit) {
        HTTPResponse resp;
        return ws_connect(hostname, port, std::move(target), resp, std::move(query_parameters), std::move(headers), header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit);
    }

    template <typename Base>
    int BasicWebSocketClient<Base>::ws_connect(pn::StringView url, HTTPResponse& resp, HTTPHeaders headers, unsigned int header_climit, long header_name_rlimit, long header_value_rlimit, long body_chunk_rlimit, long body_rlimit, long misc_rlimit) {
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
    int BasicWebSocketClient<Base>::ws_connect(pn::StringView url, HTTPHeaders headers, unsigned int header_climit, long header_name_rlimit, long header_value_rlimit, long body_chunk_rlimit, long body_rlimit, long misc_rlimit) {
        HTTPResponse resp;
        return ws_connect(url, resp, std::move(headers), header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit);
    }

    template <typename Base>
    int BasicWebSocketClient<Base>::recv(WSMessage& message, bool handle_pings, long frame_rlimit, long message_rlimit) {
        for (int i = 0;;) {
            if (message.parse(*this, buf_receiver, frame_rlimit, message_rlimit) == PN_ERROR) {
                return this->ws_closed ? i : PN_ERROR;
            }

            if (message.opcode == 0x8) {
                if (on_close) {
                    if (this->ws_closed) {
                        on_close(*this, 0, {}, true, this->data);
                    } else {
                        uint16_t status_code = 0;
                        std::string reason;

                        if (message->size() >= 2) {
#if BYTE_ORDER == BIG_ENDIAN
                            memcpy(&status_code, message->data(), 2);
#else
                            reverse_memcpy(&status_code, message->data(), 2);
#endif
                        }
                        if (message->size() > 2) {
                            reason.assign(message->begin() + 2, message->end());
                        }

                        on_close(*this, status_code, reason, true, this->data);
                        if (send(WSMessage(std::move(message.data), 0x8)) == PN_ERROR) {
                            return PN_ERROR;
                        }
                    }
                }

                return i;
            } else if (handle_pings && message.opcode == 0x9) {
                if (send(WSMessage(std::move(message.data), 0xA)) == PN_ERROR) {
                    return this->ws_closed ? i : PN_ERROR;
                }
                continue;
            }

            return ++i;
        }
    }

    int make_websocket_client(SecureWebSocketClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        if (client.connect(hostname, port) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }

        if (config.configure_sockopts(client) == PN_ERROR) {
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

    int make_websocket_client(SecureWebSocketClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_websocket_client(client, hostname, port, secure, std::move(target), resp, std::move(query_parameters), std::move(headers), config);
    }

    int make_websocket_client(SecureWebSocketClient& client, pn::StringView url, HTTPResponse& resp, HTTPHeaders headers, const ClientConfig& config) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        if (!url_info.credentials.empty() && !headers.count("WWW-Authenticate")) {
            headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return make_websocket_client(client, url_info.hostname(), url_info.port(), url_info.scheme == "wss", std::move(url_info.path), resp, std::move(url_info.query_parameters), std::move(headers), config);
    }

    int make_websocket_client(SecureWebSocketClient& client, pn::StringView url, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_websocket_client(client, url, resp, std::move(headers), config);
    }

    int make_proxied_websocket_client(SecureWebSocketClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, HTTPResponse& resp, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
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

        client.buf_receiver.size = 0;
        if (client.connect(proxy_url_info.hostname(), proxy_url_info.port()) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }

        if (config.configure_sockopts(client) == PN_ERROR) {
            return PN_ERROR;
        }

        if (client.send(connect_req) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPResponse connect_resp;
        if (connect_resp.parse(client, client.buf_receiver, false, config.header_climit, config.header_name_rlimit, config.header_value_rlimit, config.body_chunk_rlimit, config.body_rlimit, config.misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        } else if (connect_resp.status_code_category() != 200) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }
        client.buf_receiver.size = config.recv_buf_size;

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

    int make_proxied_websocket_client(SecureWebSocketClient& client, pn::StringView hostname, unsigned short port, bool secure, std::string target, pn::StringView proxy_url, QueryParameters query_parameters, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_proxied_websocket_client(client, hostname, port, secure, std::move(target), proxy_url, resp, std::move(query_parameters), std::move(headers), config);
    }

    int make_proxied_websocket_client(SecureWebSocketClient& client, pn::StringView url, pn::StringView proxy_url, HTTPResponse& resp, HTTPHeaders headers, const ClientConfig& config) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        if (!url_info.credentials.empty() && !headers.count("WWW-Authenticate")) {
            headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return make_proxied_websocket_client(client, url_info.hostname(), url_info.port(), url_info.scheme == "wss", std::move(url_info.path), proxy_url, resp, std::move(url_info.query_parameters), std::move(headers), config);
    }

    int make_proxied_websocket_client(SecureWebSocketClient& client, pn::StringView url, pn::StringView proxy_url, HTTPHeaders headers, const ClientConfig& config) {
        HTTPResponse resp;
        return make_proxied_websocket_client(client, url, proxy_url, resp, std::move(headers), config);
    }

    template class BasicWebSocketClient<pn::tcp::Client>;
    template class BasicWebSocketClient<pn::tcp::SecureClient>;
} // namespace pw
