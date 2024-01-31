#include "polyweb.hpp"
#include <cstring>
#include <utility>
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
                ret[end + 4 + i] ^= masking_key[i % 4];
            }
        } else {
            PW_CLEAR_WS_FRAME_MASKED(ret);
            ret.insert(ret.end(), data.begin(), data.end());
        }

        return ret;
    }

    int WSMessage::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, size_t frame_rlimit, size_t message_rlimit) {
        bool fin = false;
        while (!fin) {
            char frame_header[2];
            {
                long result;
                if ((result = buf_receiver.recvall(conn, frame_header, 2)) == PN_ERROR) {
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
                long result;
                if ((result = buf_receiver.recvall(conn, &payload_length_16, 2)) == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 2) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }
                payload_length = ntohs(payload_length_16);
            } else if (payload_length_7 == 127) {
                uint64_t payload_length_64;
                long result;
                if ((result = buf_receiver.recvall(conn, &payload_length_64, 8)) == PN_ERROR) {
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
                long result;
                if ((result = buf_receiver.recvall(conn, &masking_key, 4)) == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result != 4) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }
            }

            if (payload_length) {
                size_t end = data.size();

                if (payload_length > frame_rlimit || end + payload_length > message_rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else {
                    data.resize(end + payload_length);
                    long result;
                    if ((result = buf_receiver.recvall(conn, &data[end], payload_length)) == PN_ERROR) {
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
    int BasicConnection<Base>::close_ws(uint16_t status_code, const std::string& reason, const char* masking_key, bool validity_check) {
        if (validity_check && !this->is_valid()) {
            ws_closed = true;
            return PN_OK;
        }

        WSMessage message(8);
        message.data.resize(2 + reason.size());

#if BYTE_ORDER == BIG_ENDIAN
        memcpy(message.data.data(), &status_code, 2);
#else
        reverse_memcpy(message.data.data(), &status_code, 2);
#endif
        memcpy(message.data.data() + 2, reason.data(), reason.size());

        if (send(message, masking_key) == PN_ERROR) {
            return PN_ERROR;
        }

        ws_closed = true;
        return PN_OK;
    }

    template <typename Base>
    int BasicServer<Base>::handle_ws_connection(pn::UniqueSocket<connection_type> conn, pn::tcp::BufReceiver& buf_receiver, ws_route_type& route) {
        route.on_open(*conn, route.data);
        for (;;) {
            if (!conn) {
                route.on_close(*conn, 0, {}, false, route.data);
                break;
            }

            WSMessage message;
            if (message.parse(*conn, buf_receiver, ws_frame_rlimit, ws_message_rlimit) == PN_ERROR) {
                route.on_close(*conn, 0, {}, false, route.data);
                return PN_ERROR;
            }

            switch (message.opcode) {
            case 0x1:
            case 0x2:
            case 0xA:
                route.on_message(*conn, std::move(message), route.data);
                break;

            case 0x8:
                if (conn->ws_closed) {
                    route.on_close(*conn, 0, {}, true, route.data);
                    if (conn->close() == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    }
                } else {
                    uint16_t status_code = 0;
                    std::string reason;

                    if (message.data.size() >= 2) {
#if BYTE_ORDER__ == BIG_ENDIAN
                        memcpy(&status_code, message.data.data(), 2);
#else
                        reverse_memcpy(&status_code, message.data.data(), 2);
#endif
                    }
                    if (message.data.size() > 2) {
                        reason.assign(message.data.begin() + 2, message.data.end());
                    }

                    route.on_close(*conn, status_code, reason, true, route.data);
                    if (conn->send(WSMessage(std::move(message.data), 0x8)) == PN_ERROR) {
                        return PN_ERROR;
                    }

                    if (conn->close() == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    }
                }
                return PN_OK;

            case 0x9:
                if (conn->send(WSMessage(std::move(message.data), 0xA)) == PN_ERROR) {
                    route.on_close(*conn, 0, {}, false, route.data);
                    return PN_ERROR;
                }
                break;
            }
        }
        return PN_OK;
    }

    template class BasicConnection<pn::tcp::Connection>;
    template class BasicConnection<pn::tcp::SecureConnection>;

    template class BasicConnection<pn::tcp::Client>;
    template class BasicConnection<pn::tcp::SecureClient>;

    template class BasicServer<pn::tcp::Server>;
    template class BasicServer<pn::tcp::SecureServer>;
} // namespace pw
