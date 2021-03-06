#include "polyweb.hpp"
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <cmath>
#include <openssl/sha.h>
#include <sstream>
#include <string.h>
#include <x86intrin.h>

namespace pw {
    namespace detail {
        tp::ThreadPool pool(std::thread::hardware_concurrency() * 3);
        thread_local int last_error = PW_ESUCCESS;

        void reverse_memcpy(char* dest, char* src, size_t len) {
            __builtin_prefetch(src, 0, 1);
            size_t i = 0;
            for (; i + 32 <= len; i += 32) {
                __m256i src_vec = _mm256_loadu_si256((__m256i_u*) (src + len - i - 1));
                __m256i reversed_vec = _mm256_shuffle_epi8(src_vec, _mm256_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31));
                _mm256_storeu_si256(((__m256i_u*) dest) + i, reversed_vec);
            }
            for (; i + 16 <= len; i += 16) {
                __m128i src_vec = _mm_loadu_si128((__m128i_u*) (src + len - i - 1));
                __m128i reversed_vec = _mm_shuffle_epi8(src_vec, _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15));
                _mm_storeu_si128(((__m128i_u*) dest) + i, reversed_vec);
            }
            for (; i < len; i++) {
                dest[i] = src[len - i - 1];
            }
        }
    } // namespace detail

    const char* strerror(int error) {
        static const char* error_strings[] = {
            "Success",       // PW_ESUCCESS
            "Network error", // PW_ENET
            "Web error",     // PW_EWEB
        };

        if (error >= 0 && error < 3) {
            return error_strings[error];
        } else {
            return "Unknown error";
        }
    }

    std::string universal_strerror(int error) {
        std::string base_error = strerror(error);
        std::string specific_error;

        switch (error) {
            case PW_ENET: {
                specific_error = pn::universal_strerror();
                break;
            }

            default: {
                return base_error;
            }
        }

        return base_error + ": " + specific_error;
    }

    std::vector<char> b64_decode(const std::string& str) {
        using namespace boost::archive::iterators;
        using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
        return boost::algorithm::trim_right_copy_if(std::vector<char>(It(std::begin(str)), It(std::end(str))), [](char c) {
            return c == '\0';
        });
    }

    std::string b64_encode(const std::vector<char>& data) {
        using namespace boost::archive::iterators;
        using It = base64_from_binary<transform_width<std::vector<char>::const_iterator, 6, 8>>;
        auto ret = std::string(It(std::begin(data)), It(std::end(data)));
        return ret.append((3 - data.size() % 3) % 3, '=');
    }

    std::string percent_encode(const std::string& str, bool plus_as_space, bool allow_slash) {
        std::string ret;
        ret.reserve(str.size());
        for (const char c : str) {
            const static char* allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
            if (plus_as_space && c == ' ') {
                ret.push_back('+');
            } else if (allow_slash && c == '/') {
                ret.push_back('/');
            } else if (c == '\0' || strchr(allowed_characters, c) == NULL) {
                std::stringstream ss;
                ss << std::hex << +c;
                ret.push_back('%');
                ret += boost::to_upper_copy(ss.str());
            } else {
                ret.push_back(c);
            }
        }
        return ret;
    }

    std::string percent_decode(const std::string& str, bool plus_as_space) {
        std::string ret;
        ret.reserve(str.size());

        uint8_t reading_percent = 0;
        char current_character;
        for (const char c : str) {
            if (!reading_percent) {
                if (c == '%') {
                    reading_percent = 2;
                    current_character = 0;
                } else if (plus_as_space && c == '+') {
                    ret.push_back(' ');
                } else {
                    ret.push_back(c);
                }
            } else {
                unsigned char nibble;
                if (c >= '0' && c <= '9') {
                    nibble = c - '0';
                } else {
                    nibble = toupper(c) - 55;
                }

                if (reading_percent == 2) {
                    current_character |= nibble << 4;
                } else if (reading_percent == 1) {
                    current_character |= nibble;
                }

                if (--reading_percent == 0) {
                    ret.push_back(current_character);
                }
            }
        }

        return ret;
    }

    std::vector<char> HTTPRequest::build(void) const {
        std::vector<char> ret;

        ret.insert(ret.end(), this->method.begin(), this->method.end());
        ret.push_back(' ');

        std::string encoded_target = percent_encode(this->target);
        ret.insert(ret.end(), encoded_target.begin(), encoded_target.end());
        if (!query_parameters.empty()) {
            ret.push_back('?');
            bool first = true;
            for (auto it = query_parameters.begin(); it != query_parameters.end(); it++) {
                if (!first) ret.push_back('&');
                std::string encoded_key = percent_encode(it->first, false, false);
                std::string encoded_value = percent_encode(it->second, false, false);
                ret.insert(ret.end(), encoded_key.begin(), encoded_key.end());
                ret.push_back('=');
                ret.insert(ret.end(), encoded_value.begin(), encoded_value.end());
                first = false;
            }
        }
        ret.push_back(' ');

        ret.insert(ret.end(), this->http_version.begin(), this->http_version.end());
        ret.insert(ret.end(), {'\r', '\n'});

        for (const auto& header : this->headers) {
            ret.insert(ret.end(), header.first.begin(), header.first.end());
            ret.insert(ret.end(), {':', ' '});
            ret.insert(ret.end(), header.second.begin(), header.second.end());
            ret.insert(ret.end(), {'\r', '\n'});
        }

        if (!this->body.empty()) {
            if (!headers.count("Content-Length")) {
                std::string header = "Content-Length: " + std::to_string(this->body.size()) + "\r\n";
                ret.insert(ret.end(), header.begin(), header.end());
            }

            ret.insert(ret.end(), {'\r', '\n'});
            ret.insert(ret.end(), this->body.begin(), this->body.end());
        } else {
            ret.insert(ret.end(), {'\r', '\n'});
        }

        return ret;
    }

    int HTTPRequest::parse(pn::tcp::Connection& conn) {
        method.clear();
        if (detail::read_until(conn, std::back_inserter(method), " ") == PW_ERROR) {
            return PW_ERROR;
        }
        if (method.empty()) {
            detail::set_last_error(PW_EWEB);
            return PW_ERROR;
        }

        target.clear();
        if (detail::read_until(conn, std::back_inserter(target), " ") == PW_ERROR) {
            return PW_ERROR;
        }
        if (target.empty()) {
            detail::set_last_error(PW_EWEB);
            return PW_ERROR;
        }

        http_version.clear();
        if (detail::read_until(conn, std::back_inserter(http_version), "\r\n") == PW_ERROR) {
            return PW_ERROR;
        }
        if (http_version.empty()) {
            detail::set_last_error(PW_EWEB);
            return PW_ERROR;
        }

        for (;;) {
            std::string header_name;
            if (detail::read_until(conn, std::back_inserter(header_name), ": ") == PW_ERROR) {
                return PW_ERROR;
            }
            if (header_name.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }

            std::string header_value;
            if (detail::read_until(conn, std::back_inserter(header_value), "\r\n") == PW_ERROR) {
                return PW_ERROR;
            }
            boost::trim_left(header_value);
            if (header_value.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }

            this->headers[std::move(header_name)] = std::move(header_value);

            char end_check_buf[2];
            ssize_t read_result;
#ifdef _WIN32
            for (;;) {
                if ((read_result = stream.recv(end_check_buf, sizeof(end_check_buf), MSG_PEEK)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
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
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
#endif

            if (memcmp("\r\n", end_check_buf, sizeof(end_check_buf)) == 0) {
                if ((read_result = conn.recv(end_check_buf, sizeof(end_check_buf), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                }

                break;
            }
        }

        HTTPHeaders::const_iterator content_length_it;
        if ((content_length_it = headers.find("Content-Length")) != headers.end()) {
            this->body.resize(std::stoi(content_length_it->second));

            ssize_t read_result;
            if ((read_result = conn.recv(body.data(), body.size(), MSG_WAITALL)) == 0) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            } else if (read_result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
        }

        size_t query_string_begin;
        if ((query_string_begin = target.find('?')) != std::string::npos) {
            if (query_string_begin != target.size() - 1) {
                std::string query_string(target.begin() + query_string_begin + 1, target.end());

                std::vector<std::string> split_query_string;
                boost::split(split_query_string, query_string, boost::is_any_of("&"));

                for (const auto& parameter : split_query_string) {
                    std::vector<std::string> split_parameter;
                    boost::split(split_parameter, parameter, boost::is_any_of("="));
                    if (split_parameter.size() > 1) {
                        query_parameters[percent_decode(split_parameter[0], true)] = percent_decode(split_parameter[1], true);
                    }
                }
            }
            target.resize(query_string_begin);
        }
        target = percent_decode(target);

        return PW_OK;
    }

    std::vector<char> HTTPResponse::build(void) const {
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

        if (!headers.count("Content-Length")) {
            std::string header = "Content-Length: " + std::to_string(this->body.size()) + "\r\n";
            ret.insert(ret.end(), header.begin(), header.end());
        }
        ret.insert(ret.end(), {'\r', '\n'});
        ret.insert(ret.end(), this->body.begin(), this->body.end());

        return ret;
    }

    int HTTPResponse::parse(pn::tcp::Connection& conn) {
        http_version.clear();
        if (detail::read_until(conn, std::back_inserter(http_version), " ") == PW_ERROR) {
            return PW_ERROR;
        }
        if (http_version.empty()) {
            detail::set_last_error(PW_EWEB);
            return PW_ERROR;
        }

        status_code.clear();
        if (detail::read_until(conn, std::back_inserter(status_code), " ") == PW_ERROR) {
            return PW_ERROR;
        }
        if (status_code.empty()) {
            detail::set_last_error(PW_EWEB);
            return PW_ERROR;
        }

        reason_phrase.clear();
        if (detail::read_until(conn, std::back_inserter(reason_phrase), "\r\n") == PW_ERROR) {
            return PW_ERROR;
        }
        if (reason_phrase.empty()) {
            detail::set_last_error(PW_EWEB);
            return PW_ERROR;
        }

        for (;;) {
            std::string header_name;
            if (detail::read_until(conn, std::back_inserter(header_name), ": ") == PW_ERROR) {
                return PW_ERROR;
            }
            if (header_name.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }

            std::string header_value;
            if (detail::read_until(conn, std::back_inserter(header_value), "\r\n") == PW_ERROR) {
                return PW_ERROR;
            }
            boost::trim_left(header_value);
            if (header_value.empty()) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            }

            this->headers[std::move(header_name)] = std::move(header_value);

            char end_check_buf[2];
            ssize_t read_result;
#ifdef _WIN32
            for (;;) {
                if ((read_result = stream.recv(end_check_buf, sizeof(end_check_buf), MSG_PEEK)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
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
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
#endif

            if (memcmp("\r\n", end_check_buf, sizeof(end_check_buf)) == 0) {
                if ((read_result = conn.recv(end_check_buf, sizeof(end_check_buf), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (read_result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                }

                break;
            }
        }

        HTTPHeaders::const_iterator content_length_it;
        if ((content_length_it = headers.find("Content-Length")) != headers.end()) {
            this->body.resize(std::stoi(content_length_it->second));

            ssize_t read_result;
            if ((read_result = conn.recv(body.data(), body.size(), MSG_WAITALL)) == 0) {
                detail::set_last_error(PW_EWEB);
                return PW_ERROR;
            } else if (read_result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
        }

        return PW_OK;
    }

    std::vector<char> WSMessage::build(bool masked, char* masking_key) const {
        std::vector<char> ret(2);

        PW_SET_WS_FRAME_FIN(ret);
        PW_CLEAR_WS_FRAME_RSV1(ret);
        PW_CLEAR_WS_FRAME_RSV2(ret);
        PW_CLEAR_WS_FRAME_RSV3(ret);
        PW_SET_WS_FRAME_OPCODE(ret, this->opcode);

        if (data.size() < 126) {
            PW_SET_WS_FRAME_PAYLOAD_LENGTH(ret, data.size());
        } else if (data.size() <= UINT16_MAX) {
            PW_SET_WS_FRAME_PAYLOAD_LENGTH(ret, 126);
            ret.resize(4);
            union {
                char bytes[2];
                uint16_t integer;
            } size;
            size.integer = data.size();
            detail::reverse_memcpy(ret.data() + 2, size.bytes, 2);
        } else {
            PW_SET_WS_FRAME_PAYLOAD_LENGTH(ret, 127);
            ret.resize(10);
            union {
                char bytes[8];
                uint64_t integer;
            } size;
            size.integer = data.size();
            detail::reverse_memcpy(ret.data() + 2, size.bytes, 8);
        }

        if (masked) {
            PW_SET_WS_FRAME_MASKED(ret);
            size_t end = ret.size();
            ret.resize(end + 4 + data.size());

            union {
                char bytes[4];
                int integer;
            } masking_key_union;
            memcpy(masking_key_union.bytes, masking_key, 4);
            memcpy(&ret[end], masking_key, 4);

            size_t i = 0;
            for (__m256i mask_vec = _mm256_set1_epi32(masking_key_union.integer); i + 32 <= data.size(); i += 32) {
                __m256i src_vec = _mm256_loadu_si256((__m256i_u*) &data[i]);
                __m256i masked_vec = _mm256_xor_si256(src_vec, mask_vec);
                _mm256_storeu_si256((__m256i_u*) &ret[end + 4 + i], masked_vec);
            }
            for (__m128i mask_vec = _mm_set1_epi32(masking_key_union.integer); i + 16 <= data.size(); i += 16) {
                __m128i src_vec = _mm_loadu_si128((__m128i_u*) &data[i]);
                __m128i masked_vec = _mm_xor_si128(src_vec, mask_vec);
                _mm_storeu_si128((__m128i_u*) &ret[end + 4 + i], masked_vec);
            }
            for (; i < data.size(); i++) {
                ret[end + 4 + i] ^= masking_key_union.bytes[i % 4];
            }
        } else {
            PW_CLEAR_WS_FRAME_MASKED(ret);
            ret.insert(ret.end(), data.begin(), data.end());
        }

        return ret;
    }

    int Connection::recv(WSMessage& message) {
        bool fin = false;
        while (!fin) {
            char frame_header[2];
            {
                ssize_t result;
                if ((result = pn::tcp::Connection::recv(frame_header, 2, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                }
            }

            fin = PW_GET_WS_FRAME_FIN(frame_header);
            if (PW_GET_WS_FRAME_OPCODE(frame_header) != 0) message.opcode = PW_GET_WS_FRAME_OPCODE(frame_header);
            bool masked = PW_GET_WS_FRAME_MASKED(frame_header);

            union {
                char bytes[sizeof(size_t)];
                size_t integer = 0;
            } payload_length;
            uint8_t payload_length_7 = PW_GET_WS_FRAME_PAYLOAD_LENGTH(frame_header);
            if (payload_length_7 == 126) {
                char payload_length_16[2];
                ssize_t result;
                if ((result = pn::tcp::Connection::recv(payload_length_16, 2, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                }

                detail::reverse_memcpy(payload_length.bytes, payload_length_16, 2);
            } else if (payload_length_7 == 127) {
                char payload_length_64[8];
                ssize_t result;
                if ((result = pn::tcp::Connection::recv(payload_length_64, 8, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                }

                detail::reverse_memcpy((char*) &payload_length.bytes, payload_length_64, 8);
            } else {
                payload_length.integer = payload_length_7;
            }

            union {
                char bytes[4];
                int integer;
            } masking_key;
            if (masked) {
                ssize_t result;
                if ((result = pn::tcp::Connection::recv(masking_key.bytes, 4, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                }
            }

            size_t end = message.data.size();
            message.data.resize(end + payload_length.integer);
            {
                ssize_t result;
                if ((result = pn::tcp::Connection::recv(&message.data[end], payload_length.integer, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                }
            }

            if (masked) {
                size_t i = 0;
                for (__m256i mask_vec = _mm256_set1_epi32(masking_key.integer); i + 32 <= payload_length.integer; i += 32) {
                    __m256i src_vec = _mm256_loadu_si256((__m256i_u*) &message.data[end + i]);
                    __m256i masked_vec = _mm256_xor_si256(src_vec, mask_vec);
                    _mm256_storeu_si256((__m256i_u*) &message.data[end + i], masked_vec);
                }
                for (__m128i mask_vec = _mm_set1_epi32(masking_key.integer); i + 16 <= payload_length.integer; i += 16) {
                    __m128i src_vec = _mm_loadu_si128((__m128i_u*) &message.data[end + i]);
                    __m128i masked_vec = _mm_xor_si128(src_vec, mask_vec);
                    _mm_storeu_si128((__m128i_u*) &message.data[end + i], masked_vec);
                }
                for (; i < payload_length.integer; i++) {
                    message.data[end + i] ^= masking_key.bytes[i % 4];
                }
            }
        }

        return PW_OK;
    }

    int Connection::close_ws(uint16_t status_code, const std::string& reason, bool masked, char* masking_key, bool validity_check) {
        if (validity_check && !this->is_valid()) {
            this->ws_closed = true;
            return PW_OK;
        }

        WSMessage message(8);
        message.data.resize(2 + reason.size());

        union {
            char bytes[2];
            uint16_t integer;
        } status_code_union;
        status_code_union.integer = status_code;

        detail::reverse_memcpy(message.data.data(), status_code_union.bytes, 2);
        memcpy(message.data.data() + 2, reason.data(), reason.size());

        ssize_t result;
        if ((result = this->send(message, masked, masking_key)) == 0) {
            detail::set_last_error(PW_EWEB);
            return PW_ERROR;
        } else if (result == PW_ERROR) {
            return PW_ERROR;
        }

        this->ws_closed = true;
        return PW_OK;
    }

    int Server::listen(int backlog) {
        if (pn::tcp::Server::listen([](pn::tcp::Connection& conn, void* data) -> bool {
                auto server = (Server*) data;
                detail::pool.schedule([conn = std::move(conn)](void* data) {
                    auto server = (Server*) data;
                    Connection web_conn(conn.fd, conn.addr, conn.addrlen);
                    server->handle_connection(std::move(web_conn));
                },
                    server);
                return true;
            },
                backlog,
                this) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PW_ERROR;
        }
        return PW_OK;
    }

    int Server::handle_ws_connection(Connection conn, WSRoute& route) {
        route.on_open(conn);

        while (conn.is_valid()) {
            WSMessage message;
            if (conn.recv(message) == PW_ERROR) {
                route.on_close(conn, 0, {}, false);
                return PW_ERROR;
            }

            switch (message.opcode) {
                case 0x1:
                case 0x2:
                    route.on_message(conn, message);
                    break;

                case 0x8: {
                    if (conn.ws_closed) {
                        if (conn.close() == PN_ERROR) {
                            detail::set_last_error(PW_ENET);
                            return PW_ERROR;
                        }
                    } else {
                        union {
                            char bytes[2];
                            uint16_t integer;
                        } status_code_union;
                        std::string reason;

                        if (message.data.size() >= 2) {
                            detail::reverse_memcpy(status_code_union.bytes, message.data.data(), 2);
                        }
                        if (message.data.size() > 2) {
                            reason.assign(message.data.begin() + 2, message.data.end());
                        }

                        route.on_close(conn, status_code_union.integer, reason, true);

                        ssize_t result;
                        if ((result = conn.send(WSMessage(std::move(message.data), 0x8))) == 0) {
                            detail::set_last_error(PW_EWEB);
                            return PW_ERROR;
                        } else if (result == PW_ERROR) {
                            return PW_ERROR;
                        }

                        if (conn.close() == PN_ERROR) {
                            detail::set_last_error(PW_ENET);
                            return PW_ERROR;
                        }
                    }

                    return PW_OK;
                }

                case 0x9:
                    conn.send(WSMessage(std::move(message.data), 0xA));
                    break;
            }
        }

        return PW_OK;
    }

    int Server::handle_connection(Connection conn) {
        bool keep_alive, websocket = false;
        do {
            HTTPRequest req;
            if (req.parse(conn) == PW_ERROR) {
                std::string resp_status_code;
                switch (get_last_error()) {
                    case PW_ENET: {
                        resp_status_code = "500";
                        break;
                    }

                    case PW_EWEB: {
                        resp_status_code = "400";
                        break;
                    }
                }
                conn.send_basic(resp_status_code, false);
                return PW_ERROR;
            }

            HTTPHeaders::const_iterator connection_it;
            if ((connection_it = req.headers.find("Connection")) != req.headers.end()) {
                std::string connection = boost::to_lower_copy(connection_it->second);
                if (req.http_version == "HTTP/1.1") {
                    HTTPHeaders::const_iterator upgrade_it;
                    if (connection == "upgrade" && (upgrade_it = req.headers.find("Upgrade")) != req.headers.end()) {
                        if (boost::to_lower_copy(upgrade_it->second) == "websocket") {
                            websocket = true;
                        } else {
                            keep_alive = true;
                            ssize_t result;
                            if ((result = conn.send_basic("501", keep_alive, req.http_version)) == 0) {
                                detail::set_last_error(PW_EWEB);
                                return PW_ERROR;
                            } else if (result == PW_ERROR) {
                                return PW_ERROR;
                            }
                            continue;
                        }
                    } else if (connection != "close") {
                        keep_alive = true;
                    }
                } else {
                    keep_alive = connection == "keep-alive";
                }
            } else {
                keep_alive = req.http_version == "HTTP/1.1";
            }

            std::string ws_route_target;
            for (const auto& route : ws_routes) {
                if ((!req.query_parameters.empty()) != route.second.query) {
                    continue;
                }

                if (route.first == req.target) {
                    ws_route_target = route.first;
                    break;
                } else if (route.second.wildcard && boost::starts_with(req.target, route.first) && route.first.size() > ws_route_target.size()) {
                    ws_route_target = route.first;
                }
            }

            std::string http_route_target;
            for (const auto& route : routes) {
                if ((!req.query_parameters.empty()) != route.second.query) {
                    continue;
                }

                if (route.first == req.target) {
                    http_route_target = route.first;
                    break;
                } else if (route.second.wildcard && boost::starts_with(req.target, route.first) && route.first.size() > http_route_target.size()) {
                    http_route_target = route.first;
                }
            }

            if (websocket) {
                if (!ws_route_target.empty()) {
                    HTTPResponse resp;
                    try {
                        resp = ws_routes[ws_route_target].on_connect(conn, req);
                    } catch (const HTTPResponse& error_resp) {
                        resp = error_resp;
                    } catch (...) {
                        resp = HTTPResponse::create_basic("500", keep_alive, req.http_version);
                    }

                    resp.headers["Server"] = "Polyweb/net Engine";

                    if (resp.status_code == "101") {
                        resp.body.clear();
                        resp.headers["Connection"] = "Upgrade";
                        resp.headers["Upgrade"] = "websocket";

                        HTTPHeaders::const_iterator websocket_key_it;
                        if ((!resp.headers.count("Sec-WebSocket-Accept")) && (websocket_key_it = req.headers.find("Sec-WebSocket-Key")) != req.headers.end()) {
                            std::string websocket_key = boost::trim_right_copy(websocket_key_it->second);
                            websocket_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                            std::vector<char> hashed(20);
                            SHA1((const unsigned char*) websocket_key.data(), websocket_key.size(), (unsigned char*) hashed.data());
                            resp.headers["Sec-WebSocket-Accept"] = b64_encode(hashed);
                        }

                        HTTPHeaders::const_iterator websocket_version_it;
                        if ((websocket_version_it = req.headers.find("Sec-WebSocket-Version")) != req.headers.end()) {
                            std::vector<std::string> split_websocket_version;
                            boost::split(split_websocket_version, websocket_version_it->second, boost::is_any_of(","));

                            int closest_version_num = 13;
                            unsigned int closest_version_dist = UINT_MAX;
                            for (auto& version : split_websocket_version) {
                                boost::trim(version);

                                int version_num;
                                unsigned int version_dist;
                                if ((version_dist = std::abs((version_num = stoi(version)) - 13)) < closest_version_dist) {
                                    closest_version_num = version_num;
                                    closest_version_dist = version_dist;

                                    if (version_dist == 0) {
                                        break;
                                    }
                                }
                            }

                            resp.headers["Sec-WebSocket-Version"] = std::to_string(closest_version_num);
                        }

                        HTTPHeaders::const_iterator websocket_protocol_it;
                        if ((!resp.headers.count("Sec-WebSocket-Protocol")) && (websocket_protocol_it = req.headers.find("Sec-WebSocket-Protocol")) != req.headers.end()) {
                            std::vector<std::string> split_websocket_protocol;
                            boost::split(split_websocket_protocol, websocket_protocol_it->second, boost::is_any_of(","));
                            resp.headers["Sec-WebSocket-Protocol"] = boost::trim_copy(split_websocket_protocol.back());
                        }
                    } else {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    ssize_t result;
                    if ((result = conn.send(resp)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (result == PW_ERROR) {
                        return PW_ERROR;
                    }

                    if (resp.status_code == "101") {
                        return handle_ws_connection(std::move(conn), ws_routes[ws_route_target]);
                    }
                } else {
                    ssize_t result;
                    if ((result = conn.send_basic("404", keep_alive, req.http_version)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (result == PW_ERROR) {
                        return PW_ERROR;
                    }
                }
            } else if (!ws_route_target.empty() && http_route_target.empty()) {
                ssize_t result;
                if ((result = conn.send_basic("426", keep_alive, req.http_version, {{"Upgrade", "websocket"}})) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                } else if (result == PW_ERROR) {
                    return PW_ERROR;
                }
            } else {
                if (!http_route_target.empty()) {
                    HTTPResponse resp;
                    try {
                        resp = routes[http_route_target].cb(conn, req);
                    } catch (const HTTPResponse& error_resp) {
                        resp = error_resp;
                    } catch (...) {
                        resp = HTTPResponse::create_basic("500", keep_alive, req.http_version);
                    }

                    resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    resp.headers["Server"] = "Polyweb/net Engine";

                    ssize_t result;
                    if ((result = conn.send(resp)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (result == PW_ERROR) {
                        return PW_ERROR;
                    }
                } else {
                    ssize_t result;
                    if ((result = conn.send_basic("404", keep_alive, req.http_version)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PW_ERROR;
                    } else if (result == PW_ERROR) {
                        return PW_ERROR;
                    }
                }
            }
        } while (conn.is_valid() && keep_alive);
        return PW_OK;
    }
} // namespace pw
