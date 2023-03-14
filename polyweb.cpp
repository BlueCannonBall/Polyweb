#include "polyweb.hpp"
#include <algorithm>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <cmath>
#include <cstring>
#include <iomanip>
#include <openssl/sha.h>
#include <random>
#include <sstream>
#include <stdexcept>
#if __has_include(<endian.h>)
    #include <endian.h>
#elif __has_include(<machine/endian.h>)
    #include <machine/endian.h>
#endif
#ifdef POLYWEB_SIMD
    #include <x86intrin.h>
#endif

namespace pw {
    // f(x) = 2 * log2(x) + x + 4
    tp::ThreadPool threadpool(roundf(2.f * log2f(std::thread::hardware_concurrency()) + std::thread::hardware_concurrency() + 4.f));
    namespace detail {
        thread_local int last_error = PW_ESUCCESS;

        void reverse_memcpy(char* dest, const char* src, size_t len) {
            size_t i = 0;
#ifdef POLYWEB_SIMD
            for (const static __m128i pattern_vec = _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15); i + 16 <= len; i += 16) {
                __m128i src_vec = _mm_loadu_si128((const __m128i_u*) (src + len - 1 - i));
                __m128i reversed_vec = _mm_shuffle_epi8(src_vec, pattern_vec);
                _mm_storeu_si128(((__m128i_u*) &dest[i]), reversed_vec);
            }
#endif
            for (; i < len; i++) {
                dest[i] = src[len - 1 - i];
            }
        }
    } // namespace detail

    void reverse_memcpy(void* dest, const void* src, size_t len) {
        detail::reverse_memcpy((char*) dest, (const char*) src, len);
    }

    std::string strerror(int error) {
        static const std::string error_strings[] = {
            "Success",       // PW_ESUCCESS
            "Network error", // PW_ENET
            "Web error",     // PW_EWEB
        };

        if (error >= 0 && error <= 2) {
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

    std::string build_date(time_t rawtime) {
#ifdef _WIN32
        struct tm timeinfo = *gmtime(&rawtime);
#else
        struct tm timeinfo;
        gmtime_r(&rawtime, &timeinfo);
#endif
        std::ostringstream ss;
        ss.imbue(std::locale(setlocale(LC_ALL, "C")));
        ss << std::put_time(&timeinfo, "%a, %d %b %Y %H:%M:%S GMT");
        return ss.str();
    }

    time_t parse_date(const std::string& date) {
        struct tm timeinfo = {0};
        std::istringstream ss(date);
        ss.imbue(std::locale(setlocale(LC_ALL, "C")));
        ss >> std::get_time(&timeinfo, "%a, %d %b %Y %H:%M:%S GMT");
        return timegm(&timeinfo);
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
        for (char c : str) {
            const static char* allowed_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
            if (plus_as_space && c == ' ') {
                ret.push_back('+');
            } else if (allow_slash && c == '/') {
                ret.push_back('/');
            } else if (c == '\0' || strchr(allowed_characters, c) == nullptr) {
                std::ostringstream ss;
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
        for (char c : str) {
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

    std::string QueryParameters::build() const {
        std::string ret;
        bool first = true;
        for (auto it = map.begin(); it != map.end(); it++) {
            if (!first) ret.push_back('&');
            std::string encoded_key = percent_encode(it->first, false, false);
            std::string encoded_value = percent_encode(it->second, false, false);
            ret.insert(ret.end(), encoded_key.begin(), encoded_key.end());
            ret.push_back('=');
            ret.insert(ret.end(), encoded_value.begin(), encoded_value.end());
            first = false;
        }
        return ret;
    }

    void QueryParameters::parse(const std::string& query_string) {
        std::vector<std::string> split_query_string;
        boost::split(split_query_string, query_string, boost::is_any_of("&"));

        for (const auto& parameter : split_query_string) {
            std::vector<std::string> split_parameter;
            boost::split(split_parameter, parameter, boost::is_any_of("="));
            if (split_parameter.size() > 1) {
                map[percent_decode(split_parameter[0], true)] = percent_decode(split_parameter[1], true);
            } else if (!split_parameter[0].empty()) {
                map[percent_decode(split_parameter[0], true)]; // Create key with empty value
            }
        }
    }

    std::vector<char> HTTPRequest::build() const {
        std::vector<char> ret;

        ret.insert(ret.end(), this->method.begin(), this->method.end());
        ret.push_back(' ');

        std::string encoded_target = percent_encode(this->target);
        ret.insert(ret.end(), encoded_target.begin(), encoded_target.end());
        if (!query_parameters->empty()) {
            ret.push_back('?');
            std::string query_string = query_parameters.build();
            ret.insert(ret.end(), query_string.begin(), query_string.end());
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

        if (!headers.count("Content-Length")) {
            std::string header = "Content-Length: " + std::to_string(this->body.size()) + "\r\n";
            ret.insert(ret.end(), header.begin(), header.end());
        }
        ret.insert(ret.end(), {'\r', '\n'});
        ret.insert(ret.end(), this->body.begin(), this->body.end());

        return ret;
    }

    int HTTPRequest::parse(pn::tcp::Connection& conn, size_t header_climit, size_t header_name_rlimit, size_t header_value_rlimit, size_t body_rlimit, size_t misc_rlimit) {
        method.clear();
        if (detail::read_until(conn, std::back_inserter(method), ' ', misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (method.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        target.clear();
        if (detail::read_until(conn, std::back_inserter(target), ' ', misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (target.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        http_version.clear();
        if (detail::read_until(conn, std::back_inserter(http_version), "\r\n", misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (http_version.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        for (size_t i = 0;; i++) {
            if (i > header_climit) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            std::string header_name;
            if (detail::read_until(conn, std::back_inserter(header_name), ':', header_name_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }

            if (header_name.empty()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            std::string header_value;
            if (detail::read_until(conn, std::back_inserter(header_value), "\r\n", header_value_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }
            boost::trim(header_value);
            if (header_value.empty()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            this->headers[std::move(header_name)] = std::move(header_value);

            char end_check_buf[2];
            ssize_t result;
#ifdef _WIN32
            for (;;) {
                if ((result = conn.recv(end_check_buf, 2, MSG_PEEK)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result == 2) {
                    break;
                }
            }
#else
            if ((result = conn.recv(end_check_buf, 2, MSG_PEEK | MSG_WAITALL)) == 0) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            } else if (result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
#endif

            if (memcmp("\r\n", end_check_buf, 2) == 0) {
                if ((result = conn.recv(end_check_buf, 2, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                }
                break;
            }
        }

        HTTPHeaders::const_iterator content_length_it;
        if ((content_length_it = headers.find("Content-Length")) != headers.end()) {
            unsigned long long content_length;
            try {
                content_length = std::stoull(content_length_it->second);
            } catch (...) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            if (content_length) {
                if (content_length > body_rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else {
                    this->body.resize(content_length);
                }

                ssize_t result;
                if ((result = conn.recv(body.data(), body.size(), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                }
            }
        }

        std::string::iterator query_string_begin;
        if ((query_string_begin = std::find(target.begin(), target.end(), '?')) != target.end()) {
            if (std::next(query_string_begin) != target.end()) {
                query_parameters.parse(std::string(std::next(query_string_begin), target.end()));
            }
            target.resize(std::distance(target.begin(), query_string_begin));
        }
        target = percent_decode(target);

        return PN_OK;
    }

    std::vector<char> HTTPResponse::build() const {
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

        if (!headers.count("Date")) {
            std::string header = "Date: " + build_date() + "\r\n";
            ret.insert(ret.end(), header.begin(), header.end());
        }

        if (!headers.count("Content-Length")) {
            std::string header = "Content-Length: " + std::to_string(this->body.size()) + "\r\n";
            ret.insert(ret.end(), header.begin(), header.end());
        }
        ret.insert(ret.end(), {'\r', '\n'});
        ret.insert(ret.end(), this->body.begin(), this->body.end());

        return ret;
    }

    int HTTPResponse::parse(pn::tcp::Connection& conn, size_t header_climit, size_t header_name_rlimit, size_t header_value_rlimit, size_t body_chunk_rlimit, size_t body_rlimit, size_t misc_rlimit) {
        http_version.clear();
        if (detail::read_until(conn, std::back_inserter(http_version), ' ', misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (http_version.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        status_code.clear();
        if (detail::read_until(conn, std::back_inserter(status_code), ' ', misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (status_code.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        reason_phrase.clear();
        if (detail::read_until(conn, std::back_inserter(reason_phrase), "\r\n", misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (reason_phrase.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        for (size_t i = 0;; i++) {
            if (i > header_climit) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            std::string header_name;
            if (detail::read_until(conn, std::back_inserter(header_name), ':', header_name_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }
            if (header_name.empty()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            std::string header_value;
            if (detail::read_until(conn, std::back_inserter(header_value), "\r\n", header_value_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }
            boost::trim(header_value);
            if (header_value.empty()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            this->headers[std::move(header_name)] = std::move(header_value);

            char end_check_buf[2];
            ssize_t result;
#ifdef _WIN32
            for (;;) {
                if ((result = conn.recv(end_check_buf, 2, MSG_PEEK)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if (result == 2) {
                    break;
                }
            }
#else
            if ((result = conn.recv(end_check_buf, 2, MSG_PEEK | MSG_WAITALL)) == 0) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            } else if (result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
#endif

            if (memcmp("\r\n", end_check_buf, 2) == 0) {
                if ((result = conn.recv(end_check_buf, 2, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                }
                break;
            }
        }

        HTTPHeaders::const_iterator transfer_encoding_it;
        HTTPHeaders::const_iterator content_length_it;
        if ((transfer_encoding_it = headers.find("Transfer-Encoding")) != headers.end()) {
            if (boost::to_lower_copy(transfer_encoding_it->second) == "chunked") {
                for (;;) {
                    std::string chunk_size_string;
                    if (detail::read_until(conn, std::back_inserter(chunk_size_string), "\r\n", body_chunk_rlimit) == PN_ERROR) {
                        return PN_ERROR;
                    }
                    if (chunk_size_string.empty()) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    }

                    unsigned long long chunk_size;
                    {
                        std::istringstream ss(chunk_size_string);
                        ss >> std::hex >> chunk_size;
                    }

                    if (!chunk_size) {
                        char end_buf[2];
                        ssize_t result;
                        if ((result = conn.recv(end_buf, 2, MSG_WAITALL)) == 0) {
                            detail::set_last_error(PW_EWEB);
                            return PN_ERROR;
                        } else if (result == PN_ERROR) {
                            detail::set_last_error(PW_ENET);
                            return PN_ERROR;
                        }
                        break;
                    }

                    size_t end = body.size();

                    if (chunk_size > body_chunk_rlimit || end + chunk_size > body_rlimit) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    } else {
                        body.resize(end + chunk_size);
                        ssize_t result;
                        if ((result = conn.recv(&body[end], chunk_size, MSG_WAITALL)) == 0) {
                            detail::set_last_error(PW_EWEB);
                            return PN_ERROR;
                        } else if (result == PN_ERROR) {
                            detail::set_last_error(PW_ENET);
                            return PN_ERROR;
                        }
                    }

                    char end_buf[2];
                    ssize_t result;
                    if ((result = conn.recv(end_buf, 2, MSG_WAITALL)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    } else if (result == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    }
                }
            } else { // Only chunked transfer encoding is supported atm
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }
        } else if ((content_length_it = headers.find("Content-Length")) != headers.end()) {
            unsigned long long content_length;
            try {
                content_length = std::stoull(content_length_it->second);
            } catch (...) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            if (content_length) {
                if (content_length > body_rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else {
                    this->body.resize(content_length);
                }

                ssize_t result;
                if ((result = conn.recv(body.data(), body.size(), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                }
            }
        }

        return PN_OK;
    }

    std::vector<char> WSMessage::build(bool masked, const char* masking_key) const {
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
            uint16_t size_16 = data.size();
#if __BYTE_ORDER == __BIG_ENDIAN
            memcpy(ret.data() + 2, &size_16, 2);
#else
            reverse_memcpy(ret.data() + 2, &size_16, 2);
#endif
        } else {
            PW_SET_WS_FRAME_PAYLOAD_LENGTH(ret, 127);
            ret.resize(10);
            uint64_t size_64 = data.size();
#if __BYTE_ORDER == __BIG_ENDIAN
            memcpy(ret.data() + 2, &size_64, 8);
#else
            reverse_memcpy(ret.data() + 2, &size_64, 8);
#endif
        }

        if (masked) {
            PW_SET_WS_FRAME_MASKED(ret);
            size_t end = ret.size();
            ret.resize(end + 4 + data.size());

            unsigned char random_bits[4];
            if (!masking_key) {
                const static std::independent_bits_engine<std::default_random_engine, 8, unsigned char> generator;
                std::generate(std::begin(random_bits), std::end(random_bits), generator);
                masking_key = (const char*) random_bits;
            }

            int32_t masking_key_integer;
            memcpy(&masking_key_integer, masking_key, 4);
            memcpy(&ret[end], masking_key, 4);

            size_t i = 0;
#ifdef POLYWEB_SIMD
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
            for (; i < data.size(); i++) {
                ret[end + 4 + i] ^= masking_key[i % 4];
            }
        } else {
            PW_CLEAR_WS_FRAME_MASKED(ret);
            ret.insert(ret.end(), data.begin(), data.end());
        }

        return ret;
    }

    int WSMessage::parse(pn::tcp::Connection& conn, size_t frame_rlimit, size_t message_rlimit) {
        bool fin = false;
        while (!fin) {
            char frame_header[2];
            {
                ssize_t result;
                if ((result = conn.recv(frame_header, 2, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                }
            }

            fin = PW_GET_WS_FRAME_FIN(frame_header);
            if (PW_GET_WS_FRAME_OPCODE(frame_header) != 0) this->opcode = PW_GET_WS_FRAME_OPCODE(frame_header);
            bool masked = PW_GET_WS_FRAME_MASKED(frame_header);

            unsigned long long payload_length;
            uint8_t payload_length_7 = PW_GET_WS_FRAME_PAYLOAD_LENGTH(frame_header);
            if (payload_length_7 == 126) {
                uint16_t payload_length_16;
                ssize_t result;
                if ((result = conn.recv(&payload_length_16, 2, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                }
                payload_length = ntohs(payload_length_16);
            } else if (payload_length_7 == 127) {
                uint64_t payload_length_64;
                ssize_t result;
                if ((result = conn.recv(&payload_length_64, 8, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                }
                payload_length = ntohll(payload_length_64);
            } else {
                payload_length = payload_length_7;
            }

            union {
                char bytes[4];
                int32_t integer;
            } masking_key;
            if (masked) {
                ssize_t result;
                if ((result = conn.recv(&masking_key, 4, MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else if (result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                }
            }

            if (payload_length) {
                size_t end = this->data.size();

                if (payload_length > frame_rlimit || end + payload_length > message_rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                } else {
                    this->data.resize(end + payload_length);
                    ssize_t result;
                    if ((result = conn.recv(&this->data[end], payload_length, MSG_WAITALL)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    } else if (result == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    }
                }

                if (masked) {
                    size_t i = 0;
#ifdef POLYWEB_SIMD
                    for (__m256i mask_vec = _mm256_set1_epi32(masking_key.integer); i + 32 <= payload_length; i += 32) {
                        __m256i src_vec = _mm256_loadu_si256((const __m256i_u*) &this->data[end + i]);
                        __m256i masked_vec = _mm256_xor_si256(src_vec, mask_vec);
                        _mm256_storeu_si256((__m256i_u*) &this->data[end + i], masked_vec);
                    }
                    for (__m128i mask_vec = _mm_set1_epi32(masking_key.integer); i + 16 <= payload_length; i += 16) {
                        __m128i src_vec = _mm_loadu_si128((const __m128i_u*) &this->data[end + i]);
                        __m128i masked_vec = _mm_xor_si128(src_vec, mask_vec);
                        _mm_storeu_si128((__m128i_u*) &this->data[end + i], masked_vec);
                    }
#endif
                    for (; i < payload_length; i++) {
                        this->data[end + i] ^= masking_key.bytes[i % 4];
                    }
                }
            }
        }
        return PN_OK;
    }

    int Connection::close_ws(uint16_t status_code, const std::string& reason, bool masked, const char* masking_key, bool validity_check) {
        if (validity_check && !this->is_valid()) {
            this->ws_closed = true;
            return PN_OK;
        }

        WSMessage message(8);
        message.data.resize(2 + reason.size());

#if __BYTE_ORDER == __BIG_ENDIAN
        memcpy(message.data.data(), &status_code, 2);
#else
        reverse_memcpy(message.data.data(), &status_code, 2);
#endif
        memcpy(message.data.data() + 2, reason.data(), reason.size());

        ssize_t result;
        if ((result = this->send(message, masked, masking_key)) == 0) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        } else if (result == PN_ERROR) {
            return PN_ERROR;
        }

        this->ws_closed = true;
        return PN_OK;
    }

    int Server::listen(std::function<bool(pn::tcp::Connection&, void*)> filter, void* filter_data, int backlog) {
        if (pn::tcp::Server::listen([filter = std::move(filter), filter_data](pn::tcp::Connection& conn, void* data) -> bool {
                if (filter(conn, filter_data)) {
                    conn.close(true, false);
                } else {
                    auto server = (Server*) data;
                    threadpool.schedule([conn](void* data) {
                        auto server = (Server*) data;
                        server->handle_connection(pn::UniqueSock<Connection>(conn));
                    },
                        server);
                }
                return true;
            },
                backlog,
                this) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        } else {
            throw std::logic_error("pn::tcp::Server::listen returned without an error");
        }
        return PN_OK;
    }

    int Server::handle_ws_connection(pn::UniqueSock<Connection> conn, WSRoute& route) {
        route.on_open(*conn);
        for (;;) {
            if (!conn) {
                route.on_close(*conn, 0, {}, false);
                break;
            }

            WSMessage message;
            if (message.parse(*conn, this->ws_frame_rlimit, this->ws_message_rlimit) == PN_ERROR) {
                route.on_close(*conn, 0, {}, false);
                return PN_ERROR;
            }

            switch (message.opcode) {
            case 0x1:
            case 0x2:
                route.on_message(*conn, std::move(message));
                break;

            case 0x8: {
                if (conn->ws_closed) {
                    route.on_close(*conn, 0, {}, true);
                    if (conn->close(true, false) == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    }
                } else {
                    uint16_t status_code = 0;
                    std::string reason;

                    if (message.data.size() >= 2) {
#if __BYTE_ORDER__ == __BIG_ENDIAN
                        memcpy(&status_code, message.data.data(), 2);
#else
                        reverse_memcpy(&status_code, message.data.data(), 2);
#endif
                    }
                    if (message.data.size() > 2) {
                        reason.assign(message.data.begin() + 2, message.data.end());
                    }

                    route.on_close(*conn, status_code, reason, true);

                    ssize_t result;
                    if ((result = conn->send(WSMessage(std::move(message.data), 0x8))) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    } else if (result == PN_ERROR) {
                        return PN_ERROR;
                    }

                    if (conn->close(true, false) == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    }
                }

                return PN_OK;
            }

            case 0x9:
                conn->send(WSMessage(std::move(message.data), 0xA));
                break;
            }
        }
        return PN_OK;
    }

    int Server::handle_connection(pn::UniqueSock<Connection> conn) {
        bool keep_alive = true, websocket = false;
        while (conn && keep_alive) {
            HTTPRequest req;
            if (req.parse(*conn, this->header_climit, this->header_name_rlimit, this->header_value_rlimit) == PN_ERROR) {
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
                handle_error(*conn, resp_status_code, false);
                return PN_ERROR;
            }

            HTTPHeaders::const_iterator connection_it;
            if ((connection_it = req.headers.find("Connection")) != req.headers.end()) {
                std::vector<std::string> split_connection;
                boost::split(split_connection, boost::to_lower_copy(connection_it->second), boost::is_any_of(","));
                for (auto& header : split_connection) {
                    boost::trim(header);
                }

                if (req.http_version == "HTTP/1.1") {
                    keep_alive = std::find(split_connection.begin(), split_connection.end(), "close") == split_connection.end();

                    HTTPHeaders::const_iterator upgrade_it;
                    if (std::find(split_connection.begin(), split_connection.end(), "upgrade") != split_connection.end() && (upgrade_it = req.headers.find("Upgrade")) != req.headers.end()) {
                        if (boost::to_lower_copy(upgrade_it->second) == "websocket") {
                            websocket = true;
                        } else {
                            if (handle_error(*conn, "501", keep_alive, req.http_version) == PN_ERROR) {
                                return PN_ERROR;
                            }
                            continue;
                        }
                    }
                } else {
                    keep_alive = std::find(split_connection.begin(), split_connection.end(), "keep-alive") != split_connection.end();
                }
            } else {
                keep_alive = req.http_version == "HTTP/1.1";
            }

            std::string ws_route_target;
            for (const auto& route : ws_routes) {
                if (route.first == req.target) {
                    ws_route_target = route.first;
                    break;
                } else if (route.second.wildcard && boost::starts_with(req.target, route.first) && route.first.size() > ws_route_target.size()) {
                    ws_route_target = route.first;
                }
            }

            std::string http_route_target;
            for (const auto& route : routes) {
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
                        resp = ws_routes[ws_route_target].on_connect(*conn, req);
                    } catch (...) {
                        if (handle_error(*conn, "500", keep_alive, req.http_version) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        continue;
                    }

                    if (!resp.headers.count("Server")) {
                        resp.headers["Server"] = PW_SERVER_NAME;
                    }

                    if (resp.status_code == "101") {
                        resp.headers.erase("Content-Type");
                        resp.body.clear();

                        if (!resp.headers.count("Connection")) {
                            resp.headers["Connection"] = "upgrade";
                        }
                        if (!resp.headers.count("Upgrade")) {
                            resp.headers["Upgrade"] = "websocket";
                        }

                        HTTPHeaders::const_iterator websocket_version_it;
                        if ((websocket_version_it = req.headers.find("Sec-WebSocket-Version")) != req.headers.end()) {
                            std::vector<std::string> split_websocket_version;
                            boost::split(split_websocket_version, websocket_version_it->second, boost::is_any_of(","));

                            bool found_version = false;
                            for (auto& version : split_websocket_version) {
                                boost::trim(version);
                                if (version == PW_WS_VERSION) {
                                    found_version = true;
                                    break;
                                }
                            }

                            if (found_version) {
                                resp.headers["Sec-WebSocket-Version"] = PW_WS_VERSION;
                            } else {
                                if (handle_error(*conn, "501", keep_alive, req.http_version) == PN_ERROR) {
                                    return PN_ERROR;
                                }
                                continue;
                            }
                        }

                        HTTPHeaders::const_iterator websocket_key_it;
                        if ((!resp.headers.count("Sec-WebSocket-Accept")) && (websocket_key_it = req.headers.find("Sec-WebSocket-Key")) != req.headers.end()) {
                            std::string websocket_key = boost::trim_right_copy(websocket_key_it->second);
                            websocket_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                            std::vector<char> hashed(20);
                            SHA1((const unsigned char*) websocket_key.data(), websocket_key.size(), (unsigned char*) hashed.data());
                            resp.headers["Sec-WebSocket-Accept"] = b64_encode(hashed);
                        }

                        HTTPHeaders::const_iterator websocket_protocol_it;
                        if ((!resp.headers.count("Sec-WebSocket-Protocol")) && (websocket_protocol_it = req.headers.find("Sec-WebSocket-Protocol")) != req.headers.end()) {
                            std::vector<std::string> split_websocket_protocol;
                            boost::split(split_websocket_protocol, websocket_protocol_it->second, boost::is_any_of(","));
                            resp.headers["Sec-WebSocket-Protocol"] = boost::trim_copy(split_websocket_protocol.back());
                        }
                    } else if (!resp.headers.count("Connection")) {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    ssize_t result;
                    if ((result = conn->send(resp)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    } else if (result == PN_ERROR) {
                        return PN_ERROR;
                    }

                    if (resp.status_code == "101") {
                        return handle_ws_connection(std::move(conn), ws_routes[ws_route_target]);
                    }
                } else if (!http_route_target.empty()) {
                    if (handle_error(*conn, "400", keep_alive, req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else {
                    if (handle_error(*conn, "404", keep_alive, req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                }
            } else {
                if (!http_route_target.empty()) {
                    HTTPResponse resp;
                    try {
                        resp = routes[http_route_target].cb(*conn, req);
                    } catch (...) {
                        if (handle_error(*conn, "500", keep_alive, req.http_version) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        continue;
                    }

                    if (!resp.headers.count("Server")) {
                        resp.headers["Server"] = PW_SERVER_NAME;
                    }
                    if (!resp.headers.count("Connection")) {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    ssize_t result;
                    if ((result = conn->send(resp)) == 0) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    } else if (result == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else if (!ws_route_target.empty()) {
                    if (handle_error(*conn, "426", {{"Connection", keep_alive ? "keep-alive, upgrade" : "close, upgrade"}, {"Upgrade", "websocket"}}, req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else {
                    if (handle_error(*conn, "404", keep_alive, req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                }
            }
        }
        return PN_OK;
    }

    int Server::handle_error(Connection& conn, const std::string& status_code, const HTTPHeaders& headers, const std::string& http_version) {
        HTTPResponse resp;
        try {
            resp = this->on_error(status_code);
        } catch (...) {
            resp = HTTPResponse::make_basic("500");
        }

        if (!resp.headers.count("Server")) {
            resp.headers["Server"] = PW_SERVER_NAME;
        }

        for (auto& header : headers) {
            if (!resp.headers.count(header.first)) {
                resp.headers.insert(std::move(header));
            }
        }

        ssize_t result;
        if ((result = conn.send(resp)) == 0) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        } else if (result == PN_ERROR) {
            return PN_ERROR;
        }

        return PN_OK;
    }

    int Server::handle_error(Connection& conn, const std::string& status_code, bool keep_alive, const std::string& http_version) {
        HTTPResponse resp;
        try {
            resp = on_error(status_code);
        } catch (...) {
            resp = HTTPResponse::make_basic("500");
        }

        if (!resp.headers.count("Server")) {
            resp.headers["Server"] = PW_SERVER_NAME;
        }
        if (!resp.headers.count("Connection")) {
            resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
        }

        ssize_t result;
        if ((result = conn.send(resp)) == 0) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        } else if (result == PN_ERROR) {
            return PN_ERROR;
        }

        return PN_OK;
    }
} // namespace pw
