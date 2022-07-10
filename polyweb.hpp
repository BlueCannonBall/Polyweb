#ifndef _POLYWEB_HPP
#define _POLYWEB_HPP

#include "Polynet/polynet.hpp"
#include "mimetypes.hpp"
#include "threadpool.hpp"
#include <boost/algorithm/string.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <cstdint>
#include <map>
#include <openssl/sha.h>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <x86intrin.h>

#define PW_ERROR PN_ERROR
#define PW_OK    PN_OK

// Errors
#define PW_ESUCCESS 0
#define PW_ENET     1
#define PW_EWEB     2

#define UNION_CAST(x, new_type) \
    (((union {__typeof__(x) a; new_type b; }) x).b)

// Websocket macros
#define PW_GET_WS_FRAME_FIN(frame)            (frame[0] & 0b10000000)
#define PW_GET_WS_FRAME_RSV1(frame)           (frame[0] & 0b01000000)
#define PW_GET_WS_FRAME_RSV2(frame)           (frame[0] & 0b00100000)
#define PW_GET_WS_FRAME_RSV3(frame)           (frame[0] & 0b00010000)
#define PW_GET_WS_FRAME_OPCODE(frame)         (frame[0] & 0b00001111)
#define PW_GET_WS_FRAME_MASKED(frame)         (frame[1] & 0b10000000)
#define PW_GET_WS_FRAME_PAYLOAD_LENGTH(frame) (frame[1] & 0b01111111)

#define PW_SET_WS_FRAME_FIN(frame)                    (frame[0] |= 0b10000000)
#define PW_SET_WS_FRAME_RSV1(frame)                   (frame[0] |= 0b01000000)
#define PW_SET_WS_FRAME_RSV2(frame)                   (frame[0] |= 0b00100000)
#define PW_SET_WS_FRAME_RSV3(frame)                   (frame[0] |= 0b00010000)
#define PW_SET_WS_FRAME_OPCODE(frame, opcode)         (frame[0] = (frame[0] & ~0x0f) | (opcode & ~0xf0))
#define PW_SET_WS_FRAME_MASKED(frame)                 (frame[1] |= 0b10000000)
#define PW_SET_WS_FRAME_PAYLOAD_LENGTH(frame, length) (frame[1] = (frame[1] & ~0x7f) | (length & ~0x80))

#define PW_CLEAR_WS_FRAME_FIN(frame)            (frame[0] &= ~0b10000000)
#define PW_CLEAR_WS_FRAME_RSV1(frame)           (frame[0] &= ~0b01000000)
#define PW_CLEAR_WS_FRAME_RSV2(frame)           (frame[0] &= ~0b00100000)
#define PW_CLEAR_WS_FRAME_RSV3(frame)           (frame[0] &= ~0b00010000)
#define PW_CLEAR_WS_FRAME_OPCODE(frame)         (frame[0] &= ~0x0f)
#define PW_CLEAR_WS_FRAME_MASKED(frame)         (frame[1] &= ~0b10000000)
#define PW_CLEAR_WS_FRAME_PAYLOAD_LENGTH(frame) (frame[1] &= ~0x7f)

#define PW_TOGGLE_WS_FRAME_FIN(frame)            (frame[0] ^= 0b10000000)
#define PW_TOGGLE_WS_FRAME_RSV1(frame)           (frame[0] ^= 0b01000000)
#define PW_TOGGLE_WS_FRAME_RSV2(frame)           (frame[0] ^= 0b00100000)
#define PW_TOGGLE_WS_FRAME_RSV3(frame)           (frame[0] ^= 0b00010000)
#define PW_TOGGLE_WS_FRAME_OPCODE(frame)         (frame[0] ^= 0x0f)
#define PW_TOGGLE_WS_FRAME_MASKED(frame)         (frame[1] ^= 0b10000000)
#define PW_TOGGLE_WS_FRAME_PAYLOAD_LENGTH(frame) (frame[1] ^= 0x7f)

namespace pw {
    namespace detail {
        tp::ThreadPool pool(std::thread::hardware_concurrency() * 3); // NOLINT
        thread_local int last_error = PW_ESUCCESS;                    // NOLINT

        inline void set_last_error(int error) {
            last_error = error;
        }

        template <typename InsertIt>
        int read_until(pn::tcp::Connection& conn, InsertIt ret, const std::string& end_sequence) {
            size_t search_pos = 0;
            for (;;) {
                char c;
                ssize_t read_result;
                if ((read_result = conn.recv(&c, sizeof(c), MSG_WAITALL)) == 0) {
                    detail::set_last_error(PW_EWEB);
                    return PW_ERROR;
                    break;
                } else if (read_result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PW_ERROR;
                    break;
                }

                if (c == end_sequence[search_pos]) {
                    if (++search_pos == end_sequence.size()) {
                        break;
                    }
                } else {
                    ret = c;
                    search_pos = 0;

                    if (c == end_sequence[search_pos]) {
                        if (++search_pos == end_sequence.size()) {
                            break;
                        }
                    }
                }
            }

            return PW_OK;
        }

        struct case_insensitive_comparer {
            bool operator()(const std::string& a, const std::string& b) const {
                return boost::iequals(a, b);
            }
        };

        struct case_insensitive_hasher {
            size_t operator()(const std::string& key) const {
                std::string key_copy = boost::to_lower_copy(key);
                return std::hash<std::string>()(key_copy);
            }
        };

        void reverse_memcpy(char* dest, char* src, size_t len) { // NOLINT
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

        inline std::string remove_special_target_syntax(const std::string& target) {
            if (target.back() == '*' || target.back() == '?') {
                return target.substr(0, target.size() - 1);
            } else if (boost::ends_with(target, "*?")) {
                return target.substr(0, target.size() - 2);
            } else {
                return target;
            }
        }
    } // namespace detail

    inline int get_last_error(void) {
        return detail::last_error;
    }

    const char* strerror(int error = get_last_error()) { // NOLINT
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

    std::string universal_strerror(int error = get_last_error()) { // NOLINT
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

    // Remove trailing slash in target
    inline void clean_up_target(std::string& target) {
        if (target.size() > 1 && target.back() == '/') {
            target.pop_back();
        }
    }

    std::string status_code_to_reason_phrase(const std::string& status_code) { // NOLINT
        const static std::map<std::string, std::string> conversion_mapping = {
            {"100", "Continue"},
            {"101", "Switching Protocols"},
            {"200", "OK"},
            {"201", "Created"},
            {"202", "Accepted"},
            {"203", "Non-Authoritative Information"},
            {"204", "No Content"},
            {"205", "Reset Content"},
            {"206", "Partial Content"},
            {"300", "Multiple Choices"},
            {"301", "Moved Permanently"},
            {"302", "Found"},
            {"303", "See Other"},
            {"304", "Not Modified"},
            {"305", "Use Proxy"},
            {"307", "Temporary Redirect"},
            {"400", "Bad Request"},
            {"401", "Unauthorized"},
            {"402", "Payment Required"},
            {"403", "Forbidden"},
            {"404", "Not Found"},
            {"405", "Method Not Allowed"},
            {"406", "Not Acceptable"},
            {"407", "Proxy Authentication Required"},
            {"408", "Request Time-out"},
            {"409", "Conflict"},
            {"410", "Gone"},
            {"411", "Length Required"},
            {"412", "Precondition Failed"},
            {"413", "Request Entity Too Large"},
            {"414", "Request-URI Too Large"},
            {"415", "Unsupported Media Type"},
            {"416", "Requested range not satisfiable"},
            {"417", "Expectation Failed"},
            {"426", "Upgrade Required"},
            {"500", "Internal Server Error"},
            {"501", "Not Implemented"},
            {"502", "Bad Gateway"},
            {"503", "Service Unavailable"},
            {"504", "Gateway Time-out"},
            {"505", "HTTP Version not supported"}};
        return conversion_mapping.at(status_code);
    }

    std::vector<char> b64_decode(const std::string& str) { // NOLINT
        using namespace boost::archive::iterators;
        using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;
        return boost::algorithm::trim_right_copy_if(std::vector<char>(It(std::begin(str)), It(std::end(str))), [](char c) {
            return c == '\0';
        });
    }

    std::string b64_encode(const std::vector<char>& data) { // NOLINT
        using namespace boost::archive::iterators;
        using It = base64_from_binary<transform_width<std::vector<char>::const_iterator, 6, 8>>;
        auto ret = std::string(It(std::begin(data)), It(std::end(data)));
        return ret.append((3 - data.size() % 3) % 3, '=');
    }

    std::string percent_encode(const std::string& str, bool plus_as_space = false, bool allow_slash = true) { // NOLINT
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

    std::string percent_decode(const std::string& str, bool plus_as_space = false) { // NOLINT
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

    inline bool is_wildcard_target(const std::string& target) {
        return target.back() == '*' || boost::ends_with(target, "*?");
    }

    typedef std::unordered_map<std::string, std::string, detail::case_insensitive_hasher, detail::case_insensitive_comparer> HTTPHeaders;
    typedef std::unordered_map<std::string, std::string> QueryParameters;

    class HTTPRequest {
    public:
        std::string method;
        std::string target;
        HTTPHeaders headers;
        std::vector<char> body;
        QueryParameters query_parameters;
        std::string http_version = "HTTP/1.1";

        HTTPRequest(void) = default;
        HTTPRequest(const std::string& method, const std::string& target, const HTTPHeaders& headers = {}) :
            method(method),
            target(target),
            headers(headers) { }
        HTTPRequest(const std::string& method, const std::string& target, const std::vector<char>& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            method(method),
            target(target),
            headers(headers),
            body(body),
            http_version(http_version) { }
        HTTPRequest(const std::string& method, const std::string& target, const std::string& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            method(method),
            target(target),
            headers(headers),
            body(body.begin(), body.end()),
            http_version(http_version) { }
        HTTPRequest(const std::string& method, const std::string& target, const QueryParameters& query_parameters = {}, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            method(method),
            target(target),
            headers(headers),
            query_parameters(query_parameters),
            http_version(http_version) { }

        std::vector<char> build(void) const {
            std::vector<char> ret;

            ret.insert(ret.end(), this->method.begin(), this->method.end());
            ret.push_back(' ');

            std::string clean_target(this->target);
            clean_up_target(clean_target);
            std::string encoded_target = percent_encode(clean_target);
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

        inline std::string build_str(void) const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn) {
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

            clean_up_target(target); // Remove trailing slash in target

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
                target = percent_decode(target);
            }

            return PW_OK;
        }
    };

    class HTTPResponse {
    public:
        std::string status_code;
        std::string reason_phrase;
        std::vector<char> body;
        HTTPHeaders headers;
        std::string http_version = "HTTP/1.1";

        HTTPResponse(void) = default;
        HTTPResponse(const std::string& status_code) :
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)) { }
        HTTPResponse(const std::string& status_code, const std::vector<char>& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body),
            headers(headers),
            http_version(http_version) { }
        HTTPResponse(const std::string& status_code, const std::string& body, const HTTPHeaders& headers = {}, const std::string& http_version = "HTTP/1.1") :
            status_code(status_code),
            reason_phrase(status_code_to_reason_phrase(status_code)),
            body(body.begin(), body.end()),
            headers(headers),
            http_version(http_version) { }

        std::vector<char> build(void) const {
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

        inline std::string build_str(void) const {
            std::vector<char> ret = build();
            return std::string(ret.begin(), ret.end());
        }

        int parse(pn::tcp::Connection& conn) {
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

    private:
        friend class Connection;
        friend class Server;

        static HTTPResponse create_basic(const std::string& status_code, bool keep_alive, const std::string& http_version = "HTTP/1.1", const HTTPHeaders& headers = {}) {
            HTTPResponse resp(status_code, status_code + ' ' + status_code_to_reason_phrase(status_code) + '\n', headers, http_version);
            resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
            resp.headers["Content-Type"] = "text/plain";
            resp.headers["Server"] = "Polyweb/net Engine";
            return resp;
        }
    };

    class WSMessage {
    public:
        std::vector<char> data;
        uint8_t opcode;

        WSMessage(void) = default;
        WSMessage(const std::string& str, uint8_t opcode = 1) :
            data(str.begin(), str.end()),
            opcode(opcode) { }
        WSMessage(const std::vector<char>& data, uint8_t opcode = 2) :
            data(data),
            opcode(opcode) { }
        WSMessage(uint8_t opcode) :
            opcode(opcode) { }

        inline std::string to_string(void) const {
            return std::string(data.begin(), data.end());
        }

        std::vector<char> build(bool masked, char* masking_key = NULL) const {
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
    };

    class Connection: public pn::tcp::Connection {
    public:
        bool ws_closed = false;
        void* data = NULL; // User data

        Connection(void) = default;
        Connection(const Connection&) = default;
        Connection(Connection&& s) {
            *this = std::move(s);
        }
        Connection(pn::sockfd_t fd) :
            pn::tcp::Connection(fd) { }
        Connection(struct sockaddr addr, socklen_t addrlen) :
            pn::tcp::Connection(addr, addrlen) { }
        Connection(pn::sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            pn::tcp::Connection(fd, addr, addrlen) { }

        Connection& operator=(const Connection&) = default;
        inline Connection& operator=(Connection&& s) {
            pn::tcp::Connection::operator=(std::move(s));
            if (this != &s) {
                this->ws_closed = s.ws_closed;
                this->data = s.data;

                s.ws_closed = false;
                s.data = NULL;
            }

            return *this;
        }

        ssize_t send(const HTTPResponse& resp) {
            auto data = resp.build();
            ssize_t result;
            if ((result = pn::tcp::Connection::send(data.data(), data.size(), MSG_WAITALL)) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
            }
            return result;
        }

        ssize_t send(const WSMessage& message, bool masked = false, char* masking_key = NULL) {
            auto data = message.build(masked, masking_key);
            ssize_t result;
            if ((result = pn::tcp::Connection::send(data.data(), data.size(), MSG_WAITALL)) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
            }
            return result;
        }

        int close_ws(uint16_t status_code, const std::string& reason, bool masked = false, char* masking_key = NULL, bool validity_check = true) {
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

        int recv_ws(WSMessage& message) {
            bool fin = false;
            while (!fin) {
                char frame_header[2];
                {
                    ssize_t result;
                    if ((result = this->recv(frame_header, 2, MSG_WAITALL)) == 0) {
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
                    if ((result = this->recv(payload_length_16, 2, MSG_WAITALL)) == 0) {
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
                    if ((result = this->recv(payload_length_64, 8, MSG_WAITALL)) == 0) {
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
                    if ((result = this->recv(masking_key.bytes, 4, MSG_WAITALL)) == 0) {
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
                    if ((result = this->recv(&message.data[end], payload_length.integer, MSG_WAITALL)) == 0) {
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

    private:
        friend class Server;

        inline auto send_basic(const std::string& status_code, bool keep_alive, const std::string& http_version = "HTTP/1.1", const HTTPHeaders& headers = {}) {
            return send(HTTPResponse::create_basic(status_code, keep_alive, http_version, headers));
        }
    };

    typedef std::function<HTTPResponse(const Connection&, const HTTPRequest&)> HTTPRouteCallback;

    struct WSRoute {
        HTTPRouteCallback on_connect;
        std::function<void(Connection&, const WSMessage&)> on_message;
        std::function<void(Connection&, uint16_t status_code, const std::string& reason)> on_close;
    };

    class Server: public pn::tcp::Server {
    public:
        Server(void) = default;
        Server(const Server&) = default;
        Server(Server&& s) {
            *this = std::move(s);
        }
        Server(pn::sockfd_t fd) :
            pn::tcp::Server(fd) { }
        Server(struct sockaddr addr, socklen_t addrlen) :
            pn::tcp::Server(addr, addrlen) { }
        Server(pn::sockfd_t fd, struct sockaddr addr, socklen_t addrlen) :
            pn::tcp::Server(fd, addr, addrlen) { }

        Server& operator=(const Server&) = default;
        inline Server& operator=(Server&& s) {
            pn::tcp::Server::operator=(std::move(s));
            if (this != &s) {
                this->routes = std::move(s.routes);
            }

            return *this;
        }

        inline int bind(const std::string& host, const std::string& port) {
            if (pn::tcp::Server::bind(host, port) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
            return PW_OK;
        }

        inline int bind(const std::string& host, unsigned short port) {
            std::string str_port = std::to_string(port);
            return bind(host, str_port);
        }

        inline int bind(struct sockaddr* addr, socklen_t addrlen) {
            if (pn::tcp::Server::bind(addr, addrlen) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PW_ERROR;
            }
            return PW_OK;
        }

        void route(std::string target, HTTPRouteCallback route_cb) {
            clean_up_target(target);
            routes[target] = route_cb;
        }

        void unroute(std::string target) {
            clean_up_target(target);
            decltype(routes)::const_iterator route_it;
            if ((route_it = routes.find(target)) != routes.end()) {
                routes.erase(route_it);
            }
        }

        void route_ws(std::string target, const WSRoute& route) {
            clean_up_target(target);
            ws_routes[target] = route;
        }

        void unroute_ws(std::string target) {
            clean_up_target(target);
            decltype(ws_routes)::const_iterator route_it;
            if ((route_it = ws_routes.find(target)) != ws_routes.end()) {
                ws_routes.erase(route_it);
            }
        }

        int listen(int backlog) {
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

    protected:
        std::unordered_map<std::string, HTTPRouteCallback> routes;
        std::unordered_map<std::string, WSRoute> ws_routes;

        int handle_ws_connection(Connection conn, WSRoute& route) {
            while (conn.is_valid()) {
                WSMessage message;
                if (conn.recv_ws(message) == PW_ERROR) {
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

                            route.on_close(conn, status_code_union.integer, reason);

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

        int handle_connection(Connection conn) {
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
                    if ((!req.query_parameters.empty()) != (route.first.back() == '?')) {
                        continue;
                    }

                    std::string current_target = detail::remove_special_target_syntax(route.first);
                    if (current_target == req.target) {
                        ws_route_target = route.first;
                        break;
                    } else if (is_wildcard_target(route.first) && boost::starts_with(req.target, current_target) && current_target.size() > ws_route_target.size()) {
                        ws_route_target = route.first;
                    }
                }

                std::string http_route_target;
                for (const auto& route : routes) {
                    if ((!req.query_parameters.empty()) != (route.first.back() == '?')) {
                        continue;
                    }

                    std::string current_target = detail::remove_special_target_syntax(route.first);
                    if (current_target == req.target) {
                        http_route_target = route.first;
                        break;
                    } else if (is_wildcard_target(route.first) && boost::starts_with(req.target, current_target) && current_target.size() > http_route_target.size()) {
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
                            resp.headers["Connection"] = "Upgrade";
                            resp.headers["Upgrade"] = "websocket";

                            HTTPHeaders::const_iterator websocket_key_it;
                            if ((websocket_key_it = req.headers.find("Sec-WebSocket-Key")) != req.headers.end() && !resp.headers.count("Sec-WebSocket-Accept")) {
                                std::string websocket_key = boost::trim_right_copy(websocket_key_it->second);
                                websocket_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                                std::vector<char> hashed(20);
                                SHA1((const unsigned char*) websocket_key.data(), websocket_key.size(), (unsigned char*) hashed.data());
                                resp.headers["Sec-WebSocket-Accept"] = b64_encode(hashed);
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
                            resp = routes[http_route_target](conn, req);
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
    };
} // namespace pw

#endif
