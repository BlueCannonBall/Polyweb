#include "polyweb.hpp"
#include <algorithm>
#include <bitset>
#include <codecvt>
#include <iomanip>
#include <iterator>
#include <locale>
#include <math.h>
#include <sstream>
#include <string.h>
#include <wchar.h>
#ifdef POLYWEB_SIMD
    #include <x86intrin.h>
#endif

namespace pw {
    // f(x) = 2 * log2(x) + x + 4
    tp::ThreadPool threadpool(roundf(2.f * log2f(std::thread::hardware_concurrency()) + std::thread::hardware_concurrency() + 4.f));

    namespace detail {
        thread_local int last_error = PW_ESUCCESS;
        static constexpr char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        void reverse_memcpy(char* dest, const char* src, size_t size) {
            size_t i = 0;
#ifdef POLYWEB_SIMD
            for (const static __m128i pattern_vec = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15); i + 16 <= size; i += 16) {
                __m128i src_vec = _mm_loadu_si128((const __m128i_u*) (src + size - 16 - i));
                __m128i reversed_vec = _mm_shuffle_epi8(src_vec, pattern_vec);
                _mm_storeu_si128(((__m128i_u*) &dest[i]), reversed_vec);
            }
#endif
            for (; i < size; ++i) {
                dest[i] = src[size - 1 - i];
            }
        }
    } // namespace detail

    void reverse_memcpy(void* dest, const void* src, size_t size) {
        detail::reverse_memcpy((char*) dest, (const char*) src, size);
    }

    std::string strerror(int error) {
        const static std::string error_strings[] = {
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
        case PW_ENET:
            specific_error = pn::universal_strerror();
            break;

        default:
            return base_error;
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
        ss.imbue(std::locale("C"));
        ss << std::put_time(&timeinfo, "%a, %d %b %Y %H:%M:%S GMT");
        return ss.str();
    }

    time_t parse_date(const std::string& date) {
        struct tm timeinfo = {0};
        std::istringstream ss(date);
        ss.imbue(std::locale("C"));
        ss >> std::get_time(&timeinfo, "%a, %d %b %Y %H:%M:%S GMT");
        return timegm(&timeinfo);
    }

    std::string base64_encode(const unsigned char* data, size_t size) {
        std::string ret;
        ret.reserve(size + (size / 3));

        size_t i = 0;
        for (; i + 3 <= size; i += 3) {
            std::bitset<24> bits((((uint32_t) data[i]) << 16) | (((uint32_t) data[i + 1]) << 8) | data[i + 2]);
            ret.insert(ret.end(),
                {
                    detail::base64_alphabet[(bits >> 18).to_ulong()],
                    detail::base64_alphabet[((bits >> 12) & std::bitset<24>(0x3F)).to_ulong()],
                    detail::base64_alphabet[((bits >> 6) & std::bitset<24>(0x3F)).to_ulong()],
                    detail::base64_alphabet[(bits & std::bitset<24>(0x3F)).to_ulong()],
                });
        }
        if (size_t leftover = size - i) {
            switch (leftover) {
            case 1: {
                std::bitset<12> bits(((uint32_t) data[i]) << 4);
                ret.insert(ret.end(),
                    {
                        detail::base64_alphabet[(bits >> 6).to_ulong()],
                        detail::base64_alphabet[(bits & std::bitset<12>(0x3F)).to_ulong()],
                        '=',
                        '=',
                    });
                break;
            }

            case 2: {
                std::bitset<18> bits((((uint32_t) data[i]) << 10) | (((uint32_t) data[i + 1]) << 2));
                ret.insert(ret.end(),
                    {
                        detail::base64_alphabet[(bits >> 12).to_ulong()],
                        detail::base64_alphabet[((bits >> 6) & std::bitset<18>(0x3F)).to_ulong()],
                        detail::base64_alphabet[(bits & std::bitset<18>(0x3F)).to_ulong()],
                        '=',
                    });
                break;
            }
            }
        }

        return ret;
    }

    std::string base64_encode(const char* data, size_t size) {
        return base64_encode((const unsigned char*) data, size);
    }

    std::vector<char> base64_decode(pn::StringView str) {
        std::vector<uint8_t> indices;
        indices.reserve(str.size());

        for (char c : str) {
            if (const char* ptr = strchr(detail::base64_alphabet, c)) {
                indices.push_back(ptr - detail::base64_alphabet);
            } else {
                break;
            }
        }

        std::vector<char> ret;
        ret.reserve(indices.size() * 6 / 8);

        size_t i = 0;
        for (; i + 4 <= indices.size(); i += 4) {
            std::bitset<24> bits((((uint32_t) indices[i]) << 18) | (((uint32_t) indices[i + 1]) << 12) | (((uint32_t) indices[i + 2]) << 6) | indices[i + 3]);
            ret.insert(ret.end(),
                {
                    (char) (bits >> 16).to_ulong(),
                    (char) ((bits >> 8) & std::bitset<24>(0xFF)).to_ulong(),
                    (char) (bits & std::bitset<24>(0xFF)).to_ulong(),
                });
        }
        if (size_t leftover = indices.size() - i) {
            switch (leftover) {
            case 2: {
                std::bitset<12> bits((((uint32_t) indices[i]) << 6) | indices[i + 1]);
                ret.push_back((bits >> 4).to_ulong());
                break;
            }

            case 3: {
                std::bitset<18> bits((((uint32_t) indices[i]) << 12) | (((uint32_t) indices[i + 1]) << 6) | indices[i + 2]);
                ret.insert(ret.end(),
                    {
                        (char) (bits >> 10).to_ulong(),
                        (char) ((bits >> 2) & std::bitset<18>(0xFF)).to_ulong(),
                    });
                break;
            }
            }
        }

        return ret;
    }

    std::string percent_encode(pn::StringView str, bool plus_as_space, bool allow_slash) {
        std::string ret;
        ret.reserve(str.size());
        for (char c : str) {
            static constexpr char allowed_characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~@:";
            if (plus_as_space && c == ' ') {
                ret.push_back('+');
            } else if (allow_slash && c == '/') {
                ret.push_back('/');
            } else if (c == '\0' || strchr(allowed_characters, c) == nullptr) {
                unsigned char upper_nibble = (unsigned char) (c & 0xF0) >> 4;
                unsigned char lower_nibble = c & 0xF;
                ret.push_back('%');
                ret.push_back(upper_nibble < 10 ? '0' + upper_nibble : 'A' + upper_nibble - 10);
                ret.push_back(lower_nibble < 10 ? '0' + lower_nibble : 'A' + lower_nibble - 10);
            } else {
                ret.push_back(c);
            }
        }
        return ret;
    }

    std::string percent_decode(pn::StringView str, bool plus_as_space) {
        std::string ret;
        ret.reserve(str.size());

        int reading_percent = 0;
        unsigned char current_character;
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
                    nibble = toupper((unsigned char) c) - 'A' + 10;
                }

                current_character |= nibble << ((reading_percent - 1) * 4);

                if (!--reading_percent) {
                    ret.push_back(current_character);
                }
            }
        }

        return ret;
    }

    std::wstring xml_escape(pn::WStringView wstr) {
        std::wstring ret;
        ret.reserve(wstr.size() + (wstr.size() / 10));
        for (wchar_t wc : wstr) {
            static constexpr wchar_t allowed_characters[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ";
            if (wcschr(allowed_characters, wc)) {
                ret.push_back(wc);
            } else {
                std::wostringstream ss;
                ss << L"&#" << +wc << L';';
                ret += ss.str();
            }
        }
        return ret;
    }

    std::string xml_escape(const std::string& str) {
        static thread_local std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        return converter.to_bytes(xml_escape(converter.from_bytes(str)));
    }

    std::string QueryParameters::build() const {
        std::string ret;
        for (auto it = map.begin(); it != map.end(); ++it) {
            if (it != map.begin()) ret.push_back('&');
            std::string encoded_key = percent_encode(it->first, false, false);
            std::string encoded_value = percent_encode(it->second, false, false);
            ret.insert(ret.end(), encoded_key.begin(), encoded_key.end());
            ret.push_back('=');
            ret.insert(ret.end(), encoded_value.begin(), encoded_value.end());
        }
        return ret;
    }

    void QueryParameters::parse(pn::StringView query_string) {
        std::vector<std::string> split_query_string = string::split(query_string, '&');
        map.clear();
        for (const auto& parameter : split_query_string) {
            std::vector<std::string> split_parameter = string::split(parameter, '=');
            if (split_parameter.size() >= 2) {
                map[percent_decode(split_parameter[0], true)] = percent_decode(split_parameter[1], true);
            } else if (!split_parameter.empty()) {
                map[percent_decode(split_parameter[0], true)]; // Create key with empty value
            }
        }
    }

    std::string URLInfo::build() const {
        std::string ret = scheme + "://";
        if (!credentials.empty()) {
            ret += percent_encode(username()) + ':' + percent_encode(password()) + '@';
        }
        ret += host;
        if (path != "/" || !query_parameters->empty()) {
            ret += path;
            if (!query_parameters->empty()) {
                ret += '?' + query_parameters.build();
            }
        }
        return ret;
    }

    int URLInfo::parse(pn::StringView url) {
        size_t offset = 0;

        size_t scheme_host_delimiter_pos;
        if ((scheme_host_delimiter_pos = url.find("://", offset)) == std::string::npos || scheme_host_delimiter_pos == offset) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }
        scheme = url.substr(offset, scheme_host_delimiter_pos - offset);
        offset = scheme_host_delimiter_pos + 3;

        credentials.clear();
        size_t credentials_host_delimiter_pos;
        if ((credentials_host_delimiter_pos = url.find('@', offset)) != std::string::npos &&
            url.find('/', offset) > credentials_host_delimiter_pos) {
            if (credentials_host_delimiter_pos == offset) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }
            credentials = percent_decode(url.substr(offset, credentials_host_delimiter_pos - offset));
            offset = credentials_host_delimiter_pos + 1;
        }

        size_t path_pos;
        if ((path_pos = url.find('/', offset)) != std::string::npos) {
            if (path_pos == offset) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }
            host = url.substr(offset, path_pos - offset);
            offset = path_pos + 1;
        } else {
            host = url.substr(offset);
            path = '/';
            return PN_OK;
        }

        size_t path_query_string_delimiter_pos;
        if ((path_query_string_delimiter_pos = url.find('?', offset)) != std::string::npos) {
            if (path_query_string_delimiter_pos == offset) {
                path = '/';
            } else {
                path = '/' + url.substr(offset, path_query_string_delimiter_pos - offset);
            }
            offset = path_query_string_delimiter_pos + 1;
        } else {
            path = '/' + url.substr(offset, url.find('#', offset));
            return PN_OK;
        }

        query_parameters.parse(url.substr(offset, url.find('#', offset)));
        return PN_OK;
    }

    unsigned short URLInfo::port() const {
        size_t hostname_port_delimiter_pos;
        if ((hostname_port_delimiter_pos = host.find(':')) == std::string::npos) {
            return string::iequals(scheme, "https") || string::iequals(scheme, "wss") ? 443 : 80;
        } else {
            std::string port = host.substr(hostname_port_delimiter_pos + 1);
            try {
                return std::stoi(port);
            } catch (...) {
                return 80;
            }
        }
    }

    std::vector<char> HTTPRequest::build() const {
        std::vector<char> ret;

        ret.insert(ret.end(), method.begin(), method.end());
        ret.push_back(' ');

        std::string encoded_target = percent_encode(target);
        ret.insert(ret.end(), encoded_target.begin(), encoded_target.end());
        if (!query_parameters->empty()) {
            ret.push_back('?');
            std::string query_string = query_parameters.build();
            ret.insert(ret.end(), query_string.begin(), query_string.end());
        }
        ret.push_back(' ');

        ret.insert(ret.end(), http_version.begin(), http_version.end());
        ret.insert(ret.end(), {'\r', '\n'});

        for (const auto& header : headers) {
            ret.insert(ret.end(), header.first.begin(), header.first.end());
            ret.insert(ret.end(), {':', ' '});
            ret.insert(ret.end(), header.second.begin(), header.second.end());
            ret.insert(ret.end(), {'\r', '\n'});
        }

        if (!headers.count("Content-Length") && !body.empty()) {
            std::string header = "Content-Length: " + std::to_string(body.size()) + "\r\n";
            ret.insert(ret.end(), header.begin(), header.end());
        }
        ret.insert(ret.end(), {'\r', '\n'});
        ret.insert(ret.end(), body.begin(), body.end());

        return ret;
    }

    int HTTPRequest::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, unsigned int header_climit, long header_name_rlimit, long header_value_rlimit, long body_rlimit, long misc_rlimit) {
        method.clear();
        if (detail::recv_until(conn, buf_receiver, std::back_inserter(method), ' ', misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (method.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        target.clear();
        if (detail::recv_until(conn, buf_receiver, std::back_inserter(target), ' ', misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (target.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        http_version.clear();
        if (detail::recv_until(conn, buf_receiver, std::back_inserter(http_version), "\r\n", misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (http_version.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        headers.clear();
        for (unsigned int i = 0;; ++i) {
            if (i > header_climit) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            std::string header_name;
            if (detail::recv_until(conn, buf_receiver, std::back_inserter(header_name), ':', header_name_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }

            if (header_name.empty()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            std::string header_value;
            if (detail::recv_until(conn, buf_receiver, std::back_inserter(header_value), "\r\n", header_value_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }
            string::trim(header_value);

            headers[header_name] = header_value;

            char end_check_buf[2];
            if (long result = buf_receiver.recvall(conn, end_check_buf, 2); result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if (result != 2) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            if (memcmp("\r\n", end_check_buf, 2) == 0) {
                break;
            } else {
                buf_receiver.rewind(end_check_buf, 2);
            }
        }

        body.clear();
        if (auto content_length_it = headers.find("Content-Length"); content_length_it != headers.end()) {
            unsigned long long content_length;
            try {
                content_length = std::stoull(content_length_it->second);
            } catch (...) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            if (content_length) {
                if (content_length > (unsigned long long) body_rlimit) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                body.resize(content_length);
                if (long result = buf_receiver.recvall(conn, body.data(), content_length); result == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if ((unsigned long long) result != content_length) {
                    detail::set_last_error(PW_EWEB);
                    body.resize(result);
                    return PN_ERROR;
                }
            }
        }

        query_parameters->clear();
        if (auto query_string_begin = std::find(target.begin(), target.end(), '?'); query_string_begin != target.end()) {
            if (std::next(query_string_begin) != target.end()) {
                query_parameters.parse(std::string(std::next(query_string_begin), target.end()));
            }
            target.resize(std::distance(target.begin(), query_string_begin));
        }
        target = percent_decode(target);

        return PN_OK;
    }

    std::vector<char> HTTPResponse::build(bool head_only) const {
        std::vector<char> ret;

        ret.insert(ret.end(), http_version.begin(), http_version.end());
        ret.push_back(' ');
        std::string status_code_string = std::to_string(status_code);
        ret.insert(ret.end(), status_code_string.begin(), status_code_string.end());
        ret.push_back(' ');
        ret.insert(ret.end(), reason_phrase.begin(), reason_phrase.end());
        ret.insert(ret.end(), {'\r', '\n'});

        for (const auto& header : headers) {
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
            std::string header = "Content-Length: " + std::to_string(body.size()) + "\r\n";
            ret.insert(ret.end(), header.begin(), header.end());
        }
        ret.insert(ret.end(), {'\r', '\n'});
        if (!head_only) ret.insert(ret.end(), body.begin(), body.end());

        return ret;
    }

    int HTTPResponse::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, bool head_only, unsigned int header_climit, long header_name_rlimit, long header_value_rlimit, long body_chunk_rlimit, long body_rlimit, long misc_rlimit) {
        http_version.clear();
        if (detail::recv_until(conn, buf_receiver, std::back_inserter(http_version), ' ', misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (http_version.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        std::string status_code_string;
        if (detail::recv_until(conn, buf_receiver, std::back_inserter(status_code_string), ' ', misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (status_code_string.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }
        try {
            status_code = std::stoi(status_code_string);
        } catch (...) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        reason_phrase.clear();
        if (detail::recv_until(conn, buf_receiver, std::back_inserter(reason_phrase), "\r\n", misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }
        if (reason_phrase.empty()) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        headers.clear();
        for (unsigned int i = 0;; ++i) {
            if (i > header_climit) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            std::string header_name;
            if (detail::recv_until(conn, buf_receiver, std::back_inserter(header_name), ':', header_name_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }
            if (header_name.empty()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            std::string header_value;
            if (detail::recv_until(conn, buf_receiver, std::back_inserter(header_value), "\r\n", header_value_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }
            string::trim(header_value);

            headers[header_name] = header_value;

            char end_check_buf[2];
            if (long result = buf_receiver.recvall(conn, end_check_buf, 2); result == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            } else if (result != 2) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            if (memcmp("\r\n", end_check_buf, 2) == 0) {
                break;
            } else {
                buf_receiver.rewind(end_check_buf, 2);
            }
        }

        body.clear();
        if (!head_only) {
            if (auto transfer_encoding_it = headers.find("Transfer-Encoding"); transfer_encoding_it != headers.end()) {
                if (string::iequals(transfer_encoding_it->second, "chunked")) {
                    for (;;) {
                        std::string chunk_size_string;
                        if (detail::recv_until(conn, buf_receiver, std::back_inserter(chunk_size_string), "\r\n", misc_rlimit) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        if (chunk_size_string.empty()) {
                            detail::set_last_error(PW_EWEB);
                            return PN_ERROR;
                        }

                        unsigned long long chunk_size;
                        if (std::istringstream ss(chunk_size_string); !(ss >> std::hex >> chunk_size)) {
                            detail::set_last_error(PW_EWEB);
                            return PN_ERROR;
                        }

                        if (!chunk_size) {
                            char end_buf[2];
                            if (long result = buf_receiver.recvall(conn, end_buf, 2); result == PN_ERROR) {
                                detail::set_last_error(PW_ENET);
                                return PN_ERROR;
                            } else if (result != 2) {
                                detail::set_last_error(PW_EWEB);
                                return PN_ERROR;
                            }
                            break;
                        }

                        size_t end = body.size();

                        if (chunk_size > (unsigned long long) body_chunk_rlimit || end + chunk_size > (unsigned long long) body_rlimit) {
                            detail::set_last_error(PW_EWEB);
                            return PN_ERROR;
                        } else {
                            body.resize(end + chunk_size);
                            if (long result = buf_receiver.recvall(conn, &body[end], chunk_size); result == PN_ERROR) {
                                detail::set_last_error(PW_ENET);
                                return PN_ERROR;
                            } else if ((unsigned long long) result != chunk_size) {
                                detail::set_last_error(PW_EWEB);
                                body.resize(end + result);
                                return PN_ERROR;
                            }
                        }

                        char end_buf[2];
                        if (long result = buf_receiver.recvall(conn, end_buf, 2); result == PN_ERROR) {
                            detail::set_last_error(PW_ENET);
                            return PN_ERROR;
                        } else if (result != 2) {
                            detail::set_last_error(PW_EWEB);
                            return PN_ERROR;
                        }
                    }
                } else { // Only chunked transfer encoding is supported atm
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }
            } else if (auto content_length_it = headers.find("Content-Length"); content_length_it != headers.end()) {
                unsigned long long content_length;
                try {
                    content_length = std::stoull(content_length_it->second);
                } catch (...) {
                    detail::set_last_error(PW_EWEB);
                    return PN_ERROR;
                }

                if (content_length) {
                    if (content_length > (unsigned long long) body_rlimit) {
                        detail::set_last_error(PW_EWEB);
                        return PN_ERROR;
                    }

                    body.resize(content_length);
                    if (long result = buf_receiver.recvall(conn, body.data(), content_length); result == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    } else if ((unsigned long long) result != content_length) {
                        detail::set_last_error(PW_EWEB);
                        body.resize(result);
                        return PN_ERROR;
                    }
                }
            }
        }

        return PN_OK;
    }

    template <typename Base>
    int BasicConnection<Base>::ws_close(uint16_t status_code, pn::StringView reason, const char* masking_key) {
        if (!this->is_valid()) {
            ws_closed = true;
            return PN_OK;
        }

        WSMessage message(8);
        message->resize(2 + reason.size());
#if BYTE_ORDER == BIG_ENDIAN
        memcpy(message->data(), &status_code, 2);
#else
        reverse_memcpy(message->data(), &status_code, 2);
#endif
        memcpy(message->data() + 2, reason.data(), reason.size());

        if (send(message, masking_key) == PN_ERROR) {
            return PN_ERROR;
        }

        ws_closed = true;
        return PN_OK;
    }

    template class BasicConnection<pn::tcp::Connection>;
    template class BasicConnection<pn::tcp::SecureConnection>;

    template class BasicConnection<pn::tcp::Client>;
    template class BasicConnection<pn::tcp::SecureClient>;
} // namespace pw
