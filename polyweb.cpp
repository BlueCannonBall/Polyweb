#include "polyweb.hpp"
#include <algorithm>
#include <bitset>
#include <cmath>
#include <codecvt>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <locale>
#include <openssl/sha.h>
#include <sstream>
#include <stdexcept>
#include <utility>
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
            for (const static __m128i pattern_vec = _mm_setr_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15); i + 16 <= size; i += 16) {
                __m128i src_vec = _mm_loadu_si128((const __m128i_u*) (src + size - 1 - i));
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

    std::vector<char> base64_decode(const std::string& str) {
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

    std::string percent_encode(const std::string& str, bool plus_as_space, bool allow_slash) {
        std::string ret;
        ret.reserve(str.size());
        for (char c : str) {
            static constexpr char allowed_characters[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
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

    std::string percent_decode(const std::string& str, bool plus_as_space) {
        std::string ret;
        ret.reserve(str.size());

        int reading_percent = 0;
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
                char nibble;
                if (c >= '0' && c <= '9') {
                    nibble = c - '0';
                } else {
                    nibble = toupper(c) - 'A' + 10;
                }

                current_character |= nibble << ((reading_percent - 1) * 4);

                if (!--reading_percent) {
                    ret.push_back(current_character);
                }
            }
        }

        return ret;
    }

    std::wstring escape_xml(const std::wstring& wstr) {
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

    std::string escape_xml(const std::string& str) {
        static thread_local std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        return converter.to_bytes(escape_xml(converter.from_bytes(str)));
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

    void QueryParameters::parse(const std::string& query_string) {
        std::vector<std::string> split_query_string = string::split(query_string, '&');
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
        std::string ret = scheme + "://" + host;
        if (!path.empty() || !query_parameters->empty()) {
            ret += path.empty() ? "/" : path;
            if (!query_parameters->empty()) {
                ret += '?' + query_parameters.build();
            }
        }
        return ret;
    }

    int URLInfo::parse(const std::string& url) {
        size_t scheme_host_delimiter_pos;
        if ((scheme_host_delimiter_pos = url.find("://")) == std::string::npos) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }
        this->scheme = url.substr(0, scheme_host_delimiter_pos);

        size_t path_pos;
        if ((path_pos = url.find('/', scheme_host_delimiter_pos + 3)) == scheme_host_delimiter_pos + 3) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }
        this->host = url.substr(scheme_host_delimiter_pos + 3, path_pos - (scheme_host_delimiter_pos + 3));

        if (path_pos != std::string::npos) {
            size_t path_query_string_delimiter_pos = url.find('?', path_pos + 1);
            this->path = url.substr(path_pos, path_query_string_delimiter_pos - path_pos);

            if (path_query_string_delimiter_pos != std::string::npos) {
                size_t query_parameters_fragment_delimiter_pos = url.find('#', path_query_string_delimiter_pos + 1);
                this->query_parameters.parse(url.substr(path_query_string_delimiter_pos + 1, query_parameters_fragment_delimiter_pos - (path_query_string_delimiter_pos + 1)));
            }
        } else {
            this->path = '/';
        }

        return PN_OK;
    }

    unsigned short URLInfo::port() const {
        size_t hostname_port_delimiter_pos;
        if ((hostname_port_delimiter_pos = host.find(':')) == std::string::npos) {
            return this->scheme == "https" || this->scheme == "wss" ? 443 : 80;
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

        if (!headers.count("Content-Length") && !this->body.empty()) {
            std::string header = "Content-Length: " + std::to_string(this->body.size()) + "\r\n";
            ret.insert(ret.end(), header.begin(), header.end());
        }
        ret.insert(ret.end(), {'\r', '\n'});
        ret.insert(ret.end(), this->body.begin(), this->body.end());

        return ret;
    }

    int HTTPRequest::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, size_t header_climit, size_t header_name_rlimit, size_t header_value_rlimit, size_t body_rlimit, size_t misc_rlimit) {
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

        for (size_t i = 0;; ++i) {
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
            if (header_value.empty()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            this->headers[header_name] = header_value;

            char end_check_buf[2];
            long result;
            if ((result = buf_receiver.recvall(conn, end_check_buf, 2)) == PN_ERROR) {
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
                }

                this->body.resize(content_length);
                long result;
                if ((result = buf_receiver.recvall(conn, body.data(), body.size())) == PN_ERROR) {
                    detail::set_last_error(PW_ENET);
                    return PN_ERROR;
                } else if ((size_t) result != body.size()) {
                    detail::set_last_error(PW_EWEB);
                    body.resize(result);
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

    std::vector<char> HTTPResponse::build(bool head_only) const {
        std::vector<char> ret;

        ret.insert(ret.end(), this->http_version.begin(), this->http_version.end());
        ret.push_back(' ');
        std::string status_code_string = std::to_string(status_code);
        ret.insert(ret.end(), status_code_string.begin(), status_code_string.end());
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
        if (!head_only) ret.insert(ret.end(), this->body.begin(), this->body.end());

        return ret;
    }

    int HTTPResponse::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, bool head_only, size_t header_climit, size_t header_name_rlimit, size_t header_value_rlimit, size_t body_chunk_rlimit, size_t body_rlimit, size_t misc_rlimit) {
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

        for (size_t i = 0;; ++i) {
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
            if (header_value.empty()) {
                detail::set_last_error(PW_EWEB);
                return PN_ERROR;
            }

            this->headers[header_name] = header_value;

            char end_check_buf[2];
            long result;
            if ((result = buf_receiver.recvall(conn, end_check_buf, 2)) == PN_ERROR) {
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

        if (!head_only) {
            HTTPHeaders::const_iterator transfer_encoding_it;
            HTTPHeaders::const_iterator content_length_it;
            if ((transfer_encoding_it = headers.find("Transfer-Encoding")) != headers.end()) {
                if (string::iequals(transfer_encoding_it->second, "chunked")) {
                    for (;;) {
                        std::string chunk_size_string;
                        if (detail::recv_until(conn, buf_receiver, std::back_inserter(chunk_size_string), "\r\n", body_chunk_rlimit) == PN_ERROR) {
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
                            long result;
                            if ((result = buf_receiver.recvall(conn, end_buf, 2)) == PN_ERROR) {
                                detail::set_last_error(PW_ENET);
                                return PN_ERROR;
                            } else if (result != 2) {
                                detail::set_last_error(PW_EWEB);
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
                            long result;
                            if ((result = buf_receiver.recvall(conn, &body[end], chunk_size)) == PN_ERROR) {
                                detail::set_last_error(PW_ENET);
                                return PN_ERROR;
                            } else if ((unsigned long long) result != chunk_size) {
                                detail::set_last_error(PW_EWEB);
                                body.resize(end + result);
                                return PN_ERROR;
                            }
                        }

                        char end_buf[2];
                        long result;
                        if ((result = buf_receiver.recvall(conn, end_buf, 2)) == PN_ERROR) {
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
                    }

                    this->body.resize(content_length);
                    long result;
                    if ((result = buf_receiver.recvall(conn, body.data(), body.size())) == PN_ERROR) {
                        detail::set_last_error(PW_ENET);
                        return PN_ERROR;
                    } else if ((size_t) result != body.size()) {
                        detail::set_last_error(PW_EWEB);
                        body.resize(result);
                        return PN_ERROR;
                    }
                }
            }
        }

        return PN_OK;
    }

    template <>
    Connection& Connection::operator=(const pn::tcp::Connection& conn) {
        if (this != &conn) {
            this->fd = conn.fd;
            this->addr = conn.addr;
            this->addrlen = conn.addrlen;
        }
        return *this;
    }

    template <>
    SecureConnection& SecureConnection::operator=(const pn::tcp::SecureConnection& conn) {
        if (this != &conn) {
            this->fd = conn.fd;
            this->addr = conn.addr;
            this->addrlen = conn.addrlen;
            this->ssl = conn.ssl;
        }
        return *this;
    }

    template <>
    Client& Client::operator=(const pn::tcp::Client& conn) {
        if (this != &conn) {
            this->fd = conn.fd;
            this->addr = conn.addr;
            this->addrlen = conn.addrlen;
        }
        return *this;
    }

    template <>
    SecureClient& SecureClient::operator=(const pn::tcp::SecureClient& conn) {
        if (this != &conn) {
            this->fd = conn.fd;
            this->addr = conn.addr;
            this->addrlen = conn.addrlen;
            this->ssl = conn.ssl;
        }
        return *this;
    }

    template <typename Base>
    int BasicServer<Base>::listen(std::function<bool(typename Base::connection_type&, void*)> filter, void* filter_data, int backlog) {
        if (Base::listen([filter = std::move(filter), filter_data](typename Base::connection_type& conn, void* data) -> bool {
                if (filter(conn, filter_data)) {
                    conn.close(true, false);
                } else {
                    auto server = (BasicServer<Base>*) data;
                    threadpool.schedule([conn](void* data) {
                        auto server = (BasicServer<Base>*) data;
                        pn::tcp::BufReceiver buf_receiver(server->buffer_size);
                        server->handle_connection(pn::UniqueSocket<connection_type>(conn), buf_receiver);
                    },
                        server,
                        true);
                }
                return true;
            },
                backlog,
                this) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        } else {
            throw std::logic_error("Base::listen returned without an error");
        }
        return PN_OK;
    }

    template <typename Base>
    int BasicServer<Base>::handle_connection(pn::UniqueSocket<connection_type> conn, pn::tcp::BufReceiver& buf_receiver) {
        bool keep_alive = true;
        bool websocket = false;
        while (conn && keep_alive) {
            HTTPRequest req;
            if (req.parse(*conn, buf_receiver, this->header_climit, this->header_name_rlimit, this->header_value_rlimit) == PN_ERROR) {
                uint16_t resp_status_code;
                switch (get_last_error()) {
                case PW_ENET:
                    resp_status_code = 500;
                    break;

                case PW_EWEB:
                    resp_status_code = 400;
                    break;

                default:
                    throw std::logic_error("Invalid error");
                }
                handle_error(*conn, resp_status_code, false);
                return PN_ERROR;
            }

            HTTPHeaders::const_iterator connection_it;
            if ((connection_it = req.headers.find("Connection")) != req.headers.end()) {
                std::vector<std::string> split_connection = string::split_and_trim(string::to_lower_copy(connection_it->second), ',');
                if (req.http_version == "HTTP/1.1") {
                    keep_alive = std::find(split_connection.begin(), split_connection.end(), "close") == split_connection.end();

                    HTTPHeaders::const_iterator upgrade_it;
                    if (std::find(split_connection.begin(), split_connection.end(), "upgrade") != split_connection.end() && (upgrade_it = req.headers.find("Upgrade")) != req.headers.end()) {
                        std::vector<std::string> split_upgrade = string::split_and_trim(string::to_lower_copy(upgrade_it->second), ',');
                        if (req.method == "GET" && std::find(split_upgrade.begin(), split_upgrade.end(), "websocket") != split_upgrade.end()) {
                            websocket = true;
                        } else {
                            if (handle_error(*conn, 501, keep_alive, req.method == "HEAD", req.http_version) == PN_ERROR) {
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
                } else if (route.second.wildcard && string::starts_with(req.target, route.first) && route.first.size() > ws_route_target.size()) {
                    ws_route_target = route.first;
                }
            }

            std::string http_route_target;
            for (const auto& route : routes) {
                if (route.first == req.target) {
                    http_route_target = route.first;
                    break;
                } else if (route.second.wildcard && string::starts_with(req.target, route.first) && route.first.size() > http_route_target.size()) {
                    http_route_target = route.first;
                }
            }

            if (websocket) {
                if (!ws_route_target.empty()) {
                    HTTPResponse resp;
                    try {
                        resp = ws_routes[ws_route_target].on_connect(*conn, req, ws_routes[ws_route_target].data);
                    } catch (...) {
                        if (handle_error(*conn, 500, keep_alive, false, req.http_version) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        continue;
                    }

                    if (!resp.headers.count("Server")) {
                        resp.headers["Server"] = PW_SERVER_CLIENT_NAME;
                    }

                    if (resp.status_code == 101) {
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
                            std::vector<std::string> split_websocket_version = string::split_and_trim(websocket_version_it->second, ',');

                            bool found_version = false;
                            for (auto& version : split_websocket_version) {
                                if (version == PW_WS_VERSION) {
                                    found_version = true;
                                    break;
                                }
                            }

                            if (found_version) {
                                resp.headers["Sec-WebSocket-Version"] = PW_WS_VERSION;
                            } else {
                                if (handle_error(*conn, 501, keep_alive, false, req.http_version) == PN_ERROR) {
                                    return PN_ERROR;
                                }
                                continue;
                            }
                        }

                        HTTPHeaders::const_iterator websocket_key_it;
                        if (!resp.headers.count("Sec-WebSocket-Accept") && (websocket_key_it = req.headers.find("Sec-WebSocket-Key")) != req.headers.end()) {
                            std::string websocket_key = string::trim_right_copy(websocket_key_it->second);
                            websocket_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                            unsigned char digest[SHA_DIGEST_LENGTH];
                            SHA1((const unsigned char*) websocket_key.data(), websocket_key.size(), digest);
                            resp.headers["Sec-WebSocket-Accept"] = base64_encode(digest, SHA_DIGEST_LENGTH);
                        }

                        HTTPHeaders::const_iterator websocket_protocol_it;
                        if (!resp.headers.count("Sec-WebSocket-Protocol") && (websocket_protocol_it = req.headers.find("Sec-WebSocket-Protocol")) != req.headers.end()) {
                            std::vector<std::string> split_websocket_protocol = string::split(websocket_protocol_it->second, ',');
                            if (!split_websocket_protocol.empty()) {
                                resp.headers["Sec-WebSocket-Protocol"] = string::trim_copy(split_websocket_protocol.back());
                            }
                        }
                    } else if (!resp.headers.count("Connection")) {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    if (conn->send(resp) == PN_ERROR) {
                        return PN_ERROR;
                    }

                    if (resp.status_code == 101) {
                        return handle_ws_connection(std::move(conn), buf_receiver, ws_routes[ws_route_target]);
                    }
                } else if (!http_route_target.empty()) {
                    if (handle_error(*conn, 400, keep_alive, req.method == "HEAD", req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else {
                    if (handle_error(*conn, 404, keep_alive, req.method == "HEAD", req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                }
            } else {
                if (!http_route_target.empty()) {
                    HTTPResponse resp;
                    try {
                        resp = routes[http_route_target].cb(*conn, req, routes[http_route_target].data);
                    } catch (...) {
                        if (handle_error(*conn, 500, keep_alive, req.method == "HEAD", req.http_version) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        continue;
                    }

                    if (!resp.headers.count("Server")) {
                        resp.headers["Server"] = PW_SERVER_CLIENT_NAME;
                    }
                    if (!resp.headers.count("Connection")) {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    if (conn->send(resp, req.method == "HEAD") == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else if (!ws_route_target.empty()) {
                    if (handle_error(*conn, 426, {{"Connection", keep_alive ? "keep-alive, upgrade" : "close, upgrade"}, {"Upgrade", "websocket"}}, req.method == "HEAD", req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else {
                    if (handle_error(*conn, 404, keep_alive, req.method == "HEAD", req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                }
            }
        }
        return PN_OK;
    }

    template <typename Base>
    int BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, const HTTPHeaders& headers, bool head_only, const std::string& http_version) {
        HTTPResponse resp;
        try {
            resp = this->on_error(status_code);
        } catch (...) {
            resp = HTTPResponse::make_basic(500);
        }

        if (!resp.headers.count("Server")) {
            resp.headers["Server"] = PW_SERVER_CLIENT_NAME;
        }

        for (const auto& header : headers) {
            if (!resp.headers.count(header.first)) {
                resp.headers.insert(header);
            }
        }

        if (conn.send(resp, head_only) == PN_ERROR) {
            return PN_ERROR;
        }

        return PN_OK;
    }

    template <typename Base>
    int BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, bool keep_alive, bool head_only, const std::string& http_version) {
        HTTPResponse resp;
        try {
            resp = on_error(status_code);
        } catch (...) {
            resp = HTTPResponse::make_basic(500);
        }

        if (!resp.headers.count("Server")) {
            resp.headers["Server"] = PW_SERVER_CLIENT_NAME;
        }
        if (!resp.headers.count("Connection")) {
            resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
        }

        if (conn.send(resp, head_only) == PN_ERROR) {
            return PN_ERROR;
        }

        return PN_OK;
    }

    int fetch(const std::string& hostname, unsigned short port, bool secure, HTTPRequest req, HTTPResponse& resp, unsigned int max_redirects) {
        if (!req.headers.count("User-Agent")) {
            req.headers["User-Agent"] = PW_SERVER_CLIENT_NAME;
        }
        if (!req.headers.count("Host")) {
            unsigned short default_port[2] = {80, 443};
            if (port == default_port[secure]) {
                req.headers["Host"] = hostname;
            } else {
                req.headers["Host"] = hostname + ':' + std::to_string(port);
            }
        }
        if (!req.headers.count("Connection")) {
            req.headers["Connection"] = "close";
        }

        if (secure) {
            pn::UniqueSocket<pw::SecureClient> client;
            pn::tcp::BufReceiver buf_receiver;
            if (client->connect(hostname, port) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
            if (client->ssl_init(hostname) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
            if (client->ssl_connect() == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }

            if (client->send(req) == PN_ERROR) {
                return PN_ERROR;
            }

            if (resp.parse(*client, buf_receiver, req.method == "HEAD") == PN_ERROR) {
                return PN_ERROR;
            }
        } else {
            pn::UniqueSocket<pw::Client> client;
            pn::tcp::BufReceiver buf_receiver;
            if (client->connect(hostname, port) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }

            if (client->send(req) == PN_ERROR) {
                return PN_ERROR;
            }

            if (resp.parse(*client, buf_receiver, req.method == "HEAD") == PN_ERROR) {
                return PN_ERROR;
            }
        }

        HTTPHeaders::const_iterator location_it;
        if (max_redirects && resp.status_code / 100 * 100 == 300 && (location_it = resp.headers.find("Location")) != resp.headers.end()) {
            URLInfo url_info;
            if (url_info.parse(location_it->second) == PN_ERROR) {
                return PN_ERROR;
            }
            return fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", std::move(req), resp, max_redirects - 1);
        }

        return PN_OK;
    }

    int fetch(const std::string& hostname, bool secure, const HTTPRequest& req, HTTPResponse& resp, unsigned int max_redirects) {
        return fetch(hostname, secure ? 443 : 80, secure, req, resp, max_redirects);
    }

    int fetch(const std::string& method, const std::string& url, HTTPResponse& resp, const HTTPHeaders& headers, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }
        return fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", HTTPRequest(method, url_info.path_with_query_parameters(), headers, http_version), resp, max_redirects);
    }

    int fetch(const std::string& method, const std::string& url, HTTPResponse& resp, const std::vector<char>& body, const HTTPHeaders& headers, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }
        return fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", HTTPRequest(method, url_info.path_with_query_parameters(), body, headers, http_version), resp, max_redirects);
    }

    int fetch(const std::string& method, const std::string& url, HTTPResponse& resp, const std::string& body, const HTTPHeaders& headers, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }
        return fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", HTTPRequest(method, url_info.path_with_query_parameters(), body, headers, http_version), resp, max_redirects);
    }

    template class BasicConnection<pn::tcp::Connection>;
    template class BasicConnection<pn::tcp::SecureConnection>;

    template class BasicConnection<pn::tcp::Client>;
    template class BasicConnection<pn::tcp::SecureClient>;

    template class BasicServer<pn::tcp::Server>;
    template class BasicServer<pn::tcp::SecureServer>;
} // namespace pw
