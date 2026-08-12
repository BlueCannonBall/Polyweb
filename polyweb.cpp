#include "polyweb.hpp"
#ifndef _WIN32
    #include <netinet/tcp.h>
#endif
#include <algorithm>
#include <bitset>
#include <charconv>
#include <codecvt>
#include <iomanip>
#include <iterator>
#include <locale>
#include <sstream>
#include <string.h>
#include <wchar.h>

namespace pw {
    tp::ThreadPool thread_pool(std::max<unsigned int>(std::thread::hardware_concurrency(), 16));

    namespace {
        constexpr char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    } // namespace

    pn::Status ConnectionConfig::apply(pn::tcp::Connection& conn) const {
#ifdef _WIN32
        DWORD send_timeout = this->send_timeout.count();
        DWORD recv_timeout = this->recv_timeout.count();
#else
        struct timeval send_timeout;
        send_timeout.tv_sec = this->send_timeout.count() / 1000;
        send_timeout.tv_usec = (this->send_timeout.count() % 1000) * 1000;
        struct timeval recv_timeout;
        recv_timeout.tv_sec = this->recv_timeout.count() / 1000;
        recv_timeout.tv_usec = (this->recv_timeout.count() % 1000) * 1000;
#endif
        if (pn::Status result = conn.setsockopt(SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof send_timeout); !result) {
            return result;
        }
        if (pn::Status result = conn.setsockopt(SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof recv_timeout); !result) {
            return result;
        }

        int tcp_keep_alive = this->tcp_keep_alive;
        if (pn::Status result = conn.setsockopt(SOL_SOCKET, SO_KEEPALIVE, &tcp_keep_alive, sizeof tcp_keep_alive); !result) {
            return result;
        }

        int tcp_no_delay = this->tcp_no_delay;
        if (pn::Status result = conn.setsockopt(IPPROTO_TCP, TCP_NODELAY, &tcp_no_delay, sizeof tcp_no_delay); !result) {
            return result;
        }

        return {};
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
        struct tm timeinfo = {};
        std::istringstream ss(date);
        ss.imbue(std::locale("C"));
        ss >> std::get_time(&timeinfo, "%a, %d %b %Y %H:%M:%S GMT");
#ifdef _WIN32
        return _mkgmtime(&timeinfo);
#else
        return timegm(&timeinfo);
#endif
    }

    std::string base64_encode(const unsigned char* data, size_t size) {
        std::string ret;
        ret.reserve(size + (size / 3));

        size_t i = 0;
        for (; i + 3 <= size; i += 3) {
            std::bitset<24> bits((((uint32_t) data[i]) << 16) | (((uint32_t) data[i + 1]) << 8) | data[i + 2]);
            ret.insert(ret.end(),
                {
                    base64_alphabet[(bits >> 18).to_ulong()],
                    base64_alphabet[((bits >> 12) & std::bitset<24>(0x3F)).to_ulong()],
                    base64_alphabet[((bits >> 6) & std::bitset<24>(0x3F)).to_ulong()],
                    base64_alphabet[(bits & std::bitset<24>(0x3F)).to_ulong()],
                });
        }
        if (size_t leftover = size - i) {
            switch (leftover) {
            case 1: {
                std::bitset<12> bits(((uint32_t) data[i]) << 4);
                ret.insert(ret.end(),
                    {
                        base64_alphabet[(bits >> 6).to_ulong()],
                        base64_alphabet[(bits & std::bitset<12>(0x3F)).to_ulong()],
                        '=',
                        '=',
                    });
                break;
            }

            case 2: {
                std::bitset<18> bits((((uint32_t) data[i]) << 10) | (((uint32_t) data[i + 1]) << 2));
                ret.insert(ret.end(),
                    {
                        base64_alphabet[(bits >> 12).to_ulong()],
                        base64_alphabet[((bits >> 6) & std::bitset<18>(0x3F)).to_ulong()],
                        base64_alphabet[(bits & std::bitset<18>(0x3F)).to_ulong()],
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
            // A null byte is not a symbol, though strchr would answer with the alphabet's own terminator
            if (const char* ptr = c ? strchr(base64_alphabet, c) : nullptr) {
                indices.push_back(ptr - base64_alphabet);
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

    std::string status_code_to_reason_phrase(uint16_t status_code) {
        const static std::unordered_map<uint16_t, std::string> conversion_mapping = {
            {100, "Continue"},
            {101, "Switching Protocols"},
            {200, "OK"},
            {201, "Created"},
            {202, "Accepted"},
            {203, "Non-Authoritative Information"},
            {204, "No Content"},
            {205, "Reset Content"},
            {206, "Partial Content"},
            {300, "Multiple Choices"},
            {301, "Moved Permanently"},
            {302, "Found"},
            {303, "See Other"},
            {304, "Not Modified"},
            {305, "Use Proxy"},
            {307, "Temporary Redirect"},
            {400, "Bad Request"},
            {401, "Unauthorized"},
            {402, "Payment Required"},
            {403, "Forbidden"},
            {404, "Not Found"},
            {405, "Method Not Allowed"},
            {406, "Not Acceptable"},
            {407, "Proxy Authentication Required"},
            {408, "Request Time-out"},
            {409, "Conflict"},
            {410, "Gone"},
            {411, "Length Required"},
            {412, "Precondition Failed"},
            {413, "Request Entity Too Large"},
            {414, "Request-URI Too Large"},
            {415, "Unsupported Media Type"},
            {416, "Requested range not satisfiable"},
            {417, "Expectation Failed"},
            {418, "I'm a teapot"},
            {426, "Upgrade Required"},
            {500, "Internal Server Error"},
            {501, "Not Implemented"},
            {502, "Bad Gateway"},
            {503, "Service Unavailable"},
            {504, "Gateway Time-out"},
            {505, "HTTP Version not supported"},
        };

        if (auto ret_it = conversion_mapping.find(status_code); ret_it != conversion_mapping.end()) {
            return ret_it->second;
        } else if (status_code >= 100 && status_code < 600) {
            return conversion_mapping.at(status_code / 100 * 100); // Zero out last two digits
        }
        throw std::out_of_range("Invalid status code");
    }

    std::string QueryParameters::build() const {
        std::string ret;
        for (auto it = map.begin(); it != map.end(); ++it) {
            if (it != map.begin()) ret.push_back('&');
            std::string encoded_key = percent_encode(it->first, plus_as_space, false);
            std::string encoded_value = percent_encode(it->second, plus_as_space, false);
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
            // Only the first equals sign is a delimiter - the rest belong to the value
            if (size_t delimiter_pos = parameter.find('='); delimiter_pos != std::string::npos) {
                map[percent_decode(parameter.substr(0, delimiter_pos), true)] = percent_decode(parameter.substr(delimiter_pos + 1), true);
            } else {
                map[percent_decode(parameter, true)]; // Create key with empty value
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
            ret += percent_encode(path);
            if (!query_parameters->empty()) {
                ret += '?' + query_parameters.build();
            }
        }
        return ret;
    }

    pn::Status URLInfo::parse(pn::StringView url) {
        size_t offset = 0;

        size_t scheme_host_delimiter_pos;
        if ((scheme_host_delimiter_pos = url.find("://", offset)) == std::string::npos || scheme_host_delimiter_pos == offset) {
            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_URL, "parse URL scheme"));
        }
        scheme = url.substr(offset, scheme_host_delimiter_pos - offset);
        offset = scheme_host_delimiter_pos + 3;

        // A fragment belongs to none of the components that follow, and neither does anything
        // inside of it that merely looks like a delimiter
        size_t fragment_pos = url.find('#', offset);
        size_t end = fragment_pos == std::string::npos ? url.size() : fragment_pos;
        size_t host_end = std::min(url.find_first_of("/?", offset), end);

        credentials.clear();
        size_t credentials_host_delimiter_pos;
        if ((credentials_host_delimiter_pos = url.find('@', offset)) != std::string::npos &&
            credentials_host_delimiter_pos < host_end) {
            if (credentials_host_delimiter_pos == offset) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_URL, "parse URL credentials"));
            }
            credentials = percent_decode(url.substr(offset, credentials_host_delimiter_pos - offset));
            offset = credentials_host_delimiter_pos + 1;
        }

        if (host_end == offset) {
            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_URL, "parse URL host"));
        }
        host = url.substr(offset, host_end - offset);
        offset = host_end;

        // The path is kept decoded, as pw::Request keeps its target, so that handing one to the
        // other does not encode it a second time
        query_parameters->clear();
        size_t path_query_string_delimiter_pos = url.find('?', offset);
        if (path_query_string_delimiter_pos >= end) { // Also covers the absence of a query string entirely
            path = offset == end ? "/" : percent_decode(url.substr(offset, end - offset));
            return {};
        }

        if (path_query_string_delimiter_pos == offset) {
            path = '/';
        } else {
            path = percent_decode(url.substr(offset, path_query_string_delimiter_pos - offset));
        }
        offset = path_query_string_delimiter_pos + 1;

        query_parameters.parse(url.substr(offset, end - offset));
        return {};
    }

    unsigned short URLInfo::port() const {
        if (size_t hostname_port_delimiter_pos = host.find(':'); hostname_port_delimiter_pos == std::string::npos) {
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

    std::vector<char> Request::build(int parts) {
        std::vector<char> ret;

        if (parts & PW_HTTP_MESSAGE_PART_START_LINE) {
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
        }

        if (parts & PW_HTTP_MESSAGE_PART_HEADERS) {
            for (const auto& header : headers) {
                ret.insert(ret.end(), header.first.begin(), header.first.end());
                ret.insert(ret.end(), {':', ' '});
                ret.insert(ret.end(), header.second.begin(), header.second.end());
                ret.insert(ret.end(), {'\r', '\n'});
            }

            if (send_cb) {
                if (!headers.count("Transfer-Encoding")) {
                    std::string header = "Transfer-Encoding: chunked\r\n";
                    ret.insert(ret.end(), header.begin(), header.end());
                }
            } else if (!body.empty() && !headers.count("Content-Length")) {
                std::string header = "Content-Length: " + std::to_string(body.size()) + "\r\n";
                ret.insert(ret.end(), header.begin(), header.end());
            }
            ret.insert(ret.end(), {'\r', '\n'});
        }

        if (parts & PW_HTTP_MESSAGE_PART_BODY) {
            if (send_cb) {
                for (;;) {
                    if (auto chunk = send_cb(); !chunk.empty()) {
                        std::ostringstream ss;
                        ss << std::hex << chunk.size() << "\r\n";
                        std::string str = ss.str();
                        ret.insert(ret.end(), str.begin(), str.end());
                        ret.insert(ret.end(), chunk.begin(), chunk.end());
                        ret.insert(ret.end(), {'\r', '\n'});
                    } else {
                        static constexpr char last_chunk[] = "0\r\n\r\n";
                        ret.insert(ret.end(), last_chunk, last_chunk + 5);
                        break;
                    }
                }
            } else {
                ret.insert(ret.end(), body.begin(), body.end());
            }
        }

        return ret;
    }

    pn::Status Request::build(pn::tcp::Connection& conn, int parts) {
        auto data = build(send_cb ? parts & ~PW_HTTP_MESSAGE_PART_BODY : parts);
        if (pn::Result<size_t> result = conn.sendall(data.data(), data.size()); !result) {
            return std::unexpected(result.error());
        } else if (*result != data.size()) {
            return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write HTTP message"});
        }

        if ((parts & PW_HTTP_MESSAGE_PART_BODY) && send_cb) {
            for (;;) {
                auto chunk = send_cb();
                if (!chunk.empty()) {
                    std::ostringstream ss;
                    ss << std::hex << chunk.size() << "\r\n";
                    std::string str = ss.str();
                    chunk.insert(chunk.begin(), str.begin(), str.end());
                    chunk.insert(chunk.end(), {'\r', '\n'});
                    if (pn::Result<size_t> result = conn.sendall(chunk.data(), chunk.size()); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != chunk.size()) {
                        return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write HTTP chunk"});
                    }
                } else {
                    static constexpr char last_chunk[] = "0\r\n\r\n";
                    if (pn::Result<size_t> result = conn.sendall(last_chunk, 5); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != 5) {
                        return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write HTTP chunk terminator"});
                    }
                    break;
                }
            }
        }

        return {};
    }

    pn::Status Request::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, int parts, const MessageConfig& config) {
        const auto& [header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit] = config;
        if (parts & PW_HTTP_MESSAGE_PART_START_LINE) {
            method.clear();
            if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(method), ' ', misc_rlimit); !result) {
                return result;
            }
            if (method.empty()) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP request method"));
            }

            target.clear();
            if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(target), ' ', misc_rlimit); !result) {
                return result;
            }
            if (target.empty()) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP request target"));
            }

            query_parameters->clear();
            if (auto query_string_begin = std::find(target.begin(), target.end(), '?'); query_string_begin != target.end()) {
                if (std::next(query_string_begin) != target.end()) {
                    query_parameters.parse(std::string(std::next(query_string_begin), target.end()));
                }
                target.resize(std::distance(target.begin(), query_string_begin));
            }
            target = percent_decode(target);

            http_version.clear();
            if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(http_version), "\r\n", misc_rlimit); !result) {
                return result;
            }
            if (http_version.empty()) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP request version"));
            }
        }

        if (parts & PW_HTTP_MESSAGE_PART_HEADERS) {
            headers.clear();

            char crlf[2];
            if (pn::Result<size_t> result = buf_receiver.recvall(conn, crlf, sizeof crlf); !result) {
                return std::unexpected(result.error());
            } else if (*result != sizeof crlf) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP header terminator"));
            }

            if (memcmp("\r\n", crlf, sizeof crlf)) {
                buf_receiver.rewind(crlf, sizeof crlf);

                for (unsigned int i = 0;; ++i) {
                    if (i >= header_climit) {
                        return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "parse HTTP header count"));
                    }

                    std::string header_name;
                    if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(header_name), ':', header_name_rlimit); !result) {
                        return result;
                    }
                    if (header_name.empty()) {
                        return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP header name"));
                    }

                    std::string header_value;
                    if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(header_value), "\r\n", header_value_rlimit); !result) {
                        return result;
                    }
                    string::trim(header_value);

                    headers.insert_or_assign(std::move(header_name), std::move(header_value));

                    if (pn::Result<size_t> result = buf_receiver.recvall(conn, crlf, sizeof crlf); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != sizeof crlf) {
                        return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP header terminator"));
                    }

                    if (!memcmp("\r\n", crlf, sizeof crlf)) {
                        break;
                    }
                    buf_receiver.rewind(crlf, sizeof crlf);
                }
            }
        }

        if (parts & PW_HTTP_MESSAGE_PART_BODY) {
            body.clear();
            if (auto transfer_encoding_it = headers.find("Transfer-Encoding"); transfer_encoding_it != headers.end()) {
                if (string::iequals(transfer_encoding_it->second, "chunked")) {
                    unsigned long long chunk_size;
                    do {
                        std::string chunk_size_string;
                        if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(chunk_size_string), "\r\n", misc_rlimit); !result) {
                            return result;
                        }
                        if (chunk_size_string.empty()) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP chunk size"));
                        }
                        if (auto result = std::from_chars(chunk_size_string.data(), chunk_size_string.data() + chunk_size_string.size(), chunk_size, 16);
                            result.ec != std::errc {} || result.ptr != chunk_size_string.data() + chunk_size_string.size()) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP chunk size"));
                        }

                        if (chunk_size) {
                            if (recv_cb) {
                                for (unsigned long long received = 0; received < chunk_size;) {
                                    std::vector<char> chunk(std::min<unsigned long long>(chunk_size - received, body_chunk_rlimit));
                                    if (pn::Result<size_t> result = buf_receiver.recvall(conn, chunk.data(), chunk.size()); !result) {
                                        return std::unexpected(result.error());
                                    } else if (*result != chunk.size()) {
                                        return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP chunk"));
                                    }

                                    received += chunk.size();
                                    if (!recv_cb(std::move(chunk))) {
                                        return std::unexpected(pn::make_polynet_error(pn::PN_ERROR_USER_CALLBACK, "process HTTP body callback"));
                                    }
                                }
                            } else {
                                size_t end = body.size();
                                if (chunk_size > body_rlimit - end) {
                                    return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "read HTTP body"));
                                }
                                body.resize(end + chunk_size);
                                if (pn::Result<size_t> result = buf_receiver.recvall(conn, &body[end], chunk_size); !result) {
                                    return std::unexpected(result.error());
                                } else if (*result != chunk_size) {
                                    body.resize(end + *result);
                                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP chunk"));
                                }
                            }
                        }

                        char crlf[2];
                        if (pn::Result<size_t> result = buf_receiver.recvall(conn, crlf, sizeof crlf); !result) {
                            return std::unexpected(result.error());
                        } else if (*result != sizeof crlf) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP chunk terminator"));
                        }
                    } while (chunk_size);
                } else { // Only chunked transfer encoding is supported atm
                    return std::unexpected(make_polyweb_error(PW_ERROR_UNSUPPORTED, "parse HTTP transfer encoding"));
                }
            } else if (auto content_len_it = headers.find("Content-Length"); content_len_it != headers.end()) {
                unsigned long long content_len;
                try {
                    content_len = std::stoull(content_len_it->second);
                } catch (...) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP content length"));
                }

                if (content_len) {
                    if (recv_cb) {
                        for (unsigned long long received = 0; received < content_len;) {
                            std::vector<char> chunk(std::min<unsigned long long>(content_len - received, body_chunk_rlimit));
                            if (pn::Result<size_t> result = buf_receiver.recvall(conn, chunk.data(), chunk.size()); !result) {
                                return std::unexpected(result.error());
                            } else if (*result != chunk.size()) {
                                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP body"));
                            }

                            received += chunk.size();
                            if (!recv_cb(std::move(chunk))) {
                                return std::unexpected(pn::make_polynet_error(pn::PN_ERROR_USER_CALLBACK, "process HTTP body callback"));
                            }
                        }
                    } else {
                        if (content_len > body_rlimit) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "read HTTP body"));
                        }
                        body.resize(content_len);
                        if (pn::Result<size_t> result = buf_receiver.recvall(conn, body.data(), content_len); !result) {
                            return std::unexpected(result.error());
                        } else if (*result != content_len) {
                            body.resize(*result);
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP body"));
                        }
                    }
                }
            }
        }

        return {};
    }

    std::vector<char> Response::build(int parts) {
        std::vector<char> ret;

        if (parts & PW_HTTP_MESSAGE_PART_START_LINE) {
            ret.insert(ret.end(), http_version.begin(), http_version.end());
            ret.push_back(' ');
            std::string status_code_string = std::to_string(status_code);
            ret.insert(ret.end(), status_code_string.begin(), status_code_string.end());
            ret.push_back(' ');
            ret.insert(ret.end(), reason_phrase.begin(), reason_phrase.end());
            ret.insert(ret.end(), {'\r', '\n'});
        }

        if (parts & PW_HTTP_MESSAGE_PART_HEADERS) {
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

            if (send_cb) {
                if (!headers.count("Transfer-Encoding")) {
                    std::string header = "Transfer-Encoding: chunked\r\n";
                    ret.insert(ret.end(), header.begin(), header.end());
                }
            } else if (!headers.count("Content-Length")) {
                std::string header = "Content-Length: " + std::to_string(body.size()) + "\r\n";
                ret.insert(ret.end(), header.begin(), header.end());
            }
            ret.insert(ret.end(), {'\r', '\n'});
        }

        if (parts & PW_HTTP_MESSAGE_PART_BODY) {
            if (send_cb) {
                for (;;) {
                    if (auto chunk = send_cb(); !chunk.empty()) {
                        std::ostringstream ss;
                        ss << std::hex << chunk.size() << "\r\n";
                        std::string str = ss.str();
                        ret.insert(ret.end(), str.begin(), str.end());
                        ret.insert(ret.end(), chunk.begin(), chunk.end());
                        ret.insert(ret.end(), {'\r', '\n'});
                    } else {
                        static constexpr char last_chunk[] = "0\r\n\r\n";
                        ret.insert(ret.end(), last_chunk, last_chunk + 5);
                        break;
                    }
                }
            } else {
                ret.insert(ret.end(), body.begin(), body.end());
            }
        }

        return ret;
    }

    pn::Status Response::build(pn::tcp::Connection& conn, int parts) {
        auto data = build(send_cb ? parts & ~PW_HTTP_MESSAGE_PART_BODY : parts);
        if (pn::Result<size_t> result = conn.sendall(data.data(), data.size()); !result) {
            return std::unexpected(result.error());
        } else if (*result != data.size()) {
            return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write HTTP message"});
        }

        if ((parts & PW_HTTP_MESSAGE_PART_BODY) && send_cb) {
            for (;;) {
                auto chunk = send_cb();
                if (!chunk.empty()) {
                    std::ostringstream ss;
                    ss << std::hex << chunk.size() << "\r\n";
                    std::string str = ss.str();
                    chunk.insert(chunk.begin(), str.begin(), str.end());
                    chunk.insert(chunk.end(), {'\r', '\n'});
                    if (pn::Result<size_t> result = conn.sendall(chunk.data(), chunk.size()); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != chunk.size()) {
                        return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write HTTP chunk"});
                    }
                } else {
                    static constexpr char last_chunk[] = "0\r\n\r\n";
                    if (pn::Result<size_t> result = conn.sendall(last_chunk, 5); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != 5) {
                        return std::unexpected(pn::Error {std::make_error_code(std::errc::io_error), "write HTTP chunk terminator"});
                    }
                    break;
                }
            }
        }

        return {};
    }

    pn::Status Response::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, int parts, const MessageConfig& config) {
        const auto& [header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit] = config;
        if (parts & PW_HTTP_MESSAGE_PART_START_LINE) {
            http_version.clear();
            if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(http_version), ' ', misc_rlimit); !result) {
                return result;
            }
            if (http_version.empty()) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP response version"));
            }

            std::string status_code_string;
            if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(status_code_string), ' ', misc_rlimit); !result) {
                return result;
            }
            if (status_code_string.empty()) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP response status code"));
            }
            if (auto result = std::from_chars(status_code_string.data(), status_code_string.data() + status_code_string.size(), status_code);
                result.ec != std::errc {} || result.ptr != status_code_string.data() + status_code_string.size() || status_code > 999) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP status code"));
            }

            reason_phrase.clear();
            if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(reason_phrase), "\r\n", misc_rlimit); !result) {
                return result;
            }
            if (reason_phrase.empty()) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP response reason phrase"));
            }
        }

        if (parts & PW_HTTP_MESSAGE_PART_HEADERS) {
            headers.clear();

            char crlf[2];
            if (pn::Result<size_t> result = buf_receiver.recvall(conn, crlf, sizeof crlf); !result) {
                return std::unexpected(result.error());
            } else if (*result != sizeof crlf) {
                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP header terminator"));
            }

            if (memcmp("\r\n", crlf, sizeof crlf)) {
                buf_receiver.rewind(crlf, sizeof crlf);

                for (unsigned int i = 0;; ++i) {
                    if (i >= header_climit) {
                        return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "parse HTTP header count"));
                    }

                    std::string header_name;
                    if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(header_name), ':', header_name_rlimit); !result) {
                        return result;
                    }
                    if (header_name.empty()) {
                        return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP header name"));
                    }

                    std::string header_value;
                    if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(header_value), "\r\n", header_value_rlimit); !result) {
                        return result;
                    }
                    string::trim(header_value);

                    headers.insert_or_assign(std::move(header_name), std::move(header_value));

                    if (pn::Result<size_t> result = buf_receiver.recvall(conn, crlf, sizeof crlf); !result) {
                        return std::unexpected(result.error());
                    } else if (*result != sizeof crlf) {
                        return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP header terminator"));
                    }

                    if (!memcmp("\r\n", crlf, sizeof crlf)) {
                        break;
                    }
                    buf_receiver.rewind(crlf, sizeof crlf);
                }
            }
        }

        if (parts & PW_HTTP_MESSAGE_PART_BODY) {
            body.clear();
            if (auto transfer_encoding_it = headers.find("Transfer-Encoding"); transfer_encoding_it != headers.end()) {
                if (string::iequals(transfer_encoding_it->second, "chunked")) {
                    unsigned long long chunk_size;
                    do {
                        std::string chunk_size_string;
                        if (pn::Status result = detail::recv_until(conn, buf_receiver, std::back_inserter(chunk_size_string), "\r\n", misc_rlimit); !result) {
                            return result;
                        }
                        if (chunk_size_string.empty()) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP chunk size"));
                        }
                        if (auto result = std::from_chars(chunk_size_string.data(), chunk_size_string.data() + chunk_size_string.size(), chunk_size, 16);
                            result.ec != std::errc {} || result.ptr != chunk_size_string.data() + chunk_size_string.size()) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP chunk size"));
                        }

                        if (chunk_size) {
                            if (recv_cb) {
                                for (unsigned long long received = 0; received < chunk_size;) {
                                    std::vector<char> chunk(std::min<unsigned long long>(chunk_size - received, body_chunk_rlimit));
                                    if (pn::Result<size_t> result = buf_receiver.recvall(conn, chunk.data(), chunk.size()); !result) {
                                        return std::unexpected(result.error());
                                    } else if (*result != chunk.size()) {
                                        return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP chunk"));
                                    }

                                    received += chunk.size();
                                    if (!recv_cb(std::move(chunk))) {
                                        return std::unexpected(pn::make_polynet_error(pn::PN_ERROR_USER_CALLBACK, "process HTTP body callback"));
                                    }
                                }
                            } else {
                                size_t end = body.size();
                                if (chunk_size > body_rlimit - end) {
                                    return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "read HTTP body"));
                                }
                                body.resize(end + chunk_size);
                                if (pn::Result<size_t> result = buf_receiver.recvall(conn, &body[end], chunk_size); !result) {
                                    return std::unexpected(result.error());
                                } else if (*result != chunk_size) {
                                    body.resize(end + *result);
                                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP chunk"));
                                }
                            }
                        }

                        char crlf[2];
                        if (pn::Result<size_t> result = buf_receiver.recvall(conn, crlf, sizeof crlf); !result) {
                            return std::unexpected(result.error());
                        } else if (*result != sizeof crlf) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP chunk terminator"));
                        }
                    } while (chunk_size);
                } else { // Only chunked transfer encoding is supported atm
                    return std::unexpected(make_polyweb_error(PW_ERROR_UNSUPPORTED, "parse HTTP transfer encoding"));
                }
            } else if (auto content_len_it = headers.find("Content-Length"); content_len_it != headers.end()) {
                unsigned long long content_len;
                try {
                    content_len = std::stoull(content_len_it->second);
                } catch (...) {
                    return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "parse HTTP content length"));
                }

                if (content_len) {
                    if (recv_cb) {
                        for (unsigned long long received = 0; received < content_len;) {
                            std::vector<char> chunk(std::min<unsigned long long>(content_len - received, body_chunk_rlimit));
                            if (pn::Result<size_t> result = buf_receiver.recvall(conn, chunk.data(), chunk.size()); !result) {
                                return std::unexpected(result.error());
                            } else if (*result != chunk.size()) {
                                return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP body"));
                            }

                            received += chunk.size();
                            if (!recv_cb(std::move(chunk))) {
                                return std::unexpected(pn::make_polynet_error(pn::PN_ERROR_USER_CALLBACK, "process HTTP body callback"));
                            }
                        }
                    } else {
                        if (content_len > body_rlimit) {
                            return std::unexpected(make_polyweb_error(PW_ERROR_LIMIT_EXCEEDED, "read HTTP body"));
                        }
                        body.resize(content_len);
                        if (pn::Result<size_t> result = buf_receiver.recvall(conn, body.data(), content_len); !result) {
                            return std::unexpected(result.error());
                        } else if (*result != content_len) {
                            body.resize(*result);
                            return std::unexpected(make_polyweb_error(PW_ERROR_INVALID_HTTP, "read HTTP body"));
                        }
                    }
                }
            }
        }

        return {};
    }
} // namespace pw
