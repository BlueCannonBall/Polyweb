#include "polyweb.hpp"

namespace pw {
    int FetchConfig::configure_sockopts(pn::tcp::Connection& conn) const {
#ifdef _WIN32
        DWORD send_timeout = config.send_timeout.count();
        DWORD recv_timeout = config.send_timeout.count();
#else
        struct timeval send_timeout;
        send_timeout.tv_sec = this->send_timeout.count() / 1000;
        send_timeout.tv_usec = (this->send_timeout.count() % 1000) * 1000;
        struct timeval recv_timeout;
        recv_timeout.tv_sec = this->recv_timeout.count() / 1000;
        recv_timeout.tv_usec = (this->recv_timeout.count() % 1000) * 1000;
#endif
        if (conn.setsockopt(SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof send_timeout) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }
        if (conn.setsockopt(SOL_SOCKET, SO_RCVTIMEO, &recv_timeout, sizeof recv_timeout) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }

        int tcp_keep_alive = this->tcp_keep_alive;
        if (conn.setsockopt(SOL_SOCKET, SO_KEEPALIVE, &tcp_keep_alive, sizeof(int)) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }

        return PN_OK;
    }

    int FetchConfig::configure_ssl(pn::tcp::SecureClient& client, const std::string& hostname) const {
        if (client.ssl_init(hostname, verify_mode, ca_file, ca_path) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }
        return PN_OK;
    }

    int fetch(const std::string& hostname, unsigned short port, bool secure, HTTPRequest req, HTTPResponse& resp, const FetchConfig& config, unsigned int max_redirects) {
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
            pn::UniqueSocket<SecureClient> client;
            pn::tcp::BufReceiver buf_receiver(config.buffer_size);
            if (client->connect(hostname, port) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
            if (config.configure_sockopts(*client) == PN_ERROR) {
                return PN_ERROR;
            }
            if (config.configure_ssl(*client, hostname) == PN_ERROR) {
                return PN_ERROR;
            }
            if (client->ssl_connect() == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }

            if (client->send(req) == PN_ERROR) {
                return PN_ERROR;
            }

            if (resp.parse(*client, buf_receiver, req.method == "HEAD", config.header_climit, config.header_name_rlimit, config.header_value_rlimit, config.body_chunk_rlimit, config.body_rlimit, config.misc_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }
        } else {
            pn::UniqueSocket<Client> client;
            pn::tcp::BufReceiver buf_receiver;
            if (client->connect(hostname, port) == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
            if (config.configure_sockopts(*client) == PN_ERROR) {
                return PN_ERROR;
            }

            if (client->send(req) == PN_ERROR) {
                return PN_ERROR;
            }

            if (resp.parse(*client, buf_receiver, req.method == "HEAD", config.header_climit, config.header_name_rlimit, config.header_value_rlimit, config.body_chunk_rlimit, config.body_rlimit, config.misc_rlimit) == PN_ERROR) {
                return PN_ERROR;
            }
        }

        HTTPHeaders::const_iterator location_it;
        if (max_redirects && resp.status_code_category() == 300 && (location_it = resp.headers.find("Location")) != resp.headers.end()) {
            URLInfo url_info;
            if (url_info.parse(location_it->second) == PN_ERROR) {
                return PN_ERROR;
            }
            if (!url_info.credentials.empty()) {
                req.headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
            }
            return fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", std::move(req), resp, config, max_redirects - 1);
        }

        return PN_OK;
    }

    int fetch(const std::string& hostname, bool secure, const HTTPRequest& req, HTTPResponse& resp, const FetchConfig& config, unsigned int max_redirects) {
        return fetch(hostname, secure ? 443 : 80, secure, req, resp, config, max_redirects);
    }

    int fetch(const std::string& url, HTTPResponse& resp, const HTTPHeaders& headers, const FetchConfig& config, unsigned int max_redirects, const std::string& http_version) {
        return fetch("GET", url, resp, headers, config, max_redirects, http_version);
    }

    int fetch(const std::string& method, const std::string& url, HTTPResponse& resp, const HTTPHeaders& headers, const FetchConfig& config, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPRequest req(method, url_info.path, url_info.query_parameters, headers, http_version);
        if (!url_info.credentials.empty() && !req.headers.count("WWW-Authenticate")) {
            req.headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", std::move(req), resp, config, max_redirects);
    }

    int fetch(const std::string& method, const std::string& url, HTTPResponse& resp, const std::vector<char>& body, const HTTPHeaders& headers, const FetchConfig& config, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPRequest req(method, url_info.path, body, headers, http_version);
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("WWW-Authenticate")) {
            req.headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", std::move(req), resp, config, max_redirects);
    }

    int fetch(const std::string& method, const std::string& url, HTTPResponse& resp, const std::string& body, const HTTPHeaders& headers, const FetchConfig& config, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPRequest req(method, url_info.path, body, headers, http_version);
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("WWW-Authenticate")) {
            req.headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", std::move(req), resp, config, max_redirects);
    }

    int proxied_fetch(const std::string& hostname, unsigned short port, bool secure, const std::string& proxy_url, HTTPRequest req, HTTPResponse& resp, const FetchConfig& config, unsigned int max_redirects) {
        URLInfo proxy_url_info;
        if (proxy_url_info.parse(proxy_url) == PN_ERROR) {
            return PN_ERROR;
        }
        if (proxy_url_info.scheme != "http") {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        HTTPRequest connect_req("CONNECT",
            hostname + ':' + std::to_string(port),
            {
                {"Host", hostname + ':' + std::to_string(port)},
                {"Connection", "close"},
            });
        if (!proxy_url_info.credentials.empty() && !connect_req.headers.count("Proxy-Authorization")) {
            connect_req.headers["Proxy-Authorization"] = "basic " + base64_encode(proxy_url_info.credentials.data(), proxy_url_info.credentials.size());
        }

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

        pn::UniqueSocket<SecureClient> client;
        pn::tcp::BufReceiver buf_receiver;
        if (client->connect(proxy_url_info.hostname(), proxy_url_info.port()) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        }
        if (config.configure_sockopts(*client) == PN_ERROR) {
            return PN_ERROR;
        }

        if (client->send(connect_req) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPResponse connect_resp;
        if (connect_resp.parse(*client, buf_receiver, false, config.header_climit, config.header_name_rlimit, config.header_value_rlimit, config.body_chunk_rlimit, config.body_rlimit, config.misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        } else if (connect_resp.status_code_category() != 200) {
            detail::set_last_error(PW_EWEB);
            return PN_ERROR;
        }

        if (secure) {
            if (config.configure_ssl(*client, hostname) == PN_ERROR) {
                return PN_ERROR;
            }
            if (client->ssl_connect() == PN_ERROR) {
                detail::set_last_error(PW_ENET);
                return PN_ERROR;
            }
        }

        if (client->send(req) == PN_ERROR) {
            return PN_ERROR;
        }

        if (resp.parse(*client, buf_receiver, req.method == "HEAD", config.header_climit, config.header_name_rlimit, config.header_value_rlimit, config.body_chunk_rlimit, config.body_rlimit, config.misc_rlimit) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPHeaders::const_iterator location_it;
        if (max_redirects && resp.status_code_category() == 300 && (location_it = resp.headers.find("Location")) != resp.headers.end()) {
            URLInfo url_info;
            if (url_info.parse(location_it->second) == PN_ERROR) {
                return PN_ERROR;
            }
            if (!url_info.credentials.empty()) {
                req.headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
            }
            return proxied_fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", proxy_url, std::move(req), resp, config, max_redirects - 1);
        }

        return PN_OK;
    }

    int proxied_fetch(const std::string& hostname, bool secure, const std::string& proxy_url, const HTTPRequest& req, HTTPResponse& resp, const FetchConfig& config, unsigned int max_redirects) {
        return proxied_fetch(hostname, secure ? 443 : 80, secure, proxy_url, req, resp, config, max_redirects);
    }

    int proxied_fetch(const std::string& url, const std::string& proxy_url, HTTPResponse& resp, const HTTPHeaders& headers, const FetchConfig& config, unsigned int max_redirects, const std::string& http_version) {
        return proxied_fetch("GET", url, proxy_url, resp, headers, config, max_redirects, http_version);
    }

    int proxied_fetch(const std::string& method, const std::string& url, const std::string& proxy_url, HTTPResponse& resp, const HTTPHeaders& headers, const FetchConfig& config, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPRequest req(method, url_info.path, url_info.query_parameters, headers, http_version);
        if (!url_info.credentials.empty() && !req.headers.count("WWW-Authenticate")) {
            req.headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return proxied_fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", proxy_url, std::move(req), resp, config, max_redirects);
    }

    int proxied_fetch(const std::string& method, const std::string& url, const std::string& proxy_url, HTTPResponse& resp, const std::vector<char>& body, const HTTPHeaders& headers, const FetchConfig& config, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPRequest req(method, url_info.path, body, headers, http_version);
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("WWW-Authenticate")) {
            req.headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return proxied_fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", proxy_url, std::move(req), resp, config, max_redirects);
    }

    int proxied_fetch(const std::string& method, const std::string& url, const std::string& proxy_url, HTTPResponse& resp, const std::string& body, const HTTPHeaders& headers, const FetchConfig& config, unsigned int max_redirects, const std::string& http_version) {
        URLInfo url_info;
        if (url_info.parse(url) == PN_ERROR) {
            return PN_ERROR;
        }

        HTTPRequest req(method, url_info.path, body, headers, http_version);
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("WWW-Authenticate")) {
            req.headers["WWW-Authenticate"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return proxied_fetch(url_info.hostname(), url_info.port(), url_info.scheme == "https", proxy_url, std::move(req), resp, config, max_redirects);
    }
}; // namespace pw
