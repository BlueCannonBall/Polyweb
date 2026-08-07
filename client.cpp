#include "polyweb.hpp"

namespace pw {
    namespace {
        pn::Result<const pn::TLSContext*> default_tls_context() {
            static std::mutex mutex;
            static pn::TLSContext context;

            std::lock_guard<std::mutex> lock(mutex);
            if (!context.is_valid()) {
                if (pn::Status result = context.init_client(); !result) {
                    return std::unexpected(result.error());
                }
            }
            return &context;
        }
    } // namespace

    pn::Result<const pn::TLSContext*> ClientConfig::resolve_tls_context() const {
        if (tls_context) {
            return tls_context;
        }
        return default_tls_context();
    }

    pn::Status fetch(pn::StringView hostname, unsigned short port, bool secure, Request req, Response& resp, const ClientConfig& config) {
        if (!req.headers.count("User-Agent")) {
            req.headers["User-Agent"] = PW_AGENT_NAME;
        }
        if (!req.headers.count("Host")) {
            unsigned short default_port[2] = {80, 443};
            if (port == default_port[secure]) {
                req.headers["Host"] = hostname;
            } else {
                req.headers["Host"] = std::string(hostname) + ':' + std::to_string(port);
            }
        }
        if (!req.headers.count("Connection")) {
            req.headers["Connection"] = "close";
        }

        int resp_parts = req.method == "HEAD" ? PW_HTTP_MESSAGE_PART_HEAD : PW_HTTP_MESSAGE_PART_ALL;
        if (secure) {
            TLSClient client;
            client.http_config = config.http;
            pn::Error config_error;
            if (pn::Status result = client.connect(hostname, port, [&config, &config_error](auto& client) {
                    if (pn::Status result = config.tcp.apply(client); !result) {
                        config_error = result.error();
                        return false;
                    }
                    return true;
                });
                !result) {
                if (config_error) {
                    return std::unexpected(config_error);
                }
                return result;
            }
            const pn::TLSContext* context;
            if (pn::Result<const pn::TLSContext*> result = config.resolve_tls_context(); !result) {
                return std::unexpected(result.error());
            } else {
                context = *result;
            }
            if (pn::Status result = client.tls_init(*context, hostname); !result) {
                return result;
            }
            if (pn::Status result = client.tls_connect(); !result) {
                return result;
            }

            if (pn::Status result = client.send(std::move(req)); !result) {
                return result;
            }

            if (pn::Status result = client.recv(resp, resp_parts); !result) {
                return result;
            }
        } else {
            Client client;
            client.http_config = config.http;
            pn::Error config_error;
            if (pn::Status result = client.connect(hostname, port, [&config, &config_error](auto& client) {
                    if (pn::Status result = config.tcp.apply(client); !result) {
                        config_error = result.error();
                        return false;
                    }
                    return true;
                });
                !result) {
                if (config_error) {
                    return std::unexpected(config_error);
                }
                return result;
            }

            if (pn::Status result = client.send(std::move(req)); !result) {
                return result;
            }

            if (pn::Status result = client.recv(resp, resp_parts); !result) {
                return result;
            }
        }

        return {};
    }

    pn::Status fetch(pn::StringView url, Response& resp, Headers headers, const ClientConfig& config, std::string http_version) {
        return fetch("GET", url, resp, std::move(headers), config, std::move(http_version));
    }

    pn::Status fetch(std::string method, pn::StringView url, Response& resp, Headers headers, const ClientConfig& config, std::string http_version) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        Request req(std::move(method), std::move(url_info.path), std::move(url_info.query_parameters), std::move(headers), std::move(http_version));
        if (!url_info.credentials.empty() && !req.headers.count("Authorization")) {
            req.headers["Authorization"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return fetch(url_info.hostname(), url_info.port(), string::iequals(url_info.scheme, "https"), std::move(req), resp, config);
    }

    pn::Status fetch(std::string method, pn::StringView url, Response& resp, std::vector<char> body, Headers headers, const ClientConfig& config, std::string http_version) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        Request req(std::move(method), std::move(url_info.path), std::move(body), std::move(headers), std::move(http_version));
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("Authorization")) {
            req.headers["Authorization"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return fetch(url_info.hostname(), url_info.port(), string::iequals(url_info.scheme, "https"), std::move(req), resp, config);
    }

    pn::Status fetch(std::string method, pn::StringView url, Response& resp, pn::StringView body, Headers headers, const ClientConfig& config, std::string http_version) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        Request req(std::move(method), std::move(url_info.path), body, std::move(headers), std::move(http_version));
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("Authorization")) {
            req.headers["Authorization"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return fetch(url_info.hostname(), url_info.port(), string::iequals(url_info.scheme, "https"), std::move(req), resp, config);
    }

    pn::Status fetch(std::string method, pn::StringView url, Response& resp, std::move_only_function<std::vector<char>()> body_cb, Headers headers, const ClientConfig& config, std::string http_version) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        Request req(std::move(method), std::move(url_info.path), std::move(body_cb), std::move(headers), std::move(http_version));
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("Authorization")) {
            req.headers["Authorization"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return fetch(url_info.hostname(), url_info.port(), string::iequals(url_info.scheme, "https"), std::move(req), resp, config);
    }

    pn::Status proxied_fetch(pn::StringView hostname, unsigned short port, bool secure, pn::StringView proxy_url, Request req, Response& resp, const ClientConfig& config) {
        URLInfo proxy_url_info;
        if (pn::Status result = proxy_url_info.parse(proxy_url); !result) {
            return result;
        }
        if (proxy_url_info.scheme != "http") {
            return std::unexpected(make_polyweb_error(PW_ERROR_UNSUPPORTED, "use non-HTTP proxy"));
        }

        Request connect_req("CONNECT",
            std::string(hostname) + ':' + std::to_string(port),
            {
                {"Host", std::string(hostname) + ':' + std::to_string(port)},
                {"Connection", "close"},
            });
        if (!proxy_url_info.credentials.empty() && !connect_req.headers.count("Proxy-Authorization")) {
            connect_req.headers["Proxy-Authorization"] = "basic " + base64_encode(proxy_url_info.credentials.data(), proxy_url_info.credentials.size());
        }

        if (!req.headers.count("User-Agent")) {
            req.headers["User-Agent"] = PW_AGENT_NAME;
        }
        if (!req.headers.count("Host")) {
            unsigned short default_port[2] = {80, 443};
            if (port == default_port[secure]) {
                req.headers["Host"] = hostname;
            } else {
                req.headers["Host"] = std::string(hostname) + ':' + std::to_string(port);
            }
        }
        if (!req.headers.count("Connection")) {
            req.headers["Connection"] = "close";
        }

        TLSClient client;
        client.http_config = config.http;
        client.buf_receiver.capacity = 0;
        pn::Error config_error;
        if (pn::Status result = client.connect(proxy_url_info.hostname(), proxy_url_info.port(), [&config, &config_error](auto& client) {
                if (pn::Status result = config.tcp.apply(client); !result) {
                    config_error = result.error();
                    return false;
                }
                return true;
            });
            !result) {
            if (config_error) {
                return std::unexpected(config_error);
            }
            return result;
        }

        if (pn::Status result = client.send(std::move(connect_req)); !result) {
            return result;
        }

        Response connect_resp;
        if (pn::Status result = client.recv(connect_resp, false); !result) {
            return result;
        } else if (connect_resp.status_code_category() != 200) {
            return std::unexpected(make_polyweb_error(PW_ERROR_PROXY_CONNECT_REJECTED, "perform HTTP proxy CONNECT"));
        }
        client.buf_receiver.capacity = config.buf_capacity;

        if (secure) {
            const pn::TLSContext* context;
            if (pn::Result<const pn::TLSContext*> result = config.resolve_tls_context(); !result) {
                return std::unexpected(result.error());
            } else {
                context = *result;
            }
            if (pn::Status result = client.tls_init(*context, hostname); !result) {
                return result;
            }
            if (pn::Status result = client.tls_connect(); !result) {
                return result;
            }
        }

        int resp_parts = req.method == "HEAD" ? PW_HTTP_MESSAGE_PART_HEAD : PW_HTTP_MESSAGE_PART_ALL;
        if (pn::Status result = client.send(std::move(req)); !result) {
            return result;
        }

        if (pn::Status result = client.recv(resp, resp_parts); !result) {
            return result;
        }

        return {};
    }

    pn::Status proxied_fetch(pn::StringView url, pn::StringView proxy_url, Response& resp, Headers headers, const ClientConfig& config, std::string http_version) {
        return proxied_fetch("GET", url, proxy_url, resp, std::move(headers), config, std::move(http_version));
    }

    pn::Status proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, Response& resp, Headers headers, const ClientConfig& config, std::string http_version) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        Request req(std::move(method), std::move(url_info.path), std::move(url_info.query_parameters), std::move(headers), std::move(http_version));
        if (!url_info.credentials.empty() && !req.headers.count("Authorization")) {
            req.headers["Authorization"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return proxied_fetch(url_info.hostname(), url_info.port(), string::iequals(url_info.scheme, "https"), proxy_url, std::move(req), resp, config);
    }

    pn::Status proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, Response& resp, std::vector<char> body, Headers headers, const ClientConfig& config, std::string http_version) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        Request req(std::move(method), std::move(url_info.path), std::move(body), std::move(headers), std::move(http_version));
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("Authorization")) {
            req.headers["Authorization"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return proxied_fetch(url_info.hostname(), url_info.port(), string::iequals(url_info.scheme, "https"), proxy_url, std::move(req), resp, config);
    }

    pn::Status proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, Response& resp, pn::StringView body, Headers headers, const ClientConfig& config, std::string http_version) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        Request req(std::move(method), std::move(url_info.path), body, std::move(headers), std::move(http_version));
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("Authorization")) {
            req.headers["Authorization"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return proxied_fetch(url_info.hostname(), url_info.port(), string::iequals(url_info.scheme, "https"), proxy_url, std::move(req), resp, config);
    }

    pn::Status proxied_fetch(std::string method, pn::StringView url, pn::StringView proxy_url, Response& resp, std::move_only_function<std::vector<char>()> body_cb, Headers headers, const ClientConfig& config, std::string http_version) {
        URLInfo url_info;
        if (pn::Status result = url_info.parse(url); !result) {
            return result;
        }

        Request req(std::move(method), std::move(url_info.path), std::move(body_cb), std::move(headers), std::move(http_version));
        req.query_parameters = url_info.query_parameters;
        if (!url_info.credentials.empty() && !req.headers.count("Authorization")) {
            req.headers["Authorization"] = "basic " + base64_encode(url_info.credentials.data(), url_info.credentials.size());
        }

        return proxied_fetch(url_info.hostname(), url_info.port(), string::iequals(url_info.scheme, "https"), proxy_url, std::move(req), resp, config);
    }
}; // namespace pw
