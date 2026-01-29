#include "polyweb.hpp"
#include <algorithm>
#include <openssl/sha.h>
#include <stdexcept>
#if BYTE_ORDER == BIG_ENDIAN
    #include <string.h>
#endif

namespace pw {
    template <typename Base>
    int BasicServer<Base>::listen(std::function<bool(typename Base::connection_type&)> config_cb, int backlog) {
        if (Base::listen([this, config_cb = std::move(config_cb)](typename Base::connection_type conn) {
                if (!config_cb || config_cb(conn)) {
                    task_manager.insert(thread_pool.schedule([this, conn = std::move(conn)]() mutable {
                        handle_conn(connection_type(std::move(conn), pn::tcp::BufReceiver(buf_size)));
                    },
                        true));
                }
                return true;
            },
                backlog) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        } else {
            throw std::logic_error("Base::listen returned without an error");
        }
    }

    template <>
    int SecureServer::listen(std::function<bool(typename pn::tcp::SecureServer::connection_type&)> config_cb, int backlog) {
        if (pn::tcp::SecureServer::listen([this, config_cb = std::move(config_cb)](typename pn::tcp::SecureServer::connection_type conn) {
                if (!config_cb || config_cb(conn)) {
                    task_manager.insert(thread_pool.schedule([this, conn = std::move(conn)]() mutable {
                        if (ssl_ctx && conn.ssl_accept() == PN_ERROR) {
                            return;
                        }
                        handle_conn(connection_type(std::move(conn), pn::tcp::BufReceiver(buf_size)));
                    },
                        true));
                }
                return true;
            },
                backlog) == PN_ERROR) {
            detail::set_last_error(PW_ENET);
            return PN_ERROR;
        } else {
            throw std::logic_error("pw::SecureServer::listen returned without an error");
        }
    }

    template <typename Base>
    int BasicServer<Base>::handle_conn(connection_type conn) const {
        bool keep_alive = true;
        do {
            HTTPRequest req;
            if (conn.recv(req, PW_HTTP_MESSAGE_PART_HEAD, header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit) == PN_ERROR) {
                uint16_t status_code;
                switch (get_last_error()) {
                case PW_ENET:
                    status_code = 500;
                    break;

                case PW_EWEB:
                    status_code = 400;
                    break;

                default:
                    throw std::logic_error("Invalid error");
                }
                handle_error(conn, status_code, pw::universal_strerror(), false);
                return PN_ERROR;
            }

            int resp_parts = req.method == "HEAD" ? PW_HTTP_MESSAGE_PART_HEAD : PW_HTTP_MESSAGE_PART_ALL;

            bool websocket = false;
            if (auto connection_it = req.headers.find("Connection"); connection_it != req.headers.end()) {
                std::vector<std::string> split_connection = string::split_and_trim(string::to_lower_copy(connection_it->second), ',');
                if (req.http_version == "HTTP/1.1") {
                    keep_alive = std::find(split_connection.begin(), split_connection.end(), "close") == split_connection.end();

                    HTTPHeaders::iterator upgrade_it;
                    if (std::find(split_connection.begin(), split_connection.end(), "upgrade") != split_connection.end() && (upgrade_it = req.headers.find("Upgrade")) != req.headers.end()) {
                        std::vector<std::string> split_upgrade = string::split_and_trim(string::to_lower_copy(upgrade_it->second), ',');
                        if (req.method == "GET" && std::find(split_upgrade.begin(), split_upgrade.end(), "websocket") != split_upgrade.end()) {
                            websocket = true;
                        } else {
                            if (handle_error(conn, 501, "Unsupported upgrade", keep_alive, resp_parts, req.http_version) == PN_ERROR) {
                                return PN_ERROR;
                            }
                            if (conn.recv(req, PW_HTTP_MESSAGE_PART_BODY, header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit) == PN_ERROR) {
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
            for (const auto& route : http_routes) {
                if (route.first == req.target) {
                    http_route_target = route.first;
                    break;
                } else if (route.second.wildcard && string::starts_with(req.target, route.first) && route.first.size() > http_route_target.size()) {
                    http_route_target = route.first;
                }
            }

            if (websocket) {
                if (!ws_route_target.empty()) {
                    const auto& route = ws_routes.at(ws_route_target);

                    HTTPResponse resp;
                    try {
                        if (route.on_connect) {
                            resp = route.on_connect(conn, req);
                        } else {
                            resp = HTTPResponse(101);
                        }
                    } catch (const std::exception& e) {
                        if (handle_error(conn, 500, e.what(), keep_alive, false, req.http_version) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        continue;
                    } catch (...) {
                        if (handle_error(conn, 500, keep_alive, false, req.http_version) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        continue;
                    }

                    if (!resp.headers.count("Server")) {
                        resp.headers["Server"] = PW_AGENT_NAME;
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

                        if (auto websocket_version_it = req.headers.find("Sec-WebSocket-Version"); websocket_version_it != req.headers.end()) {
                            std::vector<std::string> split_websocket_version = string::split_and_trim(websocket_version_it->second, ',');

                            bool found_version = false;
                            for (const auto& version : split_websocket_version) {
                                if (version == PW_WS_VERSION) {
                                    found_version = true;
                                    break;
                                }
                            }

                            if (found_version) {
                                resp.headers["Sec-WebSocket-Version"] = PW_WS_VERSION;
                            } else {
                                if (handle_error(conn, 501, "Unsupported WebSocket version", keep_alive, false, req.http_version) == PN_ERROR) {
                                    return PN_ERROR;
                                }
                                continue;
                            }
                        }

                        HTTPHeaders::iterator websocket_key_it;
                        if (!resp.headers.count("Sec-WebSocket-Accept") && (websocket_key_it = req.headers.find("Sec-WebSocket-Key")) != req.headers.end()) {
                            std::string websocket_key = string::trim_right_copy(websocket_key_it->second);
                            websocket_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                            unsigned char digest[SHA_DIGEST_LENGTH];
                            SHA1((unsigned char*) websocket_key.data(), websocket_key.size(), digest);
                            resp.headers["Sec-WebSocket-Accept"] = base64_encode(digest, SHA_DIGEST_LENGTH);
                        }

                        HTTPHeaders::iterator websocket_protocol_it;
                        if (!resp.headers.count("Sec-WebSocket-Protocol") && (websocket_protocol_it = req.headers.find("Sec-WebSocket-Protocol")) != req.headers.end()) {
                            std::vector<std::string> split_websocket_protocol = string::split(websocket_protocol_it->second, ',');
                            if (!split_websocket_protocol.empty()) {
                                resp.headers["Sec-WebSocket-Protocol"] = string::trim_copy(split_websocket_protocol.back());
                            }
                        }
                    } else if (!resp.headers.count("Connection")) {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    if (conn.send(resp) == PN_ERROR) {
                        return PN_ERROR;
                    }

                    if (resp.status_code == 101) {
                        route.on_open(std::move(conn), std::move(req));
                        return PN_OK;
                    }
                } else if (!http_route_target.empty()) {
                    if (handle_error(conn, 400, keep_alive, resp_parts, req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else {
                    if (handle_error(conn, 404, keep_alive, resp_parts, req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                }
            } else {
                if (!http_route_target.empty()) {
                    const auto& route = http_routes.at(http_route_target);
                    if (route.parse_body) {
                        if (conn.recv(req, PW_HTTP_MESSAGE_PART_BODY, header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit) == PN_ERROR) {
                            uint16_t status_code;
                            switch (get_last_error()) {
                            case PW_ENET:
                                status_code = 500;
                                break;

                            case PW_EWEB:
                                status_code = 400;
                                break;

                            default:
                                throw std::logic_error("Invalid error");
                            }
                            handle_error(conn, status_code, pw::universal_strerror(), false, resp_parts, req.http_version);
                            return PN_ERROR;
                        }
                    }

                    HTTPResponse resp;
                    try {
                        resp = route.cb(conn, std::move(req));
                    } catch (const std::exception& e) {
                        if (handle_error(conn, 500, e.what(), keep_alive, resp_parts, req.http_version) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        if (conn.recv(req, PW_HTTP_MESSAGE_PART_BODY, header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        continue;
                    } catch (...) {
                        if (handle_error(conn, 500, keep_alive, resp_parts, req.http_version) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        if (conn.recv(req, PW_HTTP_MESSAGE_PART_BODY, header_climit, header_name_rlimit, header_value_rlimit, body_chunk_rlimit, body_rlimit, misc_rlimit) == PN_ERROR) {
                            return PN_ERROR;
                        }
                        continue;
                    }

                    if (!resp.headers.count("Server")) {
                        resp.headers["Server"] = PW_AGENT_NAME;
                    }
                    if (!resp.headers.count("Connection")) {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    if (conn.send(resp, resp_parts) == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else if (!ws_route_target.empty()) {
                    if (handle_error(conn, 426, {{"Connection", keep_alive ? "keep-alive, upgrade" : "close, upgrade"}, {"Upgrade", "websocket"}}, resp_parts, req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                } else {
                    if (handle_error(conn, 404, keep_alive, resp_parts, req.http_version) == PN_ERROR) {
                        return PN_ERROR;
                    }
                }
            }
        } while (conn && keep_alive);
        return PN_OK;
    }

    template <typename Base>
    int BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, const HTTPHeaders& headers, int parts, std::string http_version) const {
        return handle_error(conn, status_code, {}, headers, parts, std::move(http_version));
    }

    template <typename Base>
    int BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, bool keep_alive, int parts, std::string http_version) const {
        return handle_error(conn, status_code, {}, keep_alive, parts, std::move(http_version));
    }

    template <typename Base>
    int BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, pn::StringView what, const HTTPHeaders& headers, int parts, std::string http_version) const {
        HTTPResponse resp;
        try {
            if (on_error) {
                resp = on_error(status_code, what);
            } else {
                resp = pw::HTTPResponse::make_basic(status_code);
            }
        } catch (...) {
            resp = HTTPResponse::make_basic(500);
        }

        resp.http_version = std::move(http_version);
        if (!resp.headers.count("Server")) {
            resp.headers["Server"] = PW_AGENT_NAME;
        }

        for (const auto& header : headers) {
            resp.headers.insert(header);
        }

        if (conn.send(resp, parts) == PN_ERROR) {
            return PN_ERROR;
        }

        return PN_OK;
    }

    template <typename Base>
    int BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, pn::StringView what, bool keep_alive, int parts, std::string http_version) const {
        HTTPResponse resp;
        try {
            if (on_error) {
                resp = on_error(status_code, what);
            } else {
                resp = pw::HTTPResponse::make_basic(status_code);
            }
        } catch (...) {
            resp = HTTPResponse::make_basic(500);
        }

        resp.http_version = std::move(http_version);
        if (!resp.headers.count("Server")) {
            resp.headers["Server"] = PW_AGENT_NAME;
        }
        if (!resp.headers.count("Connection")) {
            resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
        }

        if (conn.send(resp, parts) == PN_ERROR) {
            return PN_ERROR;
        }

        return PN_OK;
    }

    template class BasicServer<pn::tcp::Server>;
    template class BasicServer<pn::tcp::SecureServer>;
} // namespace pw
