#include "polyweb.hpp"
#include <algorithm>
#include <openssl/sha.h>
#include <stdexcept>
#include <utility>

namespace pw {
    template <typename Base>
    int BasicServer<Base>::listen(std::function<bool(typename Base::connection_type&, void*)> filter, void* filter_data, int backlog) {
        if (Base::listen([filter = std::move(filter), filter_data](typename Base::connection_type& conn, void* data) -> bool {
                if (filter(conn, filter_data)) {
                    conn.close();
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
    }

    template <>
    int SecureServer::listen(std::function<bool(typename pn::tcp::SecureServer::connection_type&, void*)> filter, void* filter_data, int backlog) {
        if (pn::tcp::SecureServer::listen([filter = std::move(filter), filter_data](typename pn::tcp::SecureServer::connection_type& conn, void* data) -> bool {
                if (filter(conn, filter_data)) {
                    conn.close();
                } else {
                    auto server = (pw::SecureServer*) data;
                    threadpool.schedule([conn](void* data) mutable {
                        auto server = (pw::SecureServer*) data;

                        if (server->ssl_ctx && conn.ssl_accept() == PN_ERROR) {
                            conn.close();
                            return;
                        }

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
            throw std::logic_error("pw::SecureServer::listen returned without an error");
        }
    }

    template <typename Base>
    int BasicServer<Base>::handle_connection(pn::UniqueSocket<connection_type> conn, pn::tcp::BufReceiver& buf_receiver) const {
        bool keep_alive = true;
        bool websocket = false;
        do {
            HTTPRequest req;
            if (req.parse(*conn, buf_receiver, header_climit, header_name_rlimit, header_value_rlimit) == PN_ERROR) {
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
                    HTTPResponse resp;
                    try {
                        resp = ws_routes.at(ws_route_target).on_connect(*conn, req, ws_routes.at(ws_route_target).data);
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
                        return handle_ws_connection(std::move(conn), buf_receiver, ws_routes.at(ws_route_target));
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
                        resp = http_routes.at(http_route_target).cb(*conn, req, http_routes.at(http_route_target).data);
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
        } while (conn && keep_alive);
        return PN_OK;
    }

    template <typename Base>
    int BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, const HTTPHeaders& headers, bool head_only, pn::StringView http_version) const {
        HTTPResponse resp;
        try {
            resp = on_error(status_code);
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
    int BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, bool keep_alive, bool head_only, pn::StringView http_version) const {
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

    template class BasicServer<pn::tcp::Server>;
    template class BasicServer<pn::tcp::SecureServer>;
} // namespace pw
