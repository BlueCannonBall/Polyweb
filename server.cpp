#include "polyweb.hpp"
#include <algorithm>
#include <openssl/sha.h>

namespace pw {
    pn::Status RequestReceiver::parse(pn::tcp::Connection& conn, pn::tcp::BufReceiver& buf_receiver, int parts, const MessageConfig& config) {
        if (pn::Status result = Request::parse(conn, buf_receiver, parts, config); !result) {
            return result;
        }
        parts_parsed |= parts;
        return {};
    }

    pn::Status Server::listen(std::function<bool(pn::tcp::Connection&)> config_cb, int backlog) {
        return pn::tcp::Server::listen([this, config_cb = std::move(config_cb)](pn::tcp::Connection conn) {
            if (config.tcp.apply(conn) && (!config_cb || config_cb(conn))) {
                task_manager.insert(threadpool.schedule([this, conn = std::move(conn)]() mutable {
                    (void) handle_conn(connection_type(std::move(conn), pn::tcp::BufReceiver(config.buf_capacity), config.http));
                },
                    true));
            }
            return true;
        },
            backlog);
    }

    pn::Status TLSServer::listen(const pn::TLSContext& context, std::function<bool(pn::tcp::TLSConnection&)> config_cb, int backlog) {
        return pn::tcp::TLSServer::listen(context, [this, config_cb = std::move(config_cb)](pn::tcp::TLSConnection conn) {
            return dispatch_conn(std::move(conn), config_cb);
        },
            backlog);
    }

    pn::Status TLSServer::listen(std::function<bool(pn::tcp::TLSConnection&)> config_cb, int backlog) {
        return pn::tcp::TLSServer::listen([this, config_cb = std::move(config_cb)](pn::tcp::TLSConnection conn) {
            return dispatch_conn(std::move(conn), config_cb);
        },
            backlog);
    }

    bool TLSServer::dispatch_conn(pn::tcp::TLSConnection conn, const std::function<bool(pn::tcp::TLSConnection&)>& config_cb) {
        if (config.tcp.apply(conn) && (!config_cb || config_cb(conn))) {
            task_manager.insert(threadpool.schedule([this, conn = std::move(conn)]() mutable {
                // Plaintext when no context was given, and then there is no handshake
                if (conn.is_secure() && !conn.tls_accept()) {
                    return;
                }
                (void) handle_conn(connection_type(std::move(conn), pn::tcp::BufReceiver(config.buf_capacity), config.http));
            },
                true));
        }
        return true;
    }

    template <typename Base>
    pn::Status BasicServer<Base>::handle_conn(connection_type conn) const {
        bool keep_alive = true;
        do {
            RequestReceiver req;
            if (pn::Status result = conn.recv(req, PW_HTTP_MESSAGE_PART_HEAD); !result) {
                (void) handle_error(conn, 400, result.error().message(), false);
                return result;
            }

            int resp_parts = req.method == "HEAD" ? PW_HTTP_MESSAGE_PART_HEAD : PW_HTTP_MESSAGE_PART_ALL;

            bool websocket = false;
            if (auto connection_it = req.headers.find("Connection"); connection_it != req.headers.end()) {
                std::vector<std::string> split_connection = string::split_and_trim(string::to_lower_copy(connection_it->second), ',');
                if (req.http_version == "HTTP/1.1") {
                    keep_alive = std::find(split_connection.begin(), split_connection.end(), "close") == split_connection.end();

                    Headers::iterator upgrade_it;
                    if (std::find(split_connection.begin(), split_connection.end(), "upgrade") != split_connection.end() && (upgrade_it = req.headers.find("Upgrade")) != req.headers.end()) {
                        std::vector<std::string> split_upgrade = string::split_and_trim(string::to_lower_copy(upgrade_it->second), ',');
                        if (req.method == "GET" && std::find(split_upgrade.begin(), split_upgrade.end(), "websocket") != split_upgrade.end()) {
                            websocket = true;
                        } else {
                            if (pn::Status result = handle_error(conn, 501, "Unsupported upgrade", keep_alive, resp_parts, req.http_version); !result) {
                                return result;
                            }
                            if (pn::Status result = conn.recv(req, PW_HTTP_MESSAGE_PART_BODY); !result) {
                                return result;
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

                    Response resp;
                    try {
                        if (route.connect_cb) {
                            resp = route.connect_cb(conn, req);
                        } else {
                            resp = Response(101);
                        }
                    } catch (const std::exception& e) {
                        if (pn::Status result = handle_error(conn, 500, e.what(), keep_alive, false, req.http_version); !result) {
                            return result;
                        }
                        continue;
                    } catch (...) {
                        if (pn::Status result = handle_error(conn, 500, keep_alive, false, req.http_version); !result) {
                            return result;
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
                                if (pn::Status result = handle_error(conn, 501, "Unsupported WebSocket version", keep_alive, false, req.http_version); !result) {
                                    return result;
                                }
                                continue;
                            }
                        }

                        Headers::iterator websocket_key_it;
                        if (!resp.headers.count("Sec-WebSocket-Accept") && (websocket_key_it = req.headers.find("Sec-WebSocket-Key")) != req.headers.end()) {
                            std::string websocket_key = string::trim_right_copy(websocket_key_it->second);
                            websocket_key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                            unsigned char digest[SHA_DIGEST_LENGTH];
                            SHA1((unsigned char*) websocket_key.data(), websocket_key.size(), digest);
                            resp.headers["Sec-WebSocket-Accept"] = base64_encode(digest, SHA_DIGEST_LENGTH);
                        }

                        Headers::iterator websocket_protocol_it;
                        if (!resp.headers.count("Sec-WebSocket-Protocol") && (websocket_protocol_it = req.headers.find("Sec-WebSocket-Protocol")) != req.headers.end()) {
                            std::vector<std::string> split_websocket_protocol = string::split(websocket_protocol_it->second, ',');
                            if (!split_websocket_protocol.empty()) {
                                resp.headers["Sec-WebSocket-Protocol"] = string::trim_copy(split_websocket_protocol.back());
                            }
                        }
                    } else if (!resp.headers.count("Connection")) {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    bool ws_open = resp.status_code == 101;
                    if (pn::Status result = conn.send(std::move(resp)); !result) {
                        return result;
                    }

                    if (ws_open) {
                        route.open_cb(ws_connection_type(std::move(conn), config.ws), std::move(req));
                        return {};
                    }
                } else if (!http_route_target.empty()) {
                    if (pn::Status result = handle_error(conn, 400, keep_alive, resp_parts, req.http_version); !result) {
                        return result;
                    }
                } else {
                    if (pn::Status result = handle_error(conn, 404, keep_alive, resp_parts, req.http_version); !result) {
                        return result;
                    }
                }
            } else {
                if (!http_route_target.empty()) {
                    const auto& route = http_routes.at(http_route_target);
                    if (route.parse_body) {
                        if (pn::Status result = conn.recv(req, PW_HTTP_MESSAGE_PART_BODY); !result) {
                            (void) handle_error(conn, 400, result.error().message(), false, resp_parts, req.http_version);
                            return result;
                        }
                    }

                    auto discard_body = [&]() -> pn::Status {
                        if (!(req.parts_parsed & PW_HTTP_MESSAGE_PART_BODY)) {
                            req.recv_cb = [](std::vector<char>) {
                                return true;
                            };
                            return conn.recv(req, PW_HTTP_MESSAGE_PART_BODY);
                        }
                        return {};
                    };

                    Response resp;
                    try {
                        resp = route.cb(conn, req);
                    } catch (const std::exception& e) {
                        pn::Status discard_result = discard_body();
                        if (!discard_result) {
                            keep_alive = false;
                        }
                        if (pn::Status result = handle_error(conn, 500, e.what(), keep_alive, resp_parts, req.http_version); !result) {
                            return result;
                        }
                        if (!discard_result) {
                            return discard_result;
                        }
                        continue;
                    } catch (...) {
                        pn::Status discard_result = discard_body();
                        if (!discard_result) {
                            keep_alive = false;
                        }
                        if (pn::Status result = handle_error(conn, 500, keep_alive, resp_parts, req.http_version); !result) {
                            return result;
                        }
                        if (!discard_result) {
                            return discard_result;
                        }
                        continue;
                    }

                    if (pn::Status result = discard_body(); !result) {
                        keep_alive = false;
                    }

                    if (!resp.headers.count("Server")) {
                        resp.headers["Server"] = PW_AGENT_NAME;
                    }
                    if (!resp.headers.count("Connection")) {
                        resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
                    }

                    if (pn::Status result = conn.send(std::move(resp), resp_parts); !result) {
                        return result;
                    }
                } else if (!ws_route_target.empty()) {
                    if (pn::Status result = handle_error(conn, 426, {{"Connection", keep_alive ? "keep-alive, upgrade" : "close, upgrade"}, {"Upgrade", "websocket"}}, resp_parts, req.http_version); !result) {
                        return result;
                    }
                } else {
                    if (pn::Status result = handle_error(conn, 404, keep_alive, resp_parts, req.http_version); !result) {
                        return result;
                    }
                }
            }
        } while (conn && keep_alive);
        return {};
    }

    template <typename Base>
    pn::Status BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, const Headers& headers, int parts, std::string http_version) const {
        return handle_error(conn, status_code, {}, headers, parts, std::move(http_version));
    }

    template <typename Base>
    pn::Status BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, bool keep_alive, int parts, std::string http_version) const {
        return handle_error(conn, status_code, {}, keep_alive, parts, std::move(http_version));
    }

    template <typename Base>
    pn::Status BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, pn::StringView what, const Headers& headers, int parts, std::string http_version) const {
        Response resp;
        try {
            if (error_cb) {
                resp = error_cb(status_code, what);
            } else {
                resp = pw::Response::make_basic(status_code);
            }
        } catch (...) {
            resp = Response::make_basic(500);
        }

        resp.http_version = std::move(http_version);
        if (!resp.headers.count("Server")) {
            resp.headers["Server"] = PW_AGENT_NAME;
        }

        for (const auto& header : headers) {
            resp.headers.insert(header);
        }

        return conn.send(std::move(resp), parts);
    }

    template <typename Base>
    pn::Status BasicServer<Base>::handle_error(connection_type& conn, uint16_t status_code, pn::StringView what, bool keep_alive, int parts, std::string http_version) const {
        Response resp;
        try {
            if (error_cb) {
                resp = error_cb(status_code, what);
            } else {
                resp = pw::Response::make_basic(status_code);
            }
        } catch (...) {
            resp = Response::make_basic(500);
        }

        resp.http_version = std::move(http_version);
        if (!resp.headers.count("Server")) {
            resp.headers["Server"] = PW_AGENT_NAME;
        }
        if (!resp.headers.count("Connection")) {
            resp.headers["Connection"] = keep_alive ? "keep-alive" : "close";
        }

        return conn.send(std::move(resp), parts);
    }

} // namespace pw
