#ifndef POLYWEB_SSE_HPP_
#define POLYWEB_SSE_HPP_

#include <functional>
#include <stdint.h>
#include <string>
#include <utility>

namespace pw {
    class SSEEvent {
    public:
        std::string type = "message";
        std::string data;

        SSEEvent(std::string data = {}):
            data(std::move(data)) {}
        SSEEvent(std::string event, std::string data):
            type(std::move(event)),
            data(std::move(data)) {}

        std::string build() const {
            std::string ret = "event: " + type + "\r\n";

            size_t line_start = 0;
            for (size_t i = 0; i < data.size(); ++i) {
                if (data[i] != '\r' && data[i] != '\n') {
                    continue;
                }

                ret += "data: ";
                ret.append(data, line_start, i - line_start);
                ret += "\r\n";

                if (data[i] == '\r' && i + 1 < data.size() && data[i + 1] == '\n') {
                    ++i;
                }
                line_start = i + 1;
            }

            ret += "data: ";
            ret.append(data, line_start, data.size() - line_start);
            ret += "\r\n\r\n";

            return ret;
        }
    };

    class SSEParser {
    protected:
        std::string buf;
        SSEEvent current_event;
        std::move_only_function<bool(SSEEvent)> event_cb;
        bool skip_next_lf = false;

        bool handle_data() {
            while (!buf.empty()) {
                if (skip_next_lf && buf.front() == '\n') {
                    buf.erase(0, 1);
                }
                skip_next_lf = false;

                size_t end = buf.find_first_of("\r\n");
                if (end == std::string::npos) {
                    break;
                }

                std::string line = buf.substr(0, end);

                size_t delimiter_length = 1;
                if (buf[end] == '\r') {
                    if (end + 1 < buf.size() && buf[end + 1] == '\n') {
                        delimiter_length = 2;
                    } else {
                        skip_next_lf = true;
                    }
                }
                buf.erase(0, end + delimiter_length);

                if (line.empty()) {
                    if (current_event.data.empty()) {
                        current_event = {};
                        continue;
                    }
                    if (current_event.data.back() == '\n') {
                        current_event.data.pop_back();
                    }

                    if (!event_cb(std::exchange(current_event, {}))) {
                        return false;
                    }
                }

                size_t colon_pos = line.find(':');

                std::string field = line.substr(0, colon_pos);
                if (field.empty()) {
                    continue;
                }

                std::string value;
                if (colon_pos < line.size()) {
                    if (colon_pos + 1 < line.size() && line[colon_pos + 1] == ' ') {
                        value = line.substr(colon_pos + 2);
                    } else {
                        value = line.substr(colon_pos + 1);
                    }
                }

                if (field == "event") {
                    current_event.type = value.empty() ? "message" : std::move(value);
                } else if (field == "data") {
                    current_event.data += value + '\n';
                }
            }
            return true;
        }

    public:
        SSEParser(decltype(event_cb) event_cb):
            event_cb(std::move(event_cb)) {}

        template <typename T>
        bool operator()(const T& data) {
            buf.insert(buf.end(), data.begin(), data.end());
            return handle_data();
        }
    };
} // namespace pw

#endif
