#include "error.hpp"

namespace pw {
    namespace detail {
        class PolywebCategory : public std::error_category {
        public:
            const char* name() const noexcept override {
                return "polyweb";
            }

            std::string message(int error) const override {
                switch (error) {
                case PW_ERROR_INVALID_URL: return "Invalid URL";
                case PW_ERROR_INVALID_HTTP: return "Invalid HTTP message";
                case PW_ERROR_INVALID_WEBSOCKET: return "Invalid WebSocket message";
                case PW_ERROR_LIMIT_EXCEEDED: return "Protocol limit exceeded";
                case PW_ERROR_UNSUPPORTED: return "Unsupported protocol feature";
                default: return "Unknown Polyweb error";
                }
            }
        };
    } // namespace detail

    const std::error_category& polyweb_category() {
        static detail::PolywebCategory category;
        return category;
    }
} // namespace pw
