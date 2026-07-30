#ifndef POLYWEB_ERROR_HPP_
#define POLYWEB_ERROR_HPP_

#include "Polynet/error.hpp"

namespace pw {
    enum ErrorType {
        PW_ERROR_INVALID_URL,
        PW_ERROR_INVALID_HTTP,
        PW_ERROR_INVALID_WS,
        PW_ERROR_LIMIT_EXCEEDED,
        PW_ERROR_UNSUPPORTED,
    };

    const std::error_category& polyweb_category();

    inline std::error_code polyweb_error_code(ErrorType error) {
        return {error, polyweb_category()};
    }

    inline pn::Error make_error(ErrorType error, pn::StringView operation) {
        return {polyweb_error_code(error), operation};
    }
} // namespace pw

#endif
