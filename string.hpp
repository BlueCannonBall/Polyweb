#ifndef POLYWEB_STRING_HPP_
#define POLYWEB_STRING_HPP_

#include "Polynet/string.hpp"
#include <string>
#include <vector>

namespace pw {
    namespace string {
        bool starts_with(pn::StringView str, pn::StringView beginning);
        bool ends_with(pn::StringView str, pn::StringView ending);

        void trim_right(std::string& str);
        void trim_left(std::string& str);
        void trim(std::string& str);

        std::string trim_right_copy(std::string str);
        std::string trim_left_copy(std::string str);
        std::string trim_copy(std::string str);

        void to_lower(std::string& str);
        void to_upper(std::string& str);

        std::string to_lower_copy(pn::StringView str);
        std::string to_upper_copy(pn::StringView str);

        bool iequals(pn::StringView a, pn::StringView b);

        std::vector<std::string> split(pn::StringView str, char delimiter);
        std::vector<std::string> split_and_trim(pn::StringView str, char delimiter);

        struct CaseInsensitiveComparer {
            bool operator()(pn::StringView a, pn::StringView b) const {
                return string::iequals(a, b);
            }
        };

        struct CaseInsensitiveHasher {
            size_t operator()(pn::StringView str) const {
                return std::hash<std::string>()(string::to_lower_copy(str));
            }
        };
    } // namespace string
} // namespace pw

#endif
