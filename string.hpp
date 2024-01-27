#ifndef _POLYWEB_STRING_HPP
#define _POLYWEB_STRING_HPP

#include <string>
#include <vector>

namespace pw {
    namespace string {
        bool starts_with(const std::string& str, const std::string& beginning);
        bool ends_with(const std::string& str, const std::string& ending);

        void trim_right(std::string& str);
        void trim_left(std::string& str);
        void trim(std::string& str);

        std::string trim_right_copy(std::string str);
        std::string trim_left_copy(std::string str);
        std::string trim_copy(std::string str);

        void to_lower(std::string& str);
        void to_upper(std::string& str);

        std::string to_lower_copy(const std::string& str);
        std::string to_upper_copy(const std::string& str);

        bool iequals(const std::string& a, const std::string& b);

        std::vector<std::string> split(const std::string& str, char delimiter);
        std::vector<std::string> split_and_trim(const std::string& str, char delimiter);

        struct CaseInsensitiveComparer {
            bool operator()(const std::string& a, const std::string& b) const {
                return string::iequals(a, b);
            }
        };

        struct CaseInsensitiveHasher {
            size_t operator()(const std::string& str) const {
                return std::hash<std::string>()(string::to_lower_copy(str));
            }
        };
    } // namespace string
} // namespace pw

#endif
