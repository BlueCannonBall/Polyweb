#include "string.hpp"
#include <algorithm>
#include <cctype>
#include <cstddef>

namespace pw {
    namespace string {
        bool starts_with(const std::string& str, const std::string& beginning) {
            if (str.size() < beginning.size() || beginning.empty()) {
                return false;
            }

            for (size_t i = 0; i < beginning.size(); ++i) {
                if (str[i] != beginning[i]) {
                    return false;
                }
            }
            return true;
        }

        bool ends_with(const std::string& str, const std::string& ending) {
            if (str.size() < ending.size() || ending.empty()) {
                return false;
            }

            size_t difference = str.size() - ending.size();
            for (size_t i = 0; i < ending.size(); ++i) {
                if (str[difference + i] != ending[i]) {
                    return false;
                }
            }
            return true;
        }

        void trim_right(std::string& str) {
            std::string::reverse_iterator it;
            if ((it = std::find_if_not(str.rbegin(), str.rend(), isspace)) != str.rend()) {
                str.erase(it.base(), str.end());
            }
        }

        void trim_left(std::string& str) {
            std::string::iterator it;
            if ((it = std::find_if_not(str.begin(), str.end(), isspace)) != str.end()) {
                str.erase(str.begin(), it);
            }
        }

        void trim(std::string& str) {
            trim_right(str);
            trim_left(str);
        }

        std::string trim_right_copy(std::string str) {
            trim_right(str);
            return str;
        }

        std::string trim_left_copy(std::string str) {
            trim_left(str);
            return str;
        }

        std::string trim_copy(std::string str) {
            trim(str);
            return str;
        }

        void to_lower(std::string& str) {
            std::transform(str.begin(), str.end(), str.begin(), tolower);
        }

        void to_upper(std::string& str) {
            std::transform(str.begin(), str.end(), str.begin(), toupper);
        }

        std::string to_lower_copy(const std::string& str) {
            std::string ret;
            ret.reserve(str.size());
            std::transform(str.begin(), str.end(), std::back_inserter(ret), tolower);
            return ret;
        }

        std::string to_upper_copy(const std::string& str) {
            std::string ret;
            ret.reserve(str.size());
            std::transform(str.begin(), str.end(), std::back_inserter(ret), toupper);
            return ret;
        }

        bool iequals(const std::string& a, const std::string& b) {
            if (a.size() != b.size()) {
                return false;
            }

            for (size_t i = 0; i < a.size(); ++i) {
                if (tolower(a[i]) != tolower(b[i])) {
                    return false;
                }
            }
            return true;
        }

        std::vector<std::string> split(const std::string& str, char delimiter) {
            std::vector<std::string> ret;
            for (size_t i = 0; i < str.size();) {
                size_t j;
                if ((j = str.find(delimiter, i)) != i) {
                    ret.push_back(str.substr(i, j - i));
                }

                if (j == std::string::npos) {
                    break;
                } else {
                    i = j + 1;
                }
            }
            return ret;
        }

        std::vector<std::string> split_and_trim(const std::string& str, char delimiter) {
            std::vector<std::string> ret = split(str, delimiter);
            std::for_each(ret.begin(), ret.end(), trim);
            return ret;
        }
    } // namespace string
} // namespace pw
