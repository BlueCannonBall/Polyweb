#include "string.hpp"
#include <algorithm>
#include <ctype.h>
#include <iterator>
#include <stddef.h>

namespace pw {
    namespace string {
        bool starts_with(pn::StringView str, pn::StringView beginning) {
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

        bool ends_with(pn::StringView str, pn::StringView ending) {
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
            str.erase(
                std::find_if_not(str.rbegin(), str.rend(), [](char c) -> bool {
                    return isspace((unsigned char) c);
                }).base(),
                str.end());
        }

        void trim_left(std::string& str) {
            str.erase(
                str.begin(),
                std::find_if_not(str.begin(), str.end(), [](char c) -> bool {
                    return isspace((unsigned char) c);
                }));
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
            std::transform(str.begin(), str.end(), str.begin(), [](char c) -> char {
                return tolower((unsigned char) c);
            });
        }

        void to_upper(std::string& str) {
            std::transform(str.begin(), str.end(), str.begin(), [](char c) -> char {
                return toupper((unsigned char) c);
            });
        }

        std::string to_lower_copy(pn::StringView str) {
            std::string ret;
            ret.reserve(str.size());
            std::transform(str.begin(), str.end(), std::back_inserter(ret), [](char c) -> char {
                return tolower((unsigned char) c);
            });
            return ret;
        }

        std::string to_upper_copy(pn::StringView str) {
            std::string ret;
            ret.reserve(str.size());
            std::transform(str.begin(), str.end(), std::back_inserter(ret), [](char c) -> char {
                return toupper((unsigned char) c);
            });
            return ret;
        }

        bool iequals(pn::StringView a, pn::StringView b) {
            if (a.size() != b.size()) {
                return false;
            }

            for (size_t i = 0; i < a.size(); ++i) {
                if (tolower((unsigned char) a[i]) != tolower((unsigned char) b[i])) {
                    return false;
                }
            }
            return true;
        }

        std::vector<std::string> split(pn::StringView str, char delimiter) {
            std::vector<std::string> ret;
            for (size_t i = 0; i < str.size();) {
                size_t j;
                if ((j = str.find(delimiter, i)) != i) {
                    ret.push_back(str.substr(i, j - i));
                }

                if (j == std::string::npos) {
                    break;
                }
                i = j + 1;
            }
            return ret;
        }

        std::vector<std::string> split_and_trim(pn::StringView str, char delimiter) {
            std::vector<std::string> ret = split(str, delimiter);
            std::for_each(ret.begin(), ret.end(), trim);
            return ret;
        }
    } // namespace string
} // namespace pw
