#ifndef POLYWEB_BINARY_HPP_
#define POLYWEB_BINARY_HPP_

#include "polyweb.hpp"
#include <concepts>
#include <cstddef>
#include <iterator>
#include <string.h>
#include <type_traits>

namespace pw {
    namespace binary {
        namespace detail {
            template <typename T>
            concept ByteType =
                std::same_as<std::remove_cv_t<T>, char> ||
                std::same_as<std::remove_cv_t<T>, signed char> ||
                std::same_as<std::remove_cv_t<T>, unsigned char> ||
                std::same_as<std::remove_cv_t<T>, std::byte>;

            template <typename It>
            concept ContiguousByteInputIterator =
                std::contiguous_iterator<It> && ByteType<std::iter_value_t<It>>;
        } // namespace detail

        template <typename T, detail::ContiguousByteInputIterator InputIt>
            requires std::is_trivially_copyable_v<T>
        InputIt read(InputIt first, InputIt last, T& ret, int byte_order = BIG_ENDIAN) {
            auto byte_count = (std::iter_difference_t<InputIt>) sizeof(T);
            if (std::distance(first, last) >= byte_count) {
                if (byte_order == BYTE_ORDER) {
                    memcpy(&ret, &*first, sizeof(T));
                } else {
                    reverse_memcpy(&ret, &*first, sizeof(T));
                }
                std::advance(first, byte_count);
            }
            return first;
        }

        template <typename T, detail::ContiguousByteInputIterator InputIt>
            requires std::is_trivially_copyable_v<T>
        bool try_read(InputIt& first, InputIt last, T& ret, int byte_order = BIG_ENDIAN) {
            InputIt old_first = first;
            first = read(first, last, ret, byte_order);
            return first != old_first;
        }

        template <typename T, typename OutputIt>
            requires std::is_trivially_copyable_v<T> &&
                     (requires(OutputIt it, unsigned char byte) { *it++ = byte; } || requires(OutputIt it, std::byte byte) { *it++ = byte; })
        OutputIt write(OutputIt ret, const T& value, int byte_order = BIG_ENDIAN) {
            const auto* bytes = (const unsigned char*) &value;
            for (std::size_t i = 0; i < sizeof(T); ++i) {
                const unsigned char byte = byte_order == BYTE_ORDER ? bytes[i] : bytes[sizeof(T) - 1 - i];
                if constexpr (requires(OutputIt it, std::byte value) { *it++ = value; }) {
                    *ret++ = (std::byte) byte;
                } else {
                    *ret++ = byte;
                }
            }
            return ret;
        }
    } // namespace binary
} // namespace pw

#endif
