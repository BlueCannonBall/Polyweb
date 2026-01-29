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
            concept ByteAliasingType =
                std::same_as<T, char> ||
                std::same_as<T, signed char> ||
                std::same_as<T, unsigned char> ||
                std::same_as<T, std::byte>;

            template <typename It>
            concept ReadableByteIterator = std::input_iterator<It> && ByteAliasingType<std::iter_value_t<It>>;

            template <typename It, typename T>
            concept WritableToByte = ByteAliasingType<T> &&
                                     requires(It it, T value) {
                                         *it = value;
                                     };

            template <typename It>
            concept ByteOutputIterator =
                WritableToByte<It, char> ||
                WritableToByte<It, signed char> ||
                WritableToByte<It, unsigned char> ||
                WritableToByte<It, std::byte>;

            template <typename It>
            concept ByteIterator = ReadableByteIterator<It> || ByteOutputIterator<It>;

            template <typename It>
            concept ContiguousByteIterator = ByteIterator<It> && std::contiguous_iterator<It>;
        } // namespace detail

        template <typename T, detail::ContiguousByteIterator InputIt>
            requires std::is_trivially_copyable_v<T>
        InputIt read(InputIt first, InputIt last, T& ret, int byte_order = BIG_ENDIAN) {
            if (std::distance(first, last) >= (ptrdiff_t) sizeof(T)) {
                if (byte_order == BYTE_ORDER) {
                    memcpy(&ret, &*first, sizeof(T));
                } else {
                    reverse_memcpy(&ret, &*first, sizeof(T));
                }
                std::advance(first, sizeof(T));
            }
            return first;
        }

        template <typename T, detail::ContiguousByteIterator InputIt>
            requires std::is_trivially_copyable_v<T>
        bool try_read(InputIt& first, InputIt last, T& ret, int byte_order = BIG_ENDIAN) {
            InputIt old_first = first;
            first = read(first, last, ret, byte_order);
            return first != old_first;
        }

        template <typename T, detail::ByteOutputIterator OutputIt>
            requires std::is_trivially_copyable_v<T>
        OutputIt write(OutputIt ret, const T& value, int byte_order = BIG_ENDIAN) {
            auto bytes = (const char*) &value;
            for (size_t i = 0; i < sizeof(T); ++i) {
                if (byte_order == BYTE_ORDER) {
                    *ret++ = bytes[i];
                } else {
                    *ret++ = bytes[sizeof(T) - 1 - i];
                }
            }
            return ret;
        }
    } // namespace binary
} // namespace pw
