#ifndef POLYWEB_BINARY_HPP_
#define POLYWEB_BINARY_HPP_

#include "Polynet/polynet.hpp"
#include <algorithm>
#include <concepts>
#include <cstddef>
#include <iterator>
#include <memory>
#include <stddef.h>
#include <string.h>
#include <type_traits>

namespace pw {
    inline void reverse_memcpy(void* __restrict dest, const void* __restrict src, size_t size) {
        char* __restrict dest_bytes = (char*) dest;
        const char* __restrict src_bytes = (const char*) src;
        for (size_t i = 0; i < size; ++i) {
            dest_bytes[i] = src_bytes[size - 1 - i];
        }
    }

    inline void reverse_memmove(void* dest, const void* src, size_t size) {
        char* dest_bytes = (char*) dest;
        const char* src_bytes = (const char*) src;
        // Overlap in either direction defeats a reversing copy, which reads the
        // far end of the source only after the near end has been overwritten.
        // The straight copy is the one that survives overlap, so do that first
        // and reverse in place afterwards.
        if (dest_bytes < src_bytes + size && src_bytes < dest_bytes + size) {
            memmove(dest, src, size);
            std::reverse(dest_bytes, dest_bytes + size);
        } else {
            reverse_memcpy(dest, src, size);
        }
    }

    namespace binary {
        // A one-byte object whose representation is the wire byte. Not the
        // types that may be aliased through — that list leaves out signed char
        // — because nothing here punts a pointer at another type: reads go
        // through memcpy and writes go element by element.
        template <typename T>
        concept ByteType =
            std::same_as<std::remove_cv_t<T>, char> ||
            std::same_as<std::remove_cv_t<T>, signed char> ||
            std::same_as<std::remove_cv_t<T>, unsigned char> ||
            std::same_as<std::remove_cv_t<T>, char8_t> ||
            std::same_as<std::remove_cv_t<T>, std::byte>;

        template <typename It>
        concept ContiguousByteInputIterator =
            std::contiguous_iterator<It> && ByteType<std::iter_value_t<It>>;

        template <typename It>
        concept ByteOutputIterator =
            std::output_iterator<It, char> ||
            std::output_iterator<It, signed char> ||
            std::output_iterator<It, unsigned char> ||
            std::output_iterator<It, char8_t> ||
            std::output_iterator<It, std::byte>;

        // What may cross the wire as a single unit. Trivially copyable is too
        // weak a requirement: anything wider than a scalar has an internal
        // layout, and reversing the bytes of a struct transposes its members
        // rather than converting their byte order, silently. Aggregates have to
        // be sent field by field.
        template <typename T>
        concept Packable = std::integral<T> || std::floating_point<T> || std::is_enum_v<T>;

        // std::byte is the one byte type that takes no implicit conversion from
        // an integer, so it is the one that needs asking about. Public because
        // a protocol layering its own framing on top of write() needs to emit a
        // byte without deciding this again.
        template <ByteOutputIterator OutputIt>
        OutputIt write_byte(OutputIt ret, unsigned char byte) {
            if constexpr (requires(std::byte value) { *ret++ = value; }) {
                *ret++ = (std::byte) byte;
            } else {
                *ret++ = byte;
            }
            return ret;
        }

        // Returns the iterator past what was read, or `first` unchanged if the
        // range is too short — in which case `ret` is left alone. The return
        // value is the only report of that, hence the nodiscard; callers that
        // would rather branch on it want try_read.
        template <Packable T, ContiguousByteInputIterator InputIt>
        [[nodiscard]] InputIt read(InputIt first, InputIt last, T& ret, int byte_order = BIG_ENDIAN) {
            auto byte_count = (std::iter_difference_t<InputIt>) sizeof(T);
            if (std::distance(first, last) < byte_count) {
                return first;
            }

            if constexpr (std::same_as<T, bool>) {
                // A bool occupies a byte but only 0 and 1 are valid object
                // representations for one. The wire is attacker-controlled, so
                // copying 0x02 into a bool is reachable UB.
                unsigned char byte;
                memcpy(&byte, std::to_address(first), 1);
                ret = byte;
            } else if (byte_order == BYTE_ORDER) {
                memcpy(&ret, std::to_address(first), sizeof(T));
            } else {
                reverse_memcpy(&ret, std::to_address(first), sizeof(T));
            }

            std::advance(first, byte_count);
            return first;
        }

        template <Packable T, ContiguousByteInputIterator InputIt>
        [[nodiscard]] bool try_read(InputIt& first, InputIt last, T& ret, int byte_order = BIG_ENDIAN) {
            InputIt old_first = first;
            first = read(first, last, ret, byte_order);
            return first != old_first;
        }

        template <Packable T, ByteOutputIterator OutputIt>
        OutputIt write(OutputIt ret, T value, int byte_order = BIG_ENDIAN) {
            auto bytes = (const unsigned char*) &value;
            for (size_t i = 0; i < sizeof(T); ++i) {
                ret = write_byte(ret, byte_order == BYTE_ORDER ? bytes[i] : bytes[sizeof(T) - 1 - i]);
            }
            return ret;
        }

    } // namespace binary
} // namespace pw

#endif
