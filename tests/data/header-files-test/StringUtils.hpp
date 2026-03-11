// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 LLVM Project Contributors
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.

#ifndef LLVM_ADT_STRING_UTILS_HPP
#define LLVM_ADT_STRING_UTILS_HPP

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace llvm {

/// Splits a string by the given delimiter and returns a vector of substrings.
///
/// \param input The string to split.
/// \param delimiter The character to split on.
/// \return A vector of substrings.
inline std::vector<std::string> split(const std::string &input, char delimiter) {
    std::vector<std::string> tokens;
    std::istringstream stream(input);
    std::string token;

    while (std::getline(stream, token, delimiter)) {
        if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    return tokens;
}

/// Trims whitespace from the beginning and end of a string.
inline std::string trim(const std::string &str) {
    auto start = std::find_if_not(str.begin(), str.end(), ::isspace);
    auto end = std::find_if_not(str.rbegin(), str.rend(), ::isspace).base();

    if (start >= end) {
        return "";
    }
    return std::string(start, end);
}

/// Converts a string to lowercase.
inline std::string toLower(const std::string &str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

/// Converts a string to uppercase.
inline std::string toUpper(const std::string &str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::toupper);
    return result;
}

/// Checks if a string starts with the given prefix.
inline bool startsWith(const std::string &str, const std::string &prefix) {
    return str.size() >= prefix.size() &&
           str.compare(0, prefix.size(), prefix) == 0;
}

/// Checks if a string ends with the given suffix.
inline bool endsWith(const std::string &str, const std::string &suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

/// Replaces all occurrences of a substring with another substring.
inline std::string replaceAll(const std::string &str,
                               const std::string &from,
                               const std::string &to) {
    std::string result = str;
    size_t pos = 0;
    while ((pos = result.find(from, pos)) != std::string::npos) {
        result.replace(pos, from.length(), to);
        pos += to.length();
    }
    return result;
}

} // namespace llvm

#endif // LLVM_ADT_STRING_UTILS_HPP