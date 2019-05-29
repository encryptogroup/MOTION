#pragma once

#include <iostream>
#include <limits>
#include <string>

#include "config.h"
#include "typedefs.h"

#define OMP_NESTED TRUE

namespace ABYN {

// just in case if we all of a sudden will decide to change the name
constexpr std::string_view FRAMEWORK_NAME{"ABYN"};

constexpr auto MB = 1024 * 1024;

constexpr bool ABYN_VERBOSE_DEBUG_WISH = true;

// Don't compile unnecessary code if verbose debugging is not needed
constexpr bool ABYN_VERBOSE_DEBUG = !ABYN_DEBUG ? false : ABYN_VERBOSE_DEBUG_WISH;

constexpr std::size_t AES_KEY_SIZE = 16;

constexpr std::size_t AES_BLOCK_SIZE_ = 16;

constexpr std::size_t AES_IV_SIZE = AES_BLOCK_SIZE_ / 2;

constexpr std::size_t MESSAGE_SIZE_BYTELEN = sizeof(std::uint32_t);

// 2^32 - 2, approx. 4.3 GB
constexpr std::uint32_t MAX_MESSAGE_SIZE = std::numeric_limits<std::uint32_t>::max() - 1;

constexpr std::uint32_t TERMINATION_MESSAGE =
    std::numeric_limits<std::uint32_t>::max();  // 2^32 - 1

constexpr std::uint8_t TERMINATION_MESSAGE_U8[4]{0xFF, 0xFF, 0xFF, 0xFF};

}  // namespace ABYN
