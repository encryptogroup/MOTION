#ifndef ABYN_CONSTANTS_H
#define ABYN_CONSTANTS_H

#include <iostream>
#include <limits>
#include <string>

#include "config.h"
#include "typedefs.h"

#define OMP_NESTED TRUE

namespace ABYN {

// just in case if we all of a sudden will decide to change the name
const std::string_view FRAMEWORK_NAME{"ABYN"};

const auto MB = 1024 * 1024;

const bool ABYN_VERBOSE_DEBUG_WISH = true;

// Don't compile unnecessary code if verbose debugging is not needed
const bool ABYN_VERBOSE_DEBUG = !ABYN_DEBUG ? false : ABYN_VERBOSE_DEBUG_WISH;

const std::size_t AES_KEY_SIZE = 16;

const std::size_t AES_BLOCK_SIZE_ = 16;

const std::size_t AES_IV_SIZE = AES_BLOCK_SIZE_ / 2;

const std::size_t MESSAGE_SIZE_BYTELEN = sizeof(u32);

// 2^32 - 2, approx. 4.3 GB
const u32 MAX_MESSAGE_SIZE = std::numeric_limits<u32>::max() - 1;

const u32 TERMINATION_MESSAGE = std::numeric_limits<u32>::max();  // 2^32 - 1

const u8 TERMINATION_MESSAGE_U8[4]{0xFF, 0xFF, 0xFF, 0xFF};

}  // namespace ABYN
#endif  // ABYN_CONSTANTS_H
