#ifndef ABYN_CONSTANTS_H
#define ABYN_CONSTANTS_H

#include <string>
#include <limits>

#include "typedefs.h"

#define OMP_NESTED TRUE

namespace ABYN {

  const std::string_view FRAMEWORK_NAME{"ABYN"}; //just in case if we all of a sudden will decide to change the name

  const auto MAXIMUM_CONNECTION_TIMEOUT = 60; //seconds

  const auto MB = 1024 * 1024;

  //Don't compile unnecessary code if verbose debugging is not needed
  const bool VERBOSE_DEBUG = true;

  const size_t AES_KEY_SIZE = 16;

  const size_t AES_BLOCK_SIZE_ = 16;

  const size_t AES_IV_SIZE = AES_BLOCK_SIZE_ / 2;

  const float ABYN_VERSION = 1.0f;

  const size_t MESSAGE_SIZE_BYTELEN = sizeof(uint32_t);

  const u32 MAX_MESSAGE_SIZE = std::numeric_limits<u32>::max() - 1; // 2^32 - 2, approx. 4.3 GB

  const u32 TERMINATION_MESSAGE = std::numeric_limits<u32>::max(); // 2^32 - 1

  const u8 TERMINATION_MESSAGE_U8[4]{0xFF, 0xFF, 0xFF, 0xFF};

}
#endif //ABYN_CONSTANTS_H
