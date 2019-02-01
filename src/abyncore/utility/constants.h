#ifndef ABYN_CONSTANTS_H
#define ABYN_CONSTANTS_H

#include <string>

#define OMP_NESTED TRUE

namespace ABYN {

  const auto MAXIMUM_CONNECTION_TIMEOUT = 60;//seconds

  const std::string_view LOG_PATH("log_file");

  const auto MB = 1024 * 1024;

  //Don't compile unnecessary code if debugging is not needed
  const bool DEBUG = true;

  //Don't compile unnecessary code if verbose debugging is not needed
  const bool VERBOSE_DEBUG = true;

  const size_t AES_KEY_SIZE = 16;

  const size_t AES_BLOCK_SIZE_ = 16;

  const size_t AES_IV_SIZE = AES_BLOCK_SIZE_ / 2;

}
#endif //ABYN_CONSTANTS_H
