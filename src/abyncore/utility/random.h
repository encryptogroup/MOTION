#pragma once

#include <random>
#include <vector>

#include "utility/typedefs.h"

namespace ABYN {

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
inline static T CeilDivide(T value, T divisor) {
  return value / divisor;
}

static inline std::vector<std::uint8_t> RandomVector(std::size_t size_in_bytes) {
  std::vector<std::uint8_t> buffer(size_in_bytes);
  std::random_device random_device;  // use real randomness to create seeds
  for (auto i = 0u; i < buffer.size();) {
    try {
      if (i + sizeof(std::uint32_t) <=
          buffer.size()) {  // if can write a std::uint32_t to the buffer directly
        auto u32_ptr = reinterpret_cast<std::uint32_t*>(buffer.data());
        u32_ptr[i / sizeof(std::uint32_t)] = random_device();
      } else {  // if we need less bytes than sizeof(std::uint32_t)
        auto r = random_device();
        auto bytes_left = buffer.size() - i;
        assert(bytes_left < sizeof(std::uint32_t));
        std::copy(&r, &r + bytes_left, buffer.data() + i);
      }
      i += sizeof(std::uint32_t);
    } catch (std::exception& e) {
      // could not get enough randomness from random device, try again
    }
  }
  return std::move(buffer);
}
}  // namespace ABYN
