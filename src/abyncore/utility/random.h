#ifndef RANDOM_H
#define RANDOM_H

#include <vector>
#include <random>

#include "utility/typedefs.h"

namespace ABYN {

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline static T CeilDivide(T value, T divisor) {
    return value / divisor;
  }

  static inline std::vector<u8> RandomVector(size_t size_in_bytes) {
    std::vector<u8> buffer(size_in_bytes);
    std::random_device random_device; // use real randomness to create seeds
    for (auto i = 0u; i < buffer.size();) {
      try {
        if(i + sizeof(u32) < buffer.size()) {  //if can write a u32 to the buffer directly
          auto u32_ptr = reinterpret_cast<u32*>(buffer.data());
          u32_ptr[i / sizeof(u32)] = random_device();
        } else{                               //if we need less bytes than sizeof(u32)
          auto r = random_device();
          auto bytes_left = buffer.size() - i;
          assert(bytes_left < sizeof(u32));
          std::copy(&r, &r + bytes_left, buffer.data() + i);
        }
        i+= sizeof(u32);
      } catch (std::exception & e) {
        //could not get enough randomness from random device, try again
      }
    }
    return std::move(buffer);
  }
}

#endif //RANDOM_H
