#ifndef HELPERS_H
#define HELPERS_H

namespace ABYN::Helpers {

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline auto ToByteVector(const std::vector<T> &values) {
    std::vector<u8> result(sizeof(T) * values.size());
    std::copy(values.data(), values.data() + values.size(), result.data());
    return std::move(result);
  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline auto FromByteVector(const std::vector<u8> &buffer) {
    assert(buffer.size() % sizeof(T) == 0); // buffer length is multiple of the element size
    std::vector<T> result(sizeof(T) * buffer.size());
    std::copy(buffer.data(), buffer.data() + buffer.size(), result.data());
    return std::move(result);
  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  inline auto FromByteVector(const flatbuffers::Vector<unsigned char> &buffer) {
    assert(buffer.size() % sizeof(T) == 0); // buffer length is multiple of the element size
    std::vector<T> result(sizeof(T) * buffer.size());
    std::copy(buffer.data(), buffer.data() + buffer.size(), result.data());
    return std::move(result);
  };

  inline void WaitFor(const bool &condition) {
    while (!condition) {
      std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
  }

  template<typename T>
  inline std::vector<T> AddShares(std::vector<std::vector<T>> vectors) {
    if (vectors.size() == 0) { return {}; } //if empty input vector

    std::vector<T> result = vectors.at(0);

    for (auto i = 1u; i < vectors.size(); ++i) {
      auto &v = vectors.at(i);
      assert(v.size() == result.size()); //expect the vectors to be of the same size
      for (auto j = 0u; j < result.size(); ++j) {
        result.at(j) += v.at(j); //TODO: implement using AVX2 and AVX512
      }
    }

    return result;
  }

  namespace Print {
    inline std::string Hex(const std::vector<u8> &v) {
      std::string buffer("");
      for (auto i = 0u; i < v.size(); ++i) {
        buffer.append(fmt::format("{0:#x} ", v.at(i)));
      }
      buffer.erase(buffer.end() - 1); //remove the last whitespace
      return std::move(buffer);
    }

    inline std::string Hex(const std::vector<u8> &&v) { return std::move(Hex(v)); }
  }
}

#endif //HELPERS_H
